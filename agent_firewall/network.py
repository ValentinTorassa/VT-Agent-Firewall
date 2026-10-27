"""Network allowlist: which URLs a `net.request` may reach.

Network is deny-all by default. A policy that sets

    "network": {"mode": "allowlist", "allow": ["https://docs.python.org"]}

lets GET and HEAD requests without a body reach the listed origins; everything
else stays denied (`net-allowlist`). An entry is `scheme://host[:port][/path]`:

- the scheme is http, https, ws or wss, and must match exactly (an https entry
  does not allow http);
- the host is a DNS name, `*.` plus a DNS name (any name below it, never the
  name itself), or an IP address; a port that is not the scheme's default must
  be written, and must match;
- a path, when given, is a prefix that ends at a segment boundary (`/3` covers
  `/3` and `/3/...`, not `/30`).

The firewall checks the URL, and the agent host or the executor fetches it, so
two URL parsers read the same string. Anything they could read differently is
refused instead of guessed, in entries and in requests alike:

- user info (`https://allowed.example@evil.example`), a backslash
  (`https://evil.example\\@allowed.example` is evil.example to a browser and
  allowed.example to urllib), `%` in the host, whitespace, control and
  non-ASCII characters (IDN hosts are written in punycode);
- a host that is neither a canonical IP address nor a DNS name whose last label
  starts with a letter, so `127.1`, `2130706433` and `0x7f.0.0.1`, which a
  browser reads as 127.0.0.1, match nothing;
- a port spelled in a way that does not round-trip (`:0443`, an empty `:`);
- for a path-prefix entry, a request path with a `.` or `..` segment, plain or
  percent-encoded, or an encoded slash inside a segment.

What an allowed origin does with the request is outside the firewall: data can
leave in the URL itself, the firewall does not resolve DNS, and a redirect is
the host's or the executor's business (the gateway's executor never follows
one; Claude Code's WebFetch does not follow a redirect to another host).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

MODES = ("deny_all", "allowlist")
DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
METHODS = frozenset({"GET", "HEAD"})
MAX_URL_CHARS = 8192

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class URLRefused(ValueError):
    """A URL the allowlist will not interpret."""


@dataclass(frozen=True)
class Target:
    """A URL in the strict form both parsers agree on."""
    scheme: str
    host: str                     # lowercase DNS name, or the IP's compressed form
    ip: object | None             # ipaddress.IPv4Address / IPv6Address
    port: int                     # explicit or the scheme's default
    path: str

    def origin(self) -> str:
        host = f"[{self.host}]" if self.ip is not None and self.ip.version == 6 \
            else self.host
        port = "" if self.port == DEFAULT_PORTS[self.scheme] else f":{self.port}"
        return f"{self.scheme}://{host}{port}"


@dataclass(frozen=True)
class AllowEntry:
    text: str                     # as written in the policy
    scheme: str
    host: str                     # for a wildcard, the suffix without "*."
    wildcard: bool
    ip: object | None
    port: int
    path: str                     # "" covers every path

    def covers(self, target: Target) -> bool:
        if target.scheme != self.scheme or target.port != self.port:
            return False
        if self.ip is not None or target.ip is not None:
            if self.ip is None or target.ip is None or self.ip != target.ip:
                return False
        elif self.wildcard:
            if not target.host.endswith("." + self.host):
                return False
        elif target.host != self.host:
            return False
        if not self.path:
            return True
        if _dot_segments(target.path):
            return False
        if target.path == self.path:
            return True
        base = self.path if self.path.endswith("/") else self.path + "/"
        return target.path.startswith(base)


def parse_target(url) -> Target:
    """The request URL in strict form, or URLRefused saying why not."""
    parts, host = _split(url)
    if host.startswith("*."):
        raise URLRefused("a wildcard is not a host")
    ip = _ip(host)
    if ip is None and not _dns_name(host):
        raise URLRefused(f"host {host!r} is neither a DNS name nor a canonical IP "
                         f"address")
    if parts.port == 0:
        raise URLRefused("port 0")
    port = DEFAULT_PORTS[parts.scheme] if parts.port is None else parts.port
    return Target(parts.scheme, str(ip) if ip is not None else host, ip, port,
                  parts.path)


def parse_entry(text) -> AllowEntry:
    """A `network.allow` entry; ValueError when it is not one."""
    try:
        parts, host = _split(text)
    except URLRefused as e:
        raise ValueError(f"network.allow entry {text!r}: {e}") from None
    problem = None
    if parts.query or parts.fragment or "?" in text or "#" in text:
        problem = "no query or fragment: an entry names an origin and a path prefix"
    elif parts.path not in ("", "/") and ("%" in parts.path
                                          or _dot_segments(parts.path)
                                          or "//" in parts.path):
        problem = "the path prefix must be plain: no %, no . or .. segments, no //"
    wildcard = host.startswith("*.")
    if wildcard:
        host = host[2:]
        if not _dns_name(host) or "." not in host:
            problem = "a wildcard covers the names below a DNS name of two labels or more"
        ip = None
    else:
        ip = _ip(host)
        if ip is None and not _dns_name(host):
            problem = ("the host must be a DNS name whose last label starts with a "
                       "letter, or a canonical IP address")
    if parts.port == 0:
        problem = "port 0"
    if problem:
        raise ValueError(f"network.allow entry {text!r}: {problem}")
    path = "" if parts.path in ("", "/") else parts.path
    return AllowEntry(text=text, scheme=parts.scheme,
                      host=str(ip) if ip is not None else host, wildcard=wildcard,
                      ip=ip, path=path,
                      port=DEFAULT_PORTS[parts.scheme] if parts.port is None
                      else parts.port)


def match(entries, url, method, body) -> tuple[AllowEntry | None, str]:
    """The entry that allows this request, or None and why nothing does."""
    if not isinstance(method, str) or method not in METHODS:
        return None, (f"method {method!r}: network.allow covers GET and HEAD only "
                      f"(an API call goes through api.call)")
    if body is not None:
        return None, "a request body: network.allow covers GET and HEAD without one"
    try:
        target = parse_target(url)
    except URLRefused as e:
        return None, f"URL refused ({e})"
    for entry in entries:
        if entry.covers(target):
            return entry, ""
    return None, f"{target.origin()} is not on network.allow"


def origin_of(url) -> Target | None:
    """The strict form of `url`, or None when the allowlist could never match it."""
    try:
        return parse_target(url)
    except URLRefused:
        return None


def is_local(target: Target) -> bool:
    """An IP address, localhost or a single-label name: the machine itself or
    the networks it sits on, not a public host."""
    return target.ip is not None or "." not in target.host \
        or target.host.endswith(".localhost")


# -- strict parsing -------------------------------------------------------------------

def _split(url):
    if not isinstance(url, str):
        raise URLRefused("not a string")
    if not url or len(url) > MAX_URL_CHARS:
        raise URLRefused(f"empty or longer than {MAX_URL_CHARS} characters")
    for c in url:
        if not "\x21" <= c <= "\x7e":
            raise URLRefused(f"contains {c!r} (whitespace, a control or a non-ASCII "
                             f"character)")
    if "\\" in url:
        raise URLRefused("contains a backslash, which parsers read differently")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as e:
        raise URLRefused(str(e)) from None
    if parts.scheme not in DEFAULT_PORTS:
        raise URLRefused(f"scheme {parts.scheme!r} (http, https, ws or wss only)")
    netloc = parts.netloc
    if not netloc:
        raise URLRefused("no host")
    if "@" in netloc:
        raise URLRefused("user info in the URL")
    if "%" in netloc:
        raise URLRefused("percent-encoding in the host")
    host = parts.hostname or ""
    spelled = f"[{host}]" if ":" in host else host
    if port is not None:
        spelled += f":{port}"
    if netloc.lower() != spelled:
        raise URLRefused(f"authority {netloc!r} is not in canonical form")
    return parts, host


def _ip(host: str):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    # IPv4 must already be canonical (Python refuses short and octal forms);
    # IPv6 compares as an address, which both parsers agree on.
    if ip.version == 4 and str(ip) != host:
        return None
    return ip


def _dns_name(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    labels = host.split(".")
    # The last label starts with a letter, so no parser reads the name as an
    # IPv4 number (`127.1`, `0x7f.1`, `2130706433`).
    return all(_LABEL.match(label) for label in labels) and labels[-1][0].isalpha()


def _dot_segments(path: str) -> bool:
    """A `.` or `..` segment, plain or percent-encoded, a `;` parameter on one
    (`..;`), or a slash hidden in a segment: what a server may normalize out
    of a path prefix."""
    for segment in path.split("/"):
        decoded = unquote(segment)
        if "/" in decoded or "\\" in decoded:
            return True
        if decoded.split(";", 1)[0] in (".", ".."):
            return True
    return False
