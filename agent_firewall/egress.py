"""Secret egress: the values in the policy's `secret_files` never leave in a request.

Path rules stop the agent from reading a secret file. They cannot stop a value
that reached the agent some other way (a program the firewall cannot bound, a
host tool the hook does not see, an MCP result, a copy nobody listed) from
leaving through a channel the policy allows: a URL on `network.allow`, an
argument to an allowlisted binary, a file the agent may write, an MCP or API
argument. The firewall can read the secret files itself, so it knows the
values, and refuses any request that carries one (`secret-egress`).

What counts as a value, line by line (dotenv, ini, YAML, netrc, PEM, token files):

- `KEY=VALUE`, `export KEY=VALUE`, `KEY = VALUE` and `KEY: VALUE` give VALUE
  (quotes and an unquoted trailing ` # comment` removed, and each of its
  words) when KEY names a credential: one of its words, split on `_`, `-`,
  `.` and camelCase, is in CREDENTIAL_WORDS (`API_KEY`, `AWS_SECRET_ACCESS_KEY`,
  `_authToken`, `DB_PASSWORD`). Other keys (`NODE_ENV`, `API_URL`, `PORT`)
  are configuration: as secrets they would refuse every request that mentions
  `development` or `http://localhost:3000`.
- The password of a URL value, under any key (`DATABASE_URL=postgres://u:p@h/db`).
- A line that is not an assignment, whole (a token file, the body of a PEM
  key), and the word after a credential word in it (netrc's `password X`).

Comments (`#`, `;`), `[section]` headers, PEM armor lines and values shorter
than MIN_LENGTH characters are skipped.

Every string in the request is checked (dict keys and numbers included) as
written and percent-decoded once and twice (`+` as a space), for the value
itself and for its base64 (standard and URL-safe, at any offset inside a
longer encoded string) and hex spellings. Any other transformation (split,
reversed, compressed, encrypted, another encoding) is not detected: this is a
tripwire for the value itself, not containment. Values live in memory only;
the audit log and the learning trace keep which file and key matched, never
the value.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit

MIN_LENGTH = 8
MAX_FILE_BYTES = 1024 * 1024
MAX_SCAN_CHARS = 16 * 1024 * 1024

CREDENTIAL_WORDS = frozenset({
    "KEY", "KEYS", "APIKEY", "ACCESSKEY", "SECRETKEY", "PRIVATEKEY", "TOKEN", "TOKENS",
    "AUTHTOKEN", "ACCESSTOKEN", "REFRESHTOKEN", "SECRET", "SECRETS", "PASSWORD",
    "PASSWORDS", "PASSWD", "PASS", "PWD", "PASSPHRASE", "CREDENTIAL", "CREDENTIALS",
    "AUTHORIZATION", "SALT", "SIGNATURE", "DSN", "WEBHOOK", "BEARER", "PAT", "MNEMONIC",
})

_PEM_ARMOR = re.compile(r"^-----(BEGIN|END) [A-Z0-9 ]+-----$")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
_YAML_PAIR = re.compile(r"""^([^\s:'"]+|'[^']*'|"[^"]*"):\s+(.*)$""")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@dataclass(frozen=True)
class Secret:
    source: Path               # the secret file
    name: str                  # the key, or "line N"
    forms: tuple[str, ...]     # the value and its base64 and hex spellings


def load(paths) -> list[Secret]:
    """The secrets in every file of `paths`. A missing file has none; a
    directory, a file over MAX_FILE_BYTES or an unreadable one is a policy
    that cannot load (ValueError): its values could not be checked."""
    secrets: list[Secret] = []
    seen: set[str] = set()
    for path in paths:
        path = Path(path)
        if not path.exists():
            continue
        if not path.is_file():
            raise ValueError(f"secret_files: {path} is not a file (list each file)")
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError(f"secret_files: {path} is larger than "
                                 f"{MAX_FILE_BYTES} bytes and cannot be checked")
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError as e:
            raise ValueError(f"secret_files: cannot read {path}: {e}") from e
        for name, value in values(text):
            if value not in seen:
                seen.add(value)
                secrets.append(Secret(path, name, spellings(value)))
    return secrets


def values(text: str):
    """(name, value) for every secret value in a secret file's text."""
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if (not line or line.startswith(("#", ";")) or _PEM_ARMOR.match(line)
                or (line.startswith("[") and line.endswith("]"))):
            continue
        key, value = _assignment(line)
        found: list[tuple[str, str]] = []
        if key is None:
            found.append((f"line {number}", line))
            words = line.split()
            found += [(f"line {number}", after)
                      for word, after in zip(words, words[1:], strict=False)
                      if names_credential(word)]
        else:
            if names_credential(key):
                found.append((key, value))
                words = value.split()
                if len(words) > 1:           # `Bearer TOKEN`: the token alone too
                    found += [(key, word) for word in words]
            password = _url_password(value)
            if password:
                found.append((f"{key} (URL password)", password))
        for name, secret in found:
            if len(secret) >= MIN_LENGTH:
                yield name[:64], secret


def _assignment(line: str) -> tuple[str | None, str]:
    """(KEY, VALUE) when the line assigns a value, else (None, line). A line
    that only looks like `KEY=` because it ends in base64 padding is not one."""
    key, eq, value = line.partition("=")
    key = key.strip()
    if key.startswith("export "):
        key = key[len("export "):].strip()
    if eq and key and value.strip("= \t") and (
            _IDENTIFIER.match(key) or (" " not in key and names_credential(key))):
        return key, _unquote(value.strip())
    m = _YAML_PAIR.match(line)
    if m:
        return m.group(1).strip("'\""), _unquote(m.group(2).strip().rstrip(","))
    return None, line


def _unquote(value: str) -> str:
    for quote in ('"', "'"):
        if value.startswith(quote):
            end = value.find(quote, 1)
            return value[1:end] if end > 0 else value[1:]
    return value.split(" #", 1)[0].strip()


def names_credential(key: str) -> bool:
    words = re.split(r"[^A-Za-z0-9]+", _CAMEL.sub("_", key))
    return any(word.upper() in CREDENTIAL_WORDS for word in words)


def _url_password(value: str) -> str | None:
    if "://" not in value or "@" not in value:
        return None
    try:
        return urlsplit(value).password
    except ValueError:
        return None


def spellings(value: str) -> tuple[str, ...]:
    """The value, its hex, and the part of its base64 that does not depend on
    what surrounds it in a longer encoded string (one per offset mod 3)."""
    data = value.encode("utf-8")
    forms = {value, data.hex(), data.hex().upper()}
    for offset in range(3):
        encoded = base64.b64encode(bytes(offset) + data).decode("ascii")
        start = (8 * offset + 5) // 6          # first character from the value alone
        end = (8 * (offset + len(data))) // 6  # past the last one it does not share
        core = encoded[start:end]
        if len(core) >= MIN_LENGTH:
            forms.add(core)
            forms.add(core.replace("+", "-").replace("/", "_"))
    return tuple(sorted(forms, key=len, reverse=True))


def strings(value, limit: int | None = None):
    """Every string in a request's params: values, dict keys, numbers as
    written. Iterative, and a container seen twice is walked once. More than
    `limit` (MAX_SCAN_CHARS) characters in all is a ValueError: a request too
    large to check."""
    limit = MAX_SCAN_CHARS if limit is None else limit
    stack, seen, total = [value], set(), 0
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            total += len(item)
            if total > limit:
                raise ValueError(f"request too large to check for secret values "
                                 f"(over {limit} characters)")
            yield item
        elif isinstance(item, bool) or item is None:
            continue
        elif isinstance(item, (int, float)):
            yield str(item)
        elif isinstance(item, (dict, list, tuple)):
            if id(item) in seen:
                continue
            seen.add(id(item))
            if isinstance(item, dict):
                stack.extend(item.keys())
                stack.extend(item.values())
            else:
                stack.extend(item)


def find(secrets: list[Secret], params) -> Secret | None:
    """The first secret any string in `params` carries, in any spelling."""
    if not secrets:
        return None
    for text in strings(params):
        candidates = [text]
        for _ in range(2):
            decoded = unquote_plus(candidates[-1])
            if decoded != candidates[-1]:
                candidates.append(decoded)
        for secret in secrets:
            if any(form in candidate for candidate in candidates
                   for form in secret.forms):
                return secret
    return None
