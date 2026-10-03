"""Policy engine: normalize the ActionRequest, then evaluate rules.

Normalization happens BEFORE evaluation and the executor only receives
normalized params:
- every fs path is canonicalized with realpath (resolves `..` and symlinks)
- shell requests are tokenized to argv (shlex), parsed with the binary's own
  grammar (argv.py) and never reach a shell; a request marked `via_shell`
  (an agent host's Bash tool, which does use a shell) must first be one
  simple command with nothing for the shell to expand (shell_syntax.py)
- URLs are parsed into scheme/host/port

A protected path covers everything below it. Any request that names or
reaches one, blocked or not, taints the session.

Rule precedence (per tool, most specific first):
  fs-protected > fs-sandbox > tool-specific checks > allow/default-deny
Shell order: sh-syntax (via_shell only) > sh-allowlist > sh-paths > sh-args >
sh-recursive.
Fail-closed: malformed params, unknown tools, options outside a grammar, or
no matching allow rule all produce BLOCK.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from urllib.parse import urlparse

from . import argv as argv_grammar
from . import shell_syntax
from .config import Config
from .models import ActionRequest, Decision, PolicyDecision
from .session import SessionState


class PolicyEngine:
    def __init__(self, config: Config):
        self.cfg = config

    def evaluate(self, req: ActionRequest, session: SessionState) -> PolicyDecision:
        handler = {
            "fs.read": self._fs_read,
            "fs.write": self._fs_write,
            "shell.run": self._shell_run,
            "net.request": self._net_request,
            "mcp.call": self._mcp_call,
            "mcp.resource": self._mcp_resource,
            "api.call": self._api_call,
        }.get(req.tool)
        if handler is None:
            return self._decide(req, Decision.BLOCK, "unknown-tool",
                                f"no policy for tool '{req.tool}' (default-deny)",
                                "medium", {})
        try:
            return handler(req, session)
        except (KeyError, TypeError, ValueError) as e:
            # Parser/normalizer failure: fail closed.
            return self._decide(req, Decision.BLOCK, "parse-error",
                                f"malformed request: {e}", "medium", {})

    # -- helpers ----------------------------------------------------------

    def _decide(self, req, decision, rule_id, reason, risk, normalized,
                matched=None) -> PolicyDecision:
        return PolicyDecision(
            request=req, decision=decision, rule_id=rule_id, reason=reason,
            risk=risk, rules_matched=matched or [rule_id], normalized=normalized,
        )

    def _resolve_cwd(self, params: dict) -> Path:
        cwd = params.get("cwd")
        if not cwd:
            return self.cfg.sandbox_root
        p = Path(cwd)
        if not p.is_absolute():
            p = self.cfg.sandbox_root / p
        return Path(os.path.realpath(p))

    def _resolve_path(self, spelled: str, cwd: Path) -> Path:
        p = Path(spelled)
        if not p.is_absolute():
            p = cwd / p
        return Path(os.path.realpath(p))

    def _check_read_path(self, req, session, resolved, spelled, cwd, rule_prefix):
        """Shared read-side checks. Returns a BLOCK decision or None."""
        normalized = {"path": str(resolved), "spelled": spelled, "cwd": str(cwd)}
        if not self.cfg.in_sandbox(cwd):
            return self._decide(req, Decision.BLOCK, "fs-sandbox",
                                f"cwd escapes sandbox: {cwd}", "high", normalized)
        if self.cfg.is_protected(resolved):
            session.tainted = True
            return self._decide(req, Decision.BLOCK, "fs-protected",
                                f"protected path: {resolved}", "high", normalized,
                                matched=[f"{rule_prefix}", "fs-protected"]
                                if rule_prefix != "fs-protected" else None)
        if not self.cfg.in_sandbox(resolved):
            return self._decide(req, Decision.BLOCK, "fs-sandbox",
                                f"path escapes sandbox: {resolved}", "high", normalized)
        return None

    # -- fs.read / fs.write -------------------------------------------------

    def _fs_read(self, req, session) -> PolicyDecision:
        spelled = req.params["path"]
        cwd = self._resolve_cwd(req.params)
        resolved = self._resolve_path(spelled, cwd)
        blocked = self._check_read_path(req, session, resolved, spelled, cwd,
                                        "fs-protected")
        if blocked:
            return blocked
        return self._decide(req, Decision.ALLOW, "fs-read-ok",
                            f"read inside sandbox: {resolved}", "low",
                            {"path": str(resolved), "spelled": spelled,
                             "cwd": str(cwd)})

    def _fs_write(self, req, session) -> PolicyDecision:
        spelled = req.params["path"]
        content = req.params.get("content", "")
        cwd = self._resolve_cwd(req.params)
        resolved = self._resolve_path(spelled, cwd)
        normalized = {"path": str(resolved), "spelled": spelled,
                      "cwd": str(cwd), "content": content}
        blocked = self._check_read_path(req, session, resolved, spelled, cwd,
                                        "fs-protected")
        if blocked:
            return blocked
        if self.cfg.in_writable(resolved):
            return self._decide(req, Decision.ALLOW, "fs-write-ok",
                                f"write inside writable dir: {resolved}", "low",
                                normalized)
        return self._decide(req, Decision.REQUIRE_APPROVAL, "fs-write-scope",
                            f"write outside writable set: {resolved}", "medium",
                            normalized)

    # -- shell.run ------------------------------------------------------------

    def _shell_run(self, req, session) -> PolicyDecision:
        # Accept either command+args or a command_line string. The string is
        # tokenized with shlex and NEVER passed to a shell: metacharacters
        # become literal argv tokens, so pipes/redirection/subshells are inert.
        # That only holds when the gateway executes. With `via_shell` the host
        # hands the line to bash or zsh, so it must be one simple command whose
        # shlex argv is exactly what the shell will run.
        if req.params.get("via_shell"):
            blocked = self._shell_syntax(req, session)
            if blocked:
                return blocked
        if "command_line" in req.params:
            argv = shlex.split(req.params["command_line"])
        else:
            argv = [req.params["command"], *map(str, req.params.get("args", []))]
        if not argv:
            raise ValueError("empty argv")
        binary, args = argv[0], argv[1:]
        cwd = self._resolve_cwd(req.params)
        normalized = {"binary": binary, "args": args, "cwd": str(cwd)}

        if not self.cfg.in_sandbox(cwd):
            return self._decide(req, Decision.BLOCK, "fs-sandbox",
                                f"cwd escapes sandbox: {cwd}", "high", normalized)
        # Taint on potential access: any token (or --opt=value) that names a
        # protected path taints the session, whatever the decision below.
        self._taint_if_named(args, cwd, session)
        if binary not in self.cfg.shell_allowlist:
            return self._decide(req, Decision.BLOCK, "sh-allowlist",
                                f"binary not allowlisted: {binary}", "high",
                                normalized)
        parsed = argv_grammar.parse(binary, args)
        # Every file the grammar says the command may open is checked against
        # the canonical filesystem view, option values included (--file=.env).
        for spelled in parsed.paths:
            resolved = self._resolve_path(spelled, cwd)
            if self.cfg.is_protected(resolved):
                session.tainted = True
                return self._decide(req, Decision.BLOCK, "sh-paths",
                                    f"argv touches protected path: {resolved}",
                                    "high", normalized,
                                    matched=["sh-paths", "fs-protected"])
            if not self.cfg.in_sandbox(resolved):
                return self._decide(req, Decision.BLOCK, "sh-paths",
                                    f"argv escapes sandbox: {resolved}", "high",
                                    normalized)
        forbidden = sorted(self.cfg.shell_forbidden_args.get(binary, set())
                           .intersection(args))
        if parsed.errors or forbidden:
            bad = forbidden + [e for e in parsed.errors if e not in forbidden]
            return self._decide(req, Decision.BLOCK, "sh-args",
                                f"arguments outside the {binary} grammar or "
                                f"forbidden: {bad}", "high", normalized)
        # A recursive read names no protected file; it reaches one. Walk the
        # trees it would descend, symlinks followed, before letting it run.
        for spelled in parsed.walk_roots:
            root = self._resolve_path(spelled, cwd)
            hit = self._tree_hit(root, parsed.max_depth)
            if hit is None:
                continue
            kind, where = hit
            if kind == "protected":
                session.tainted = True
                return self._decide(req, Decision.BLOCK, "sh-recursive",
                                    f"{binary} would walk into protected path "
                                    f"{where} from {root}", "high", normalized,
                                    matched=["sh-recursive", "fs-protected"])
            reason = (f"{binary} would leave the sandbox through {where}"
                      if kind == "escape" else
                      f"tree under {root} is too large to verify")
            return self._decide(req, Decision.BLOCK, "sh-recursive", reason,
                                "high", normalized)
        return self._decide(req, Decision.ALLOW, "sh-ok",
                            f"allowlisted binary, paths in sandbox: {binary}",
                            "low", normalized)

    def _shell_syntax(self, req, session) -> PolicyDecision | None:
        line = req.params["command_line"]
        found = shell_syntax.problem(line)
        if found is None:
            return None
        cwd = self._resolve_cwd(req.params)
        try:
            # Best effort: a refused line that names a protected path still
            # taints the session.
            self._taint_if_named(shlex.split(line), cwd, session)
        except ValueError:
            pass
        return self._decide(req, Decision.BLOCK, "sh-syntax",
                            f"the host runs this line through a shell and it "
                            f"contains {found}; only one simple command with "
                            f"literal arguments can be checked (no pipes, "
                            f"redirects, chaining, substitution, variables, "
                            f"globs or ~): split it into separate calls",
                            "high", {"command_line": line, "cwd": str(cwd)})

    TREE_WALK_LIMIT = 20_000

    def _tree_hit(self, root: Path, max_depth: int | None):
        """First protected path or sandbox escape reachable from `root`,
        following symlinks, within `max_depth`. Fail-closed on huge trees."""
        found = self.cfg.protected_under(root, max_depth)
        if found is not None:
            return "protected", found
        seen = {root}
        stack = [(root, 0)]
        visited = 0
        while stack:
            directory, depth = stack.pop()
            if max_depth is not None and depth >= max_depth:
                continue
            try:
                entries = list(os.scandir(directory))
            except OSError:
                continue
            for entry in entries:
                visited += 1
                if visited > self.TREE_WALK_LIMIT:
                    return "limit", directory
                real = Path(os.path.realpath(entry.path))
                if self.cfg.is_protected(real):
                    return "protected", real
                if not self.cfg.in_sandbox(real):
                    return "escape", real
                try:
                    is_dir = entry.is_dir(follow_symlinks=True)
                except OSError:
                    is_dir = False
                if is_dir and real not in seen:
                    seen.add(real)
                    remaining = None if max_depth is None else max_depth - depth - 1
                    found = self.cfg.protected_under(real, remaining)
                    if found is not None:
                        return "protected", found
                    stack.append((real, depth + 1))
        return None

    def _taint_if_named(self, tokens: list[str], cwd: Path, session) -> None:
        for token in tokens:
            for spelled in (token, token.partition("=")[2]):
                if not spelled or "\0" in spelled:
                    continue
                try:
                    if self.cfg.is_protected(self._resolve_path(spelled, cwd)):
                        session.tainted = True
                        return
                except (OSError, ValueError):
                    continue

    # -- net.request ----------------------------------------------------------

    def _net_request(self, req, session) -> PolicyDecision:
        url = req.params["url"]
        parsed = urlparse(url)
        normalized = {"url": url, "scheme": parsed.scheme,
                      "host": parsed.hostname, "port": parsed.port,
                      "method": req.params.get("method", "GET")}
        matched = ["net-deny-all"]
        reason = "network is deny-total by policy"
        if session.tainted:
            matched.append("taint-session")
            reason += "; session tainted by protected-path access"
        return self._decide(req, Decision.BLOCK, "net-deny-all", reason, "high",
                            normalized, matched=matched)

    # -- mcp.call ---------------------------------------------------------------

    def _mcp_call(self, req, session) -> PolicyDecision:
        server = req.params["server"]
        tool = req.params["tool"]
        arguments = req.params.get("arguments", {})
        if not isinstance(arguments, dict):
            raise TypeError("MCP arguments must be an object")
        normalized = {"server": server, "tool": tool, "arguments": arguments}
        if tool not in self.cfg.mcp_registry.get(server, set()):
            return self._decide(req, Decision.BLOCK, "mcp-unknown-tool",
                                f"unregistered MCP tool: {server}/{tool}", "high",
                                normalized)
        # A registered tool is still not a free pass. Every string argument
        # that is a known path name, or looks like a path, or exists under the
        # server's root is canonicalized and checked like fs.read, so
        # `read_file ../.env` through an MCP filesystem server hits the same wall.
        base = self.cfg.mcp_roots.get(server, self.cfg.sandbox_root)
        for key, spelled in self._mcp_strings(arguments):
            if not (key in self.cfg.mcp_path_arguments
                    or self._looks_like_path(spelled, base)):
                continue
            blocked = self._mcp_check_path(req, session, normalized, server,
                                           f"{tool} argument {key!r}", spelled, base)
            if blocked:
                return blocked
        return self._decide(req, Decision.ALLOW, "mcp-ok",
                            f"registered MCP tool: {server}/{tool}", "low",
                            normalized)

    def _mcp_resource(self, req, session) -> PolicyDecision:
        server = req.params["server"]
        uri = req.params["uri"]
        if not isinstance(uri, str):
            raise TypeError("resource uri must be a string")
        normalized = {"server": server, "uri": uri}
        if server not in self.cfg.mcp_resources:
            return self._decide(req, Decision.BLOCK, "mcp-resources-denied",
                                f"resources are not enabled for {server} "
                                f"(default-deny)", "high", normalized)
        if uri.startswith("file:"):
            base = self.cfg.mcp_roots.get(server, self.cfg.sandbox_root)
            blocked = self._mcp_check_path(req, session, normalized, server,
                                           "resource", uri, base)
            if blocked:
                return blocked
        return self._decide(req, Decision.ALLOW, "mcp-resource-ok",
                            f"resource read enabled for {server}", "low", normalized)

    def _mcp_check_path(self, req, session, normalized, server, what, spelled, base):
        if not isinstance(spelled, str):
            raise TypeError(f"MCP path argument {what} must be a string")
        resolved = self._resolve_path(self._strip_file_uri(spelled), base)
        if self.cfg.is_protected(resolved):
            session.tainted = True
            return self._decide(req, Decision.BLOCK, "mcp-protected-path",
                                f"{server}/{what} is a protected path: {resolved}",
                                "high", normalized,
                                matched=["mcp-protected-path", "fs-protected"])
        if not self.cfg.in_sandbox(resolved):
            return self._decide(req, Decision.BLOCK, "mcp-sandbox",
                                f"{server}/{what} escapes the sandbox: {resolved}",
                                "high", normalized)
        return None

    def _mcp_strings(self, value, key: str = ""):
        """(key, string) for every string in nested arguments. Values under a
        known path key must be strings (or lists of them): anything else is a
        malformed request."""
        if isinstance(value, dict):
            for k, v in value.items():
                if k in self.cfg.mcp_path_arguments and not isinstance(v, (str, list)):
                    raise TypeError(f"MCP path argument {k!r} must be a string")
                yield from self._mcp_strings(v, k)
        elif isinstance(value, list):
            for v in value:
                if key in self.cfg.mcp_path_arguments and not isinstance(v, str):
                    raise TypeError(f"MCP path argument {key!r} must be a string")
                yield from self._mcp_strings(v, key)
        elif isinstance(value, str):
            yield key, value

    @staticmethod
    def _strip_file_uri(spelled: str) -> str:
        if spelled.startswith("file://"):
            return urlparse(spelled).path or "/"
        if spelled.startswith("file:"):
            return spelled[len("file:"):]
        return os.path.expanduser(spelled) if spelled.startswith("~") else spelled

    @staticmethod
    def _looks_like_path(spelled: str, base: Path) -> bool:
        if not spelled or len(spelled) > 4096 or "\0" in spelled:
            return False
        if spelled.startswith(("file:", "/", "./", "../", "~")) or spelled in (".", ".."):
            return True
        if "/" in spelled and "://" not in spelled and not any(c.isspace() for c in spelled):
            return True
        try:
            return os.path.lexists(base / spelled)
        except (OSError, ValueError):
            return False

    # -- api.call ---------------------------------------------------------------

    def _api_call(self, req, session) -> PolicyDecision:
        """Authorization per operation, independent of who the caller is.

        A valid delegation says who the agent acts for; it does not say what it
        may do. That is decided here, per audience and operation, before any
        credential exists. The scope in `normalized` is the only one the
        executor will ask the broker for.
        """
        audience = req.params["audience"]
        operation = req.params["operation"]
        arguments = req.params.get("arguments", {})
        if not isinstance(audience, str) or not isinstance(operation, str) \
                or not isinstance(arguments, dict):
            raise TypeError("audience/operation must be strings, arguments a dict")
        rule = self.cfg.apis.get(audience, {}).get(operation)
        normalized = {"audience": audience, "operation": operation,
                      "arguments": arguments,
                      "scope": rule.get("scope") if rule else None}
        if rule is None or not rule.get("scope"):
            return self._decide(req, Decision.BLOCK, "api-unknown-operation",
                                f"no policy for {audience}:{operation} (default-deny)",
                                "high", normalized)
        if session.tainted:
            return self._decide(req, Decision.BLOCK, "taint-session",
                                "session tainted by protected-path access; "
                                "no outbound API calls", "high", normalized,
                                matched=["api-policy", "taint-session"])
        decision = {"allow": Decision.ALLOW,
                    "require_approval": Decision.REQUIRE_APPROVAL}.get(
                        rule.get("decision"), Decision.BLOCK)
        rule_id = {Decision.ALLOW: "api-ok",
                   Decision.REQUIRE_APPROVAL: "api-approval",
                   Decision.BLOCK: "api-blocked"}[decision]
        risk = {Decision.ALLOW: "low", Decision.REQUIRE_APPROVAL: "medium",
                Decision.BLOCK: "high"}[decision]
        return self._decide(req, decision, rule_id,
                            f"{audience}:{operation} needs {rule['scope']} "
                            f"({decision.value} by policy)", risk, normalized)
