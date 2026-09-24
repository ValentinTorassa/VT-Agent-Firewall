"""Policy engine: normalize the ActionRequest, then evaluate rules.

Normalization happens BEFORE evaluation and the executor only receives
normalized params:
- every fs path is canonicalized with realpath (resolves `..` and symlinks)
- shell requests are tokenized to argv (shlex) and never reach a shell
- URLs are parsed into scheme/host/port

Rule precedence (per tool, most specific first):
  fs-protected > fs-sandbox > tool-specific checks > allow/default-deny
Fail-closed: malformed params, unknown tools, or no matching allow rule
all produce BLOCK.
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from urllib.parse import urlparse

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
        if binary not in self.cfg.shell_allowlist:
            return self._decide(req, Decision.BLOCK, "sh-allowlist",
                                f"binary not allowlisted: {binary}", "high",
                                normalized)
        forbidden = self.cfg.shell_forbidden_args.get(binary, set())
        bad = sorted(forbidden.intersection(args))
        if bad:
            return self._decide(req, Decision.BLOCK, "sh-args",
                                f"forbidden args for {binary}: {bad}", "high",
                                normalized)
        # Every non-flag argument is treated as a path candidate and checked
        # against the canonical filesystem view.
        for arg in args:
            if arg.startswith("-"):
                continue
            resolved = self._resolve_path(arg, cwd)
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
        return self._decide(req, Decision.ALLOW, "sh-ok",
                            f"allowlisted binary, paths in sandbox: {binary}",
                            "low", normalized)

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
        normalized = {"server": server, "tool": tool, "arguments": arguments}
        if tool in self.cfg.mcp_registry.get(server, set()):
            return self._decide(req, Decision.ALLOW, "mcp-ok",
                                f"registered MCP tool: {server}/{tool}", "low",
                                normalized)
        return self._decide(req, Decision.BLOCK, "mcp-unknown-tool",
                            f"unregistered MCP tool: {server}/{tool}", "high",
                            normalized)
