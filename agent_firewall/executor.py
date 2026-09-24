"""Executors: the only code that touches the real world.

Input is ALWAYS the normalized dict from a PolicyDecision, never the
spelled request params. shell=False everywhere; network executor exists
only for the --no-firewall contrast mode (policy never allows it).
"""

from __future__ import annotations

import subprocess
import urllib.request
from pathlib import Path

READ_CAP_BYTES = 64 * 1024
SHELL_TIMEOUT_SEC = 10
NET_TIMEOUT_SEC = 5


class Executor:
    def __init__(self, broker=None, subject: str | None = None, apis=None,
                 actor: str = "agent", mcp_backends=None):
        self.broker = broker    # TokenBroker holding the user's delegation
        self.subject = subject  # the user the agent acts for
        self.apis = apis or {}  # audience -> resource server client
        self.actor = actor
        self.mcp_backends = mcp_backends or {}  # server name -> live MCP connection

    def execute(self, tool: str, normalized: dict):
        return {
            "fs.read": self._fs_read,
            "fs.write": self._fs_write,
            "shell.run": self._shell_run,
            "net.request": self._net_request,
            "mcp.call": self._mcp_call,
            "api.call": self._api_call,
        }[tool](normalized)

    def _fs_read(self, n: dict) -> str:
        data = Path(n["path"]).read_bytes()[:READ_CAP_BYTES]
        return data.decode("utf-8", errors="replace")

    def _fs_write(self, n: dict) -> str:
        Path(n["path"]).write_text(n["content"], encoding="utf-8")
        return f"wrote {len(n['content'])} bytes to {n['path']}"

    def _shell_run(self, n: dict) -> str:
        proc = subprocess.run(
            [n["binary"], *n["args"]],
            shell=False, cwd=n["cwd"], capture_output=True, text=True,
            timeout=SHELL_TIMEOUT_SEC,
        )
        out = (proc.stdout + proc.stderr).strip()
        return f"exit={proc.returncode} {out[:2000]}"

    def _net_request(self, n: dict) -> str:
        body = n.get("body")
        data = body.encode() if isinstance(body, str) else None
        req = urllib.request.Request(n["url"], data=data,
                                     method=n.get("method", "GET"))
        with urllib.request.urlopen(req, timeout=NET_TIMEOUT_SEC) as resp:
            return f"HTTP {resp.status}"

    def _mcp_call(self, n: dict):
        backend = self.mcp_backends.get(n["server"])
        if backend is not None:
            # A real server behind the MCP proxy: forward the approved call and
            # return its MCP result object untouched.
            return backend.call_tool(n["tool"], n["arguments"])
        # Simulated MCP server: registered tools only, no real side effects.
        if n["tool"] == "ping":
            return "pong"
        if n["tool"] == "echo":
            return str(n["arguments"].get("text", ""))
        return f"simulated result for {n['server']}/{n['tool']}"

    def _api_call(self, n: dict) -> dict:
        # The token is minted here, after the policy said yes, for exactly the
        # audience and scope of this one call. It is used and dropped: only its
        # claims (jti, scope, expiry) come back for the audit record.
        if self.broker is None or self.subject is None:
            raise RuntimeError("no credential broker configured")
        api = self.apis.get(n["audience"])
        if api is None:
            raise RuntimeError(f"no client for audience {n['audience']!r}")
        token = self.broker.exchange(
            subject=self.subject, actor=self.actor,
            tool=f"{n['audience']}:{n['operation']}",
            audience=n["audience"], scopes={n["scope"]})
        result = api.call(token.value, n["operation"], n["arguments"])
        return {"result": result, "token": token.claims()}
