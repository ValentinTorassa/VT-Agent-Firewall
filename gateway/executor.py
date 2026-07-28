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
    def execute(self, tool: str, normalized: dict):
        return {
            "fs.read": self._fs_read,
            "fs.write": self._fs_write,
            "shell.run": self._shell_run,
            "net.request": self._net_request,
            "mcp.call": self._mcp_call,
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

    def _mcp_call(self, n: dict) -> str:
        # Simulated MCP server: registered tools only, no real side effects.
        if n["tool"] == "ping":
            return "pong"
        if n["tool"] == "echo":
            return str(n["arguments"].get("text", ""))
        return f"simulated result for {n['server']}/{n['tool']}"
