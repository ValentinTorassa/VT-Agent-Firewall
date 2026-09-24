"""The MCP proxy against a real MCP server process, spoken to over stdio.

The server (examples/fs_mcp_server.py) does no path checking at all, so every
block here comes from the proxy. Run from the repo root:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # for test_gateway helpers

from test_gateway import make_workspace  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SERVER = REPO / "examples" / "fs_mcp_server.py"
TIMEOUT = 10


class McpClient:
    """Just enough of an MCP host: newline-delimited JSON-RPC over pipes."""

    def __init__(self, argv: list[str]):
        env = {**os.environ, "PYTHONPATH": str(REPO)}
        self.proc = subprocess.Popen(argv, cwd=REPO, env=env, text=True,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, bufsize=1)
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        self._ids = iter(range(1, 10_000))

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.put(json.loads(line))

    def send(self, message: dict) -> None:
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        rid = next(self._ids)
        self.send({"jsonrpc": "2.0", "id": rid, "method": method,
                   "params": params or {}})
        reply = self.lines.get(timeout=TIMEOUT)
        assert reply["id"] == rid, reply
        return reply

    def call(self, name: str, **arguments) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments})["result"]

    def close(self) -> str:
        self.proc.stdin.close()
        self.proc.wait(timeout=TIMEOUT)
        return self.proc.stderr.read()


class TestMcpProxy(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gw-mcp-"))
        self.ws = make_workspace(self.tmp)
        self.policy = self.tmp / "policy.json"
        self.policy.write_text(json.dumps({
            "sandbox_root": "demo_workspace",
            "protected_paths": ["demo_workspace/.env",
                                "demo_workspace/fake_credentials.txt"],
            "writable_dirs": ["demo_workspace/normal"],
            "shell_allowlist": [],
            "network": {"mode": "deny_all"},
            # write_file and delete_file exist on the server but are not registered.
            "mcp_registry": {"fs": ["read_file", "list_directory"]},
        }))
        self.audit = self.tmp / "mcp-audit.jsonl"
        self.client = None

    def tearDown(self):
        if self.client and self.client.proc.poll() is None:
            self.client.close()

    def start(self, *extra: str) -> McpClient:
        self.client = McpClient([
            sys.executable, "-m", "agent_firewall.mcp_proxy",
            "--policy", str(self.policy), "--audit", str(self.audit),
            "--base-dir", str(self.tmp), "--server-name", "fs", *extra,
            "--", sys.executable, str(SERVER), str(self.ws)])
        init = self.client.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}})
        self.assertEqual(init["result"]["serverInfo"]["name"], "naive-fs")
        self.client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return self.client

    def audit_records(self) -> list[dict]:
        return [json.loads(l) for l in self.audit.read_text().splitlines() if l]

    def test_contrast_without_the_proxy_the_same_server_leaks(self):
        # Talk to the server directly: nothing stops read_file ../.env.
        self.client = McpClient([sys.executable, str(SERVER), str(self.ws)])
        leaked = self.client.call("read_file", path="malicious_repo/../.env")
        self.assertIn("fake-synthetic-key", leaked["content"][0]["text"])

    def test_initialize_and_ping_are_relayed(self):
        client = self.start()
        self.assertEqual(client.request("ping")["result"], {})

    def test_tools_list_hides_unregistered_tools(self):
        client = self.start()
        names = [t["name"] for t in client.request("tools/list")["result"]["tools"]]
        self.assertEqual(sorted(names), ["list_directory", "read_file"])

    def test_allowed_call_reaches_the_real_server(self):
        client = self.start()
        result = client.call("read_file", path="normal/notes.txt")
        self.assertFalse(result["isError"])
        self.assertIn("benign notes", result["content"][0]["text"])

    def test_protected_paths_are_blocked_before_the_server_sees_them(self):
        client = self.start()
        for path in (".env", "malicious_repo/../.env", "malicious_repo/config-link",
                     str(self.ws / "fake_credentials.txt")):
            result = client.call("read_file", path=path)
            self.assertTrue(result["isError"], path)
            self.assertIn("mcp-protected-path", result["content"][0]["text"], path)
            self.assertNotIn("fake-synthetic-key", json.dumps(result), path)

    def test_unregistered_tool_is_blocked_and_nothing_is_deleted(self):
        client = self.start()
        result = client.call("delete_file", path="canary/must-remain.txt")
        self.assertTrue(result["isError"])
        self.assertIn("mcp-unknown-tool", result["content"][0]["text"])
        self.assertTrue((self.ws / "canary" / "must-remain.txt").exists())

    def test_every_tool_call_is_audited_once_with_its_rule(self):
        client = self.start()
        client.call("read_file", path="normal/notes.txt")
        client.call("read_file", path=".env")
        client.call("write_file", path="normal/x.txt", content="x")
        client.close()
        rules = [r["rule_id"] for r in self.audit_records()]
        self.assertEqual(rules, ["mcp-ok", "mcp-protected-path", "mcp-unknown-tool"])
        self.assertEqual([r["outcome"] for r in self.audit_records()],
                         ["executed", "not_executed", "not_executed"])

    def test_malformed_arguments_fail_closed(self):
        client = self.start()
        reply = client.request("tools/call", {"name": "read_file", "arguments": "x"})
        self.assertTrue(reply["result"]["isError"])
        self.assertIn("parse-error", reply["result"]["content"][0]["text"])

    def test_pin_mismatch_refuses_to_start_the_server(self):
        proc = subprocess.run([
            sys.executable, "-m", "agent_firewall.mcp_proxy",
            "--policy", str(self.policy), "--audit", str(self.audit),
            "--base-dir", str(self.tmp), "--server-name", "fs",
            "--pin", f"{SERVER}={'0' * 64}",
            "--", sys.executable, str(SERVER), str(self.ws)],
            cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO)},
            capture_output=True, text=True, timeout=TIMEOUT, stdin=subprocess.DEVNULL)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("pin mismatch", proc.stderr)

    def test_matching_pin_starts_normally(self):
        digest = hashlib.sha256(SERVER.read_bytes()).hexdigest()
        client = self.start("--pin", f"{SERVER}={digest}")
        self.assertEqual(client.request("ping")["result"], {})


if __name__ == "__main__":
    unittest.main()
