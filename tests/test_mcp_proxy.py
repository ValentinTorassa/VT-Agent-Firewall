"""The MCP proxy against a real MCP server process, spoken to over stdio.

The server (examples/fs_mcp_server.py) does no path checking at all, so every
block here comes from the proxy. Run from the repo root:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))  # for test_gateway helpers
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_gateway import make_workspace  # noqa: E402

from agent_firewall import Gateway, learn  # noqa: E402
from agent_firewall.mcp_proxy import Learner, McpProxy  # noqa: E402

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
        self.pump = threading.Thread(target=self._pump, daemon=True)
        self.pump.start()
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
        self.pump.join(timeout=TIMEOUT)
        err = self.proc.stderr.read()
        self.proc.stdout.close()
        self.proc.stderr.close()
        return err


class McpProxyTestBase(unittest.TestCase):
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


class TestMcpProxy(McpProxyTestBase):
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

    def test_allowed_call_has_intent_and_outcome_while_blocks_have_one_record(self):
        client = self.start()
        client.call("read_file", path="normal/notes.txt")
        client.call("read_file", path=".env")
        client.call("write_file", path="normal/x.txt", content="x")
        client.close()
        rules = [r["rule_id"] for r in self.audit_records()]
        self.assertEqual(rules, ["mcp-ok", "mcp-ok", "mcp-protected-path", "mcp-unknown-tool"])
        self.assertEqual([r["outcome"] for r in self.audit_records()],
                         ["intent", "executed", "not_executed", "not_executed"])

    def test_malformed_arguments_fail_closed(self):
        client = self.start()
        reply = client.request("tools/call", {"name": "read_file", "arguments": "x"})
        self.assertTrue(reply["result"]["isError"])
        self.assertIn("parse-error", reply["result"]["content"][0]["text"])

    def test_paths_outside_the_sandbox_are_blocked(self):
        client = self.start()
        for arguments in ({"path": "/etc/hostname"}, {"path": "../../outside"},
                          {"path": "file:///etc/hostname"}):
            result = client.call("read_file", **arguments)
            self.assertTrue(result["isError"], arguments)
            self.assertIn("mcp-sandbox", result["content"][0]["text"], arguments)

    def test_a_batch_is_rejected_and_the_proxy_keeps_working(self):
        # 0.1.0: a JSON array crashed the dispatch loop and took the proxy down.
        client = self.start()
        client.send([{"jsonrpc": "2.0", "id": 90, "method": "tools/call",
                      "params": {"name": "read_file", "arguments": {"path": ".env"}}}])
        reply = client.lines.get(timeout=TIMEOUT)
        self.assertEqual(reply["error"]["code"], -32600)
        self.assertEqual(client.request("ping")["result"], {})

    def test_a_tool_call_sent_as_a_notification_never_reaches_the_server(self):
        client = self.start()
        client.send({"jsonrpc": "2.0", "method": "tools/call",
                     "params": {"name": "read_file", "arguments": {"path": ".env"}}})
        self.assertEqual(client.request("ping")["result"], {})
        self.assertIn("dropped tools/call sent as a notification", client.close())

    def test_resources_are_denied_by_default(self):
        client = self.start()
        reply = client.request("resources/read", {"uri": f"file://{self.ws / '.env'}"})
        self.assertIn("mcp-resources-denied", reply["error"]["message"])
        self.assertNotIn("fake-synthetic-key", json.dumps(reply))
        self.assertEqual(client.request("resources/list")["result"], {"resources": []})
        client.close()
        self.assertEqual([r["rule_id"] for r in self.audit_records()],
                         ["mcp-resources-denied"])

    def test_unknown_methods_are_not_relayed(self):
        client = self.start()
        reply = client.request("files/read_everything", {"path": ".env"})
        self.assertEqual(reply["error"]["code"], -32601)

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


class TestLearning(McpProxyTestBase):
    """`--learn TRACE`: the same guarantees as the hook's."""

    GATED = ("tools/call", "resources/read")

    def setUp(self):
        super().setUp()
        self.trace = self.tmp / "state" / "trace.jsonl"
        # A session in protocol order: the gated requests are the five tools/call
        # and the resources/read; the rest is relayed or refused before the policy.
        self.session = [
            ("tools/list", {}),
            ("tools/call", {"name": "read_file",
                            "arguments": {"path": "normal/notes.txt"}}),
            ("tools/call", {"name": "write_file",              # hidden, unregistered
                            "arguments": {"path": "normal/x.txt", "content": "x"}}),
            ("tools/call", {"name": "read_file", "arguments": "not an object"}),
            ("resources/read", {"uri": f"file://{self.ws / 'normal' / 'notes.txt'}"}),
            ("ping", {}),
            ("tools/call", {"name": "read_file", "arguments": {"path": ".env"}}),
            ("tools/call", {"name": "delete_file",
                            "arguments": {"path": "canary/must-remain.txt"}}),
        ]

    def play(self, *extra: str) -> list[dict]:
        client = self.start(*extra)
        replies = [client.request(method, params) for method, params in self.session]
        # Not decided by the policy, so not observed: a dropped notification.
        client.send({"jsonrpc": "2.0", "method": "tools/call",
                     "params": {"name": "read_file", "arguments": {"path": ".env"}}})
        replies.append(client.request("ping"))
        client.close()
        return replies

    def observations(self) -> list[dict]:
        return [json.loads(line) for line in self.trace.read_text().splitlines() if line]

    def test_answers_are_the_same_with_and_without_learn(self):
        self.assertEqual(self.play("--learn", str(self.trace)), self.play())
        self.assertTrue((self.ws / "canary" / "must-remain.txt").exists())

    def test_one_observation_per_gated_request(self):
        self.play("--learn", str(self.trace))
        observations = self.observations()
        self.assertEqual([o["host_tool"] for o in observations],
                         [m for m, _ in self.session if m in self.GATED])
        self.assertEqual([(o["decision"], o["rule_id"]) for o in observations],
                         [("allow", "mcp-ok"), ("block", "mcp-unknown-tool"),
                          ("block", "parse-error"), ("block", "mcp-resources-denied"),
                          ("block", "mcp-protected-path"), ("block", "mcp-unknown-tool")])
        [session] = {o["session_id"] for o in observations}
        self.assertTrue(session.startswith("mcp-fs-"))
        for obs in observations:
            self.assertEqual((obs["v"], obs["kind"], obs["mode"], obs["host"]),
                             (2, "decision", "enforce", "mcp-proxy"))
            self.assertEqual(obs["sandbox_root"], str(self.ws.resolve()))
            self.assertEqual(obs["self_protected"], [str(self.trace.resolve())])
        # The proxy is one session: taint sticks from the .env read on.
        self.assertEqual([o["tainted"] for o in observations],
                         [False, False, False, False, True, True])
        # Each observation is the decision the audit log recorded for it (an
        # allowed call has an intent and an outcome record, one observation).
        audit = {}
        for record in self.audit_records():
            audit.setdefault(record["correlation_id"], record)
        self.assertEqual(len(audit), len(observations))
        for obs in observations:
            record = audit[obs["correlation_id"]]
            self.assertEqual((obs["tool"], obs["normalized"], obs["rule_id"]),
                             (record["tool"], record["normalized"], record["rule_id"]))

    def test_the_trace_is_protected_from_the_agent(self):
        # Kept inside the sandbox on purpose, with write_file registered.
        self.trace = self.ws / "normal" / "trace.jsonl"
        policy = json.loads(self.policy.read_text())
        policy["mcp_registry"]["fs"].append("write_file")
        self.policy.write_text(json.dumps(policy))
        client = self.start("--learn", str(self.trace))
        for name, arguments in (("read_file", {"path": "normal/trace.jsonl"}),
                                ("write_file", {"path": "normal/trace.jsonl",
                                                "content": "{}"}),
                                ("read_file", {"path": "normal/../normal/trace.jsonl"})):
            result = client.call(name, **arguments)
            self.assertTrue(result["isError"], (name, arguments))
            self.assertIn("mcp-protected-path", result["content"][0]["text"])
        client.close()
        self.assertEqual(len(self.observations()), 3)
        # Without --learn the same file is just a file in normal/.
        client = self.start()
        self.assertFalse(client.call("read_file", path="normal/trace.jsonl")["isError"])

    def test_an_unavailable_trace_refuses_every_call(self):
        self.trace.mkdir(parents=True)          # a directory cannot be appended to
        client = self.start("--learn", str(self.trace))
        result = client.call("read_file", path="normal/notes.txt")
        self.assertTrue(result["isError"])
        self.assertIn("(fail-closed)", result["content"][0]["text"])
        self.assertIn("learning trace", result["content"][0]["text"])
        self.assertNotIn("benign notes", json.dumps(result))
        self.assertIn("mcp-protected-path", client.call("read_file", path=".env")
                      ["content"][0]["text"])
        self.assertEqual(client.request("ping")["result"], {})
        self.assertIn("learning trace", client.close())
        intent, refused, blocked = self.audit_records()
        self.assertEqual((intent["outcome"], refused["outcome"], refused["rule_id"]),
                         ("intent", "not_executed", "fail-closed"))
        self.assertEqual(intent["action_id"], refused["action_id"])
        self.assertEqual(blocked["rule_id"], "mcp-protected-path")

    def test_a_trace_that_fails_mid_session_refuses_from_then_on(self):
        policy = json.loads(self.policy.read_text())
        policy["mcp_registry"]["fs"].append("write_file")
        self.policy.write_text(json.dumps(policy))
        gateway = Gateway(self.policy, self.audit, base_dir=self.tmp)
        learner = Learner(gateway, self.trace, self.policy, "fs")
        out = io.StringIO()
        proxy = McpProxy(gateway, "fs", [sys.executable, str(SERVER), str(self.ws)],
                         client_out=out, learner=learner)
        self.addCleanup(gateway.audit.close)
        self.addCleanup(learner.close)

        def stop_server():
            proxy.server.stop()
            proxy.server.closed.wait(TIMEOUT)
            proxy.server.proc.stdin.close()
            proxy.server.proc.stdout.close()
        self.addCleanup(stop_server)

        def call(rid, name, **arguments):
            proxy.dispatch({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                            "params": {"name": name, "arguments": arguments}})
            return json.loads(out.getvalue().splitlines()[-1])["result"]

        # The second write fails; the trace would accept the third, but a trace
        # with a missing line is not one to propose from.
        outcomes = [None, learn.TraceUnavailable("cannot write learning trace: disk full")]

        def observe(*_args, **_kwargs):
            outcome = outcomes.pop(0) if outcomes else None
            if outcome is not None:
                raise outcome

        with mock.patch.object(learn.TraceWriter, "observe", side_effect=observe):
            self.assertFalse(call(1, "read_file", path="normal/notes.txt")["isError"])
            second = call(2, "write_file", path="normal/y.txt", content="y")
            third = call(3, "read_file", path="normal/notes.txt")
        for result in (second, third):
            self.assertTrue(result["isError"])
            self.assertIn("(fail-closed)", result["content"][0]["text"])
            self.assertIn("disk full", result["content"][0]["text"])
        self.assertFalse((self.ws / "normal" / "y.txt").exists())

    def test_propose_reads_a_proxy_trace(self):
        self.play("--learn", str(self.trace))
        out = self.tmp / "proposed.json"
        report, err = io.StringIO(), io.StringIO()
        code = learn.main(["--policy", str(self.policy), "--base-dir", str(self.tmp),
                           "--out", str(out), str(self.trace)], stdout=report, stderr=err)
        self.assertEqual(code, 0, err.getvalue())
        text = report.getvalue()
        # An MCP tool is listed for a decision about the server, never registered.
        self.assertEqual(json.loads(out.read_text()), json.loads(self.policy.read_text()))
        self.assertRegex(text, r"mcp_registry +fs/write_file +1 time, 1 session")
        self.assertRegex(text, r"Not learned from\n +tools/call fs/delete_file  \(1 time\)"
                               r"\n +session mcp-fs-\w+, after tools/call fs/read_file")
        for rule in ("mcp-protected-path", "mcp-resources-denied", "parse-error"):
            self.assertIn(f"    {rule} ", text)
        self.assertIn("Replayed against the proposal: allow 1 -> 1, ask 0 -> 0, "
                      "block 5 -> 5.", text)
        self.assertNotIn("decide differently", text)
        # Every observation is replayed against the policy as it is now, the
        # resource read included: enabling resources changes its decision.
        policy = json.loads(self.policy.read_text())
        policy["mcp_resources"] = ["fs"]
        enabled = self.tmp / "resources.json"
        enabled.write_text(json.dumps(policy))
        proposal = learn.propose(enabled, [self.trace], base_dir=self.tmp)
        self.assertEqual(proposal.before, {"allow": 2, "block": 4})
        self.assertIn("1 observation(s) decide differently now", proposal.notes[-1])


if __name__ == "__main__":
    unittest.main()
