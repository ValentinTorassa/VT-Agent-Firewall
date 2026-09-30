"""Regression tests for the bypasses found in the 2026-09-29 review.

Each test is a proof of concept that worked against 0.1.0: a recursive read
that names no protected file but reaches one, option values the path check
never looked at, find predicates that write, children of a protected
directory, and MCP arguments outside the four checked names. They must stay
blocked, never execute, and taint the session when a protected path is in
reach.

Run from the repo root:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # test_gateway helpers
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_gateway import Approver, make_workspace  # noqa: E402

from agent_firewall import ActionRequest, Gateway  # noqa: E402

SECRET = "fake-synthetic-key"
REPO = Path(__file__).resolve().parent.parent


class BypassBase(unittest.TestCase):
    extra_protected: list[str] = []

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gw-bypass-"))
        self.ws = make_workspace(self.tmp)
        # normal/up -> ..: a symlinked directory back to the sandbox root.
        os.symlink("..", self.ws / "normal" / "up")
        config = {
            "sandbox_root": "demo_workspace",
            "protected_paths": ["demo_workspace/.env",
                                "demo_workspace/fake_credentials.txt",
                                *self.extra_protected],
            "writable_dirs": ["demo_workspace/normal"],
            "shell_allowlist": ["ls", "grep", "cat", "head", "tail", "find", "wc"],
            "shell_forbidden_args": {"find": ["-exec", "-execdir", "-delete"]},
            "network": {"mode": "deny_all"},
            "mcp_registry": {"demo": ["ping", "echo"], "fs": ["read_file"]},
            "approval_timeout_sec": 1,
            "apis": {"calendar-api": {"events.read": {"scope": "calendar.read",
                                                      "decision": "allow"}}},
        }
        self.config_path = self.tmp / "config.json"
        self.config_path.write_text(json.dumps(config))
        self.audit_path = self.tmp / "audit.jsonl"
        self.gw = Gateway(self.config_path, self.audit_path,
                          approver=Approver(False), base_dir=self.tmp)

    def tearDown(self):
        if self.gw.audit is not None:
            self.gw.audit.close()

    def run_shell(self, command_line: str, **params) -> dict:
        return self.gw.handle(ActionRequest(
            actor="test", tool="shell.run",
            params={"command_line": command_line, **params}))

    def mcp(self, tool: str, arguments: dict, server: str = "fs") -> dict:
        return self.gw.handle(ActionRequest(
            actor="test", tool="mcp.call",
            params={"server": server, "tool": tool, "arguments": arguments}))

    def assertBlocked(self, record: dict, rule_id: str, msg=None):
        self.assertEqual((record["decision"], record["rule_id"], record["outcome"]),
                         ("block", rule_id, "not_executed"), msg or record["reason"])
        self.assertNotIn(SECRET, json.dumps(record), msg)

    def assertAllowed(self, record: dict, msg=None):
        self.assertEqual((record["decision"], record["outcome"]),
                         ("allow", "executed"), msg or record["reason"])


class TestRecursiveReads(BypassBase):
    def test_recursive_grep_on_the_sandbox_root_is_blocked_and_taints(self):
        # 0.1.0: allow sh-ok, executed, the secret in the result, no taint, and
        # the next outbound API call allowed.
        r = self.run_shell("grep -r '' .")
        self.assertBlocked(r, "sh-recursive")
        self.assertIn("fs-protected", r["rules_matched"])
        self.assertTrue(self.gw.session.tainted)
        api = self.gw.handle(ActionRequest(actor="test", tool="api.call", params={
            "audience": "calendar-api", "operation": "events.read", "arguments": {}}))
        self.assertEqual((api["decision"], api["rule_id"]), ("block", "taint-session"))

    def test_every_recursive_spelling_is_caught(self):
        for command in ("grep -R -h '' normal/up",   # symlinked dir back to the root
                        "grep -rn key",              # no operand: grep walks cwd
                        "grep -d recurse key .",
                        "grep --directories=recurse key .",
                        "grep --recursive key .",
                        "grep --dereference-recursive key normal",  # normal/up -> ..
                        "grep -rl key malicious_repo",  # config-link -> ../.env
                        "grep -ir KEY . --include=*.env",
                        "ls -R",
                        "ls --recursive normal",
                        "find . -name .env",
                        "find normal -follow -name '*'",
                        "find . -maxdepth 1 -name '*'"):
            with self.subTest(command=command):
                self.assertBlocked(self.run_shell(command), "sh-recursive", command)

    def test_scoped_recursion_that_reaches_nothing_protected_still_runs(self):
        os.remove(self.ws / "normal" / "up")
        self.assertAllowed(self.run_shell("grep -r benign normal"))
        self.assertAllowed(self.run_shell("ls -R normal"))
        self.assertAllowed(self.run_shell("find normal -name '*.txt'"))
        # -maxdepth 0 is the start point only.
        self.assertAllowed(self.run_shell("find . -maxdepth 0"))
        # In ls, -r means reverse, not recursive.
        self.assertAllowed(self.run_shell("ls -r ."))
        self.assertFalse(self.gw.session.tainted)

    def test_a_symlink_out_of_the_sandbox_stops_a_walk(self):
        os.symlink(str(self.tmp), self.ws / "normal" / "outside")
        os.remove(self.ws / "normal" / "up")
        r = self.run_shell("grep -r x normal")
        self.assertBlocked(r, "sh-recursive")
        self.assertIn("leave the sandbox", r["reason"])


class TestOptionValues(BypassBase):
    def test_file_valued_options_are_path_checked(self):
        # 0.1.0: `grep --file=.env` was allowed; only `-f .env` was caught.
        for command in ("grep --file=.env x normal/notes.txt",
                        "grep -f.env x normal/notes.txt",
                        "grep -f .env x normal/notes.txt",
                        "grep --exclude-from=.env x normal/notes.txt",
                        "grep -e x -f fake_credentials.txt normal/notes.txt",
                        "find normal -newer .env",
                        "find normal -samefile malicious_repo/config-link"):
            with self.subTest(command=command):
                r = self.run_shell(command)
                self.assertBlocked(r, "sh-paths", command)
                self.assertIn("fs-protected", r["rules_matched"])

    def test_options_outside_the_grammar_are_refused_and_still_taint(self):
        for command in ("wc --files0-from=.env", "cat --unknown normal/notes.txt",
                        "head -Z normal/notes.txt", "tail -f normal/notes.txt",
                        "grep --no-such-flag x normal/notes.txt"):
            with self.subTest(command=command):
                self.assertBlocked(self.run_shell(command), "sh-args", command)
        # --files0-from=.env named the secret: blocked AND tainted.
        self.assertTrue(self.gw.session.tainted)

    def test_the_grep_pattern_is_not_mistaken_for_a_file(self):
        r = self.run_shell("grep benign normal/notes.txt")
        self.assertAllowed(r)
        self.assertIn("benign notes", r["result_preview"])


class TestFindPredicates(BypassBase):
    def test_find_cannot_write_execute_or_delete(self):
        # 0.1.0: `-fprint` overwrote the canary without approval.
        canary = self.ws / "canary" / "must-remain.txt"
        for command in ("find normal -maxdepth 0 -fprint canary/must-remain.txt",
                        "find normal -maxdepth 0 -fprint0 canary/must-remain.txt",
                        "find normal -maxdepth 0 -fprintf canary/must-remain.txt %p",
                        "find normal -maxdepth 0 -fls canary/must-remain.txt",
                        "find normal -ok cat {} ;",
                        "find normal -okdir cat {} ;",
                        "find normal -exec cat {} ;",
                        "find normal -execdir cat {} ;",
                        "find normal -delete"):
            with self.subTest(command=command):
                self.assertBlocked(self.run_shell(command), "sh-args", command)
        self.assertEqual(canary.read_text(), "untouched\n")
        self.assertTrue((self.ws / "normal" / "notes.txt").exists())


class TestProtectedDirectory(BypassBase):
    extra_protected = ["demo_workspace/canary"]

    def test_children_of_a_protected_directory_are_protected(self):
        # 0.1.0: protected entries matched exactly, so canary/must-remain.txt
        # was readable while canary/ itself was protected.
        read = self.gw.handle(ActionRequest(actor="test", tool="fs.read",
                                            params={"path": "canary/must-remain.txt"}))
        self.assertBlocked(read, "fs-protected")
        write = self.gw.handle(ActionRequest(actor="test", tool="fs.write", params={
            "path": "canary/new.txt", "content": "x"}))
        self.assertBlocked(write, "fs-protected")
        self.assertBlocked(self.run_shell("cat canary/must-remain.txt"), "sh-paths")
        self.assertBlocked(self.mcp("read_file", {"path": "canary/must-remain.txt"}),
                           "mcp-protected-path")
        self.assertTrue(self.gw.session.tainted)
        self.assertFalse((self.ws / "canary" / "new.txt").exists())


class TestMcpArguments(BypassBase):
    def test_path_arguments_must_stay_in_the_sandbox(self):
        # 0.1.0: absolute and ../ paths passed; only protected ones were checked.
        for arguments in ({"path": "/etc/hostname"},
                          {"path": "../../outside"},
                          {"path": "file:///etc/hostname"},
                          {"paths": ["normal/notes.txt", "/etc/passwd"]},
                          {"query": "~/.ssh/id_rsa"}):
            with self.subTest(arguments=arguments):
                self.assertBlocked(self.mcp("read_file", arguments), "mcp-sandbox")

    def test_any_argument_name_that_carries_a_path_is_checked(self):
        # 0.1.0: only path, paths, source and destination were checked.
        for arguments in ({"file": ".env"},
                          {"name": ".env"},  # exists under the root
                          {"options": {"target": "malicious_repo/config-link"}},
                          {"uri": f"file://{self.ws / '.env'}"},
                          {"paths": ["normal/notes.txt", "fake_credentials.txt"]}):
            with self.subTest(arguments=arguments):
                self.assertBlocked(self.mcp("read_file", arguments), "mcp-protected-path")
        self.assertTrue(self.gw.session.tainted)

    def test_plain_text_arguments_pass(self):
        self.assertAllowed(self.mcp("echo", {"text": "hello world"}, server="demo"))
        self.assertAllowed(self.mcp("echo", {"text": "see https://example.com/x"},
                                    server="demo"))

    def test_non_string_path_argument_fails_closed(self):
        r = self.mcp("read_file", {"path": 7})
        self.assertBlocked(r, "parse-error")

    def test_resources_are_denied_by_default(self):
        r = self.gw.handle(ActionRequest(actor="test", tool="mcp.resource", params={
            "server": "fs", "uri": "file:///etc/hostname"}))
        self.assertBlocked(r, "mcp-resources-denied")


class TestAuditMinimization(BypassBase):
    def test_written_content_is_hashed_and_bodies_truncated(self):
        content = "line with synthetic secret material\n" * 3
        r = self.gw.handle(ActionRequest(actor="test", tool="fs.write", params={
            "path": "normal/out.txt", "content": content}))
        self.assertAllowed(r)
        self.assertEqual((self.ws / "normal" / "out.txt").read_text(), content)
        log = self.audit_path.read_text()
        self.assertNotIn("synthetic secret material", log)
        for record in map(json.loads, log.splitlines()):
            self.assertEqual(record["spelled_params"]["content"]["bytes"],
                             len(content.encode()))
            self.assertRegex(record["normalized"]["content"]["sha256"], "^[0-9a-f]{64}$")
        body = "B" * 500
        net = self.gw.handle(ActionRequest(actor="test", tool="net.request", params={
            "url": "http://127.0.0.1:9/x", "method": "POST", "body": body}))
        self.assertLess(len(net["spelled_params"]["body"]), 100)
        self.assertEqual(net["spelled_params"]["body_digest"]["bytes"], 500)

    def test_verbose_audit_keeps_the_content(self):
        gw = Gateway(self.config_path, self.tmp / "verbose.jsonl",
                     base_dir=self.tmp, audit_verbose=True)
        r = gw.handle(ActionRequest(actor="test", tool="fs.write", params={
            "path": "normal/v.txt", "content": "kept"}))
        gw.audit.close()
        self.assertEqual(r["spelled_params"]["content"], "kept")


class TestExecutorStdin(unittest.TestCase):
    def test_a_command_without_file_operands_does_not_read_our_stdin(self):
        # `grep foo` with no file reads stdin. In the MCP proxy stdin is the
        # client's JSON-RPC channel: the executor must hand it /dev/null.
        script = (
            "import sys, json, tempfile, pathlib;"
            f"sys.path.insert(0, {str(REPO)!r});"
            "from agent_firewall import Gateway, ActionRequest;"
            "d = pathlib.Path(tempfile.mkdtemp());"
            f"gw = Gateway({str(REPO / 'policies/default.json')!r}, d / 'a.jsonl',"
            f" base_dir={str(REPO)!r});"
            "r = gw.handle(ActionRequest(actor='t', tool='shell.run',"
            " params={'command_line': 'grep foo', 'cwd': 'normal'}));"
            "print(r['decision'], r['outcome'])")
        proc = subprocess.Popen([sys.executable, "-c", script], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, text=True)
        try:
            proc.wait(timeout=6)   # stdin stays open: an inherited stdin would hang
        except subprocess.TimeoutExpired:
            proc.kill()
            self.fail("the executor read the gateway's stdin")
        finally:
            proc.stdin.close()
        self.assertEqual(proc.stdout.read().split(), ["allow", "executed"])


if __name__ == "__main__":
    unittest.main()
