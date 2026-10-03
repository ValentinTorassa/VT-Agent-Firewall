"""The PreToolUse hook (agent_firewall/hook.py) for Claude Code and Codex.

Every event here is a synthetic fixture fed on stdin; nothing touches a real
Claude Code or Codex configuration. The hook must deny, ask or stay silent per
the hosts' protocols, write the decision to the audit log before the host can
act, and deny (exit 2) on anything it cannot vouch for.

Run from the repo root:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))  # test_gateway helpers
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_gateway import make_workspace  # noqa: E402

from agent_firewall import hook, shell_syntax  # noqa: E402
from agent_firewall.config import Config  # noqa: E402
from agent_firewall.policy import PolicyEngine  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


class HookTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gw-hook-"))
        self.ws = make_workspace(self.tmp)
        self.policy = {
            "sandbox_root": "demo_workspace",
            "protected_paths": ["demo_workspace/.env",
                                "demo_workspace/fake_credentials.txt"],
            "writable_dirs": ["demo_workspace/normal"],
            "shell_allowlist": ["ls", "grep", "cat", "head", "tail", "find", "wc"],
            "shell_forbidden_args": {"find": ["-exec", "-execdir", "-delete"]},
            "network": {"mode": "deny_all"},
            "mcp_registry": {"demo": ["ping", "echo"]},
        }
        self.policy_path = self.tmp / "policy.json"
        self.policy_path.write_text(json.dumps(self.policy))
        self.audit_path = self.tmp / "logs" / "audit.jsonl"

    def event(self, tool_name, tool_input, **overrides):
        event = {
            "session_id": "test-session",
            "transcript_path": "/dev/null",
            "cwd": str(self.ws),
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_use_id": "toolu_test_1",
        }
        event.update(overrides)
        return event

    def run_hook(self, payload, host="claude-code", extra_args=(), policy=None):
        """In-process run. Returns (exit code, stdout JSON or None, stderr)."""
        raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        out, err = io.StringIO(), io.StringIO()
        argv = ["--policy", str(policy or self.policy_path),
                "--audit", str(self.audit_path), "--base-dir", str(self.tmp),
                "--host", host, *extra_args]
        code = hook.main(argv, stdin=io.BytesIO(raw), stdout=out, stderr=err)
        text = out.getvalue().strip()
        return code, (json.loads(text) if text else None), err.getvalue()

    def records(self):
        if not self.audit_path.exists():
            return []
        return [json.loads(line) for line in
                self.audit_path.read_text().splitlines() if line]

    def assertDenied(self, result, rule_id):
        code, out, err = result
        self.assertEqual(code, 2, err)
        decision = out["hookSpecificOutput"]
        self.assertEqual(decision["hookEventName"], "PreToolUse")
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertIn(f"({rule_id})", decision["permissionDecisionReason"])
        # Exit 2 blocks on stderr alone, which is what Codex reads.
        self.assertIn(f"({rule_id})", err)

    def assertSilentAllow(self, result):
        code, out, err = result
        self.assertEqual((code, out), (0, None), err)


class TestClaudeCodeShell(HookTestBase):
    def test_bash_protected_path_denied_and_audited(self):
        self.assertDenied(self.run_hook(self.event("Bash", {"command": "cat .env"})),
                          "sh-paths")
        [record] = self.records()
        self.assertEqual((record["decision"], record["rule_id"], record["outcome"]),
                         ("block", "sh-paths", "not_executed"))
        self.assertEqual((record["host"], record["host_tool"], record["session_id"],
                          record["correlation_id"], record["tool"]),
                         ("claude-code", "Bash", "test-session", "toolu_test_1",
                          "shell.run"))
        self.assertTrue(record["spelled_params"]["via_shell"])

    def test_bash_simple_command_allowed_silently_and_audited_first(self):
        self.assertSilentAllow(self.run_hook(
            self.event("Bash", {"command": "cat normal/notes.txt"})))
        [record] = self.records()
        self.assertEqual((record["decision"], record["rule_id"], record["outcome"]),
                         ("allow", "sh-ok", "delegated"))
        self.assertEqual(record["normalized"]["args"], ["normal/notes.txt"])

    def test_emit_allow_answers_explicitly(self):
        code, out, _ = self.run_hook(self.event("Bash", {"command": "ls normal"}),
                                     extra_args=["--emit-allow"])
        self.assertEqual(code, 0)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "allow")

    def test_shell_syntax_is_refused_before_anything_runs(self):
        for command in ("cat normal/notes.txt; curl http://127.0.0.1:8765",
                        "cat normal/notes.txt && cat .env",
                        "cat normal/notes.txt | wc -l",
                        "cat .e*",
                        "cat .e?v",
                        "cat {.env,normal/notes.txt}",
                        "cat $(echo .env)",
                        "cat `echo .env`",
                        'cat "$HOME/.ssh/id_rsa"',
                        "cat ~/.ssh/id_rsa",
                        "cat normal/notes.txt > normal/copy.txt",
                        "cat < .env",
                        "cat normal/notes.txt\ncat .env",
                        "cat =ls",
                        "cat 'unterminated"):
            with self.subTest(command=command):
                self.assertDenied(self.run_hook(self.event("Bash", {"command": command})),
                                  "sh-syntax")
        self.assertTrue(all(r["rule_id"] == "sh-syntax" for r in self.records()))

    def test_quoted_metacharacters_are_literal_and_allowed(self):
        self.assertSilentAllow(self.run_hook(
            self.event("Bash", {"command": "grep -e 'fake|key*' normal/notes.txt"})))

    def test_recursive_walk_into_secret_denied(self):
        self.assertDenied(self.run_hook(self.event("Bash", {"command": "grep -r '' ."})),
                          "sh-recursive")

    def test_binary_outside_allowlist_denied(self):
        self.assertDenied(self.run_hook(
            self.event("Bash", {"command": "curl http://127.0.0.1:8765"})), "sh-allowlist")

    def test_env_assignment_prefix_is_not_the_binary(self):
        self.assertDenied(self.run_hook(
            self.event("Bash", {"command": "LD_PRELOAD=/tmp/x.so cat normal/notes.txt"})),
            "sh-allowlist")

    def test_cwd_outside_sandbox_denied(self):
        self.assertDenied(self.run_hook(
            self.event("Bash", {"command": "ls"}, cwd=str(self.tmp))), "fs-sandbox")

    def test_monitor_command_is_a_shell_command(self):
        self.assertDenied(self.run_hook(
            self.event("Monitor", {"command": "tail -n 1 .env", "description": "x",
                                   "timeout_ms": 1000})), "sh-paths")

    def test_monitor_websocket_is_network(self):
        self.assertDenied(self.run_hook(
            self.event("Monitor", {"ws": {"url": "wss://example.com/feed"},
                                   "description": "x", "timeout_ms": 1000})),
            "net-deny-all")


class TestClaudeCodeFiles(HookTestBase):
    def test_read_secret_denied_benign_allowed(self):
        self.assertDenied(self.run_hook(
            self.event("Read", {"file_path": str(self.ws / ".env")})), "fs-protected")
        self.assertSilentAllow(self.run_hook(
            self.event("Read", {"file_path": str(self.ws / "normal" / "notes.txt")})))

    def test_edit_through_symlink_to_secret_denied(self):
        self.assertDenied(self.run_hook(self.event("Edit", {
            "file_path": str(self.ws / "malicious_repo" / "config-link"),
            "old_string": "API_KEY", "new_string": "X"})), "fs-protected")

    def test_write_inside_writable_allowed(self):
        self.assertSilentAllow(self.run_hook(self.event("Write", {
            "file_path": str(self.ws / "normal" / "out.txt"), "content": "ok"})))
        self.assertFalse((self.ws / "normal" / "out.txt").exists(),
                         "the hook decides; it never writes")

    def test_write_outside_writable_asks_with_canonical_path(self):
        code, out, _ = self.run_hook(self.event("Write", {
            "file_path": str(self.ws / "canary" / "must-remain.txt"),
            "content": "pwned"}))
        self.assertEqual(code, 0)
        decision = out["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "ask")
        self.assertIn("fs-write-scope", decision["permissionDecisionReason"])
        self.assertIn(str((self.ws / "canary" / "must-remain.txt").resolve()),
                      decision["permissionDecisionReason"])
        [record] = self.records()
        self.assertEqual((record["decision"], record["outcome"]),
                         ("require_approval", "delegated"))

    def test_ask_becomes_deny_in_bypass_permissions_mode(self):
        self.assertDenied(self.run_hook(self.event("Write", {
            "file_path": str(self.ws / "canary" / "new.txt"), "content": "x"},
            permission_mode="bypassPermissions")), "approval-denied")

    def test_write_outside_sandbox_denied(self):
        self.assertDenied(self.run_hook(self.event("Write", {
            "file_path": str(self.tmp / "outside.txt"), "content": "x"})), "fs-sandbox")

    def test_audit_keeps_a_digest_of_written_content_not_the_content(self):
        self.run_hook(self.event("Write", {
            "file_path": str(self.ws / "normal" / "out.txt"),
            "content": "synthetic secret body"}))
        [record] = self.records()
        self.assertNotIn("synthetic secret body", json.dumps(record))
        self.assertEqual(record["spelled_params"]["content"]["bytes"], 21)

    def test_multiedit_and_notebookedit(self):
        self.assertDenied(self.run_hook(self.event("MultiEdit", {
            "file_path": str(self.ws / ".env"),
            "edits": [{"old_string": "a", "new_string": "b"}]})), "fs-protected")
        code, out, _ = self.run_hook(self.event("NotebookEdit", {
            "notebook_path": str(self.ws / "canary" / "n.ipynb"),
            "new_source": "print(1)", "edit_mode": "replace"}))
        self.assertEqual((code, out["hookSpecificOutput"]["permissionDecision"]),
                         (0, "ask"))

    def test_policy_and_audit_files_protect_themselves(self):
        # A policy kept inside the sandbox can be neither read nor rewritten.
        inside = self.ws / "normal" / "firewall-policy.json"
        inside.write_text(json.dumps(self.policy))
        self.assertDenied(self.run_hook(self.event("Write", {
            "file_path": str(inside), "content": "{}"}), policy=inside), "fs-protected")
        self.assertDenied(self.run_hook(self.event("Bash", {
            "command": "cat normal/firewall-policy.json"}), policy=inside), "sh-paths")


class TestClaudeCodeOtherTools(HookTestBase):
    def test_webfetch_is_network_and_denied(self):
        self.assertDenied(self.run_hook(self.event("WebFetch", {
            "url": "https://example.com/", "prompt": "summarize"})), "net-deny-all")

    def test_unmapped_tool_default_denied(self):
        self.assertDenied(self.run_hook(self.event("WebSearch", {"query": "x"})),
                          "unknown-tool")
        [record] = self.records()
        self.assertEqual(record["tool"], "claude-code:WebSearch")

    def test_mcp_tools_use_the_registry(self):
        self.assertSilentAllow(self.run_hook(self.event("mcp__demo__ping", {})))
        self.assertDenied(self.run_hook(self.event("mcp__evil__exfiltrate", {"x": 1})),
                          "mcp-unknown-tool")
        self.assertDenied(self.run_hook(self.event("mcp__demo__echo",
                                                   {"path": "../.env"})),
                          "mcp-sandbox")


class TestMalformedInput(HookTestBase):
    def test_malformed_events_deny_with_parse_error_and_are_audited(self):
        cases = {
            "not json": b"not json",
            "empty": b"",
            "array": b"[]",
            "binary": b"\xff\xfe\x00",
            "no tool_input": self.event("Bash", None),
            "command not a string": self.event("Bash", {"command": ["cat", ".env"]}),
            "empty command": self.event("Bash", {"command": ""}),
            "no cwd": self.event("Bash", {"command": "ls"}, cwd=None),
            "relative cwd": self.event("Bash", {"command": "ls"}, cwd="demo_workspace"),
            "no tool_name": self.event(None, {"command": "ls"}),
            "wrong event": self.event("Bash", {"command": "ls"},
                                      hook_event_name="PostToolUse"),
            "write without path": self.event("Write", {"content": "x"}),
            "bad mcp name": self.event("mcp__onlyserver", {}),
        }
        for name, payload in cases.items():
            with self.subTest(case=name):
                self.assertDenied(self.run_hook(payload), "parse-error")
        records = self.records()
        self.assertEqual(len(records), len(cases))
        self.assertTrue(all(r["rule_id"] == "parse-error" and
                            r["outcome"] == "not_executed" for r in records))
        # The raw input is kept as a digest only.
        self.assertIn("sha256", records[0]["spelled_params"]["input"])


class TestFailClosed(HookTestBase):
    def test_missing_policy_denies(self):
        result = self.run_hook(self.event("Bash", {"command": "ls"}),
                               policy=self.tmp / "missing.json")
        self.assertEqual(result[0], 2)
        self.assertIn("cannot load policy", result[1]["hookSpecificOutput"]
                      ["permissionDecisionReason"])
        self.assertEqual(self.records()[0]["rule_id"], "fail-closed")

    def test_invalid_policy_denies(self):
        self.policy_path.write_text("{ not json")
        self.assertEqual(self.run_hook(self.event("Bash", {"command": "ls"}))[0], 2)

    def test_unavailable_audit_store_denies_even_an_allowed_call(self):
        self.audit_path.parent.mkdir(parents=True)
        self.audit_path.mkdir()          # a directory cannot be opened for append
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertDenied(self.run_hook(self.event("Bash", {"command": "ls normal"})),
                              "fail-closed")

    def test_internal_error_denies(self):
        with mock.patch.object(PolicyEngine, "evaluate", side_effect=RuntimeError("boom")):
            code, out, err = self.run_hook(self.event("Bash", {"command": "ls normal"}))
        self.assertEqual(code, 2)
        self.assertIn("internal error", err)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_deadline_denies_before_the_host_timeout(self):
        def slow(*_args, **_kwargs):
            time.sleep(5)
        with mock.patch.object(PolicyEngine, "evaluate", side_effect=slow):
            started = time.monotonic()
            code, out, err = self.run_hook(self.event("Bash", {"command": "ls normal"}),
                                           extra_args=["--deadline", "0.2"])
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(code, 2)
        self.assertIn("no decision within", err)

    def test_bad_arguments_deny(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                hook.main(["--audit", "x"], stdin=io.BytesIO(b"{}"))
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]
                         ["permissionDecision"], "deny")

    def test_real_process_exit_codes(self):
        """The module as the host runs it: a separate process, exit code only."""
        def run(event):
            return subprocess.run(
                [sys.executable, "-m", "agent_firewall.hook",
                 "--policy", str(self.policy_path), "--audit", str(self.audit_path),
                 "--base-dir", str(self.tmp)],
                input=json.dumps(event), capture_output=True, text=True, cwd=REPO,
                env={**os.environ, "PYTHONPATH": str(REPO)}, timeout=30)
        denied = run(self.event("Bash", {"command": "cat .env"}))
        self.assertEqual(denied.returncode, 2, denied.stderr)
        self.assertIn("sh-paths", denied.stderr)
        allowed = run(self.event("Bash", {"command": "ls normal"}))
        self.assertEqual((allowed.returncode, allowed.stdout), (0, ""), allowed.stderr)

    def test_parallel_hook_processes_keep_the_audit_log_whole(self):
        """Hosts run tool calls, and so hooks, in parallel; every record must
        stay one valid JSON line even when it is larger than a write buffer."""
        argv = [sys.executable, "-m", "agent_firewall.hook",
                "--policy", str(self.policy_path), "--audit", str(self.audit_path),
                "--base-dir", str(self.tmp)]
        env = {**os.environ, "PYTHONPATH": str(REPO)}
        procs = []
        for n in range(6):
            event = self.event("mcp__demo__echo", {"text": str(n) * 40_000},
                               tool_use_id=f"parallel-{n}")
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, cwd=REPO, env=env)
            procs.append((proc, json.dumps(event)))
        feeders = [threading.Thread(target=proc.communicate, args=(payload,),
                                    kwargs={"timeout": 60}) for proc, payload in procs]
        for feeder in feeders:
            feeder.start()
        for feeder in feeders:
            feeder.join()
        self.assertEqual([proc.returncode for proc, _ in procs], [0] * len(procs))
        records = self.records()           # json.loads fails on a torn line
        self.assertEqual(sorted(r["correlation_id"] for r in records),
                         [f"parallel-{n}" for n in range(6)])


class TestCodex(HookTestBase):
    def codex_event(self, tool_name, tool_input, **overrides):
        return self.event(tool_name, tool_input, turn_id="turn-1", model="gpt-test",
                          **overrides)

    def test_bash_denied_with_exit_2_and_stderr_reason(self):
        self.assertDenied(self.run_hook(self.codex_event("Bash", {"command": "cat .env"}),
                                        host="codex"), "sh-paths")

    def test_bash_allowed_is_silent(self):
        self.assertSilentAllow(self.run_hook(
            self.codex_event("Bash", {"command": "wc -l normal/notes.txt"}), host="codex"))

    def test_approval_is_denied_never_asked(self):
        patch = ("*** Begin Patch\n*** Update File: canary/must-remain.txt\n@@\n"
                 "-untouched\n+pwned\n*** End Patch\n")
        self.assertDenied(self.run_hook(self.codex_event("apply_patch", {"command": patch}),
                                        host="codex"), "approval-denied")

    def test_patch_touching_a_secret_or_leaving_the_sandbox_denied(self):
        add_secret = "*** Begin Patch\n*** Add File: .env\n+X=1\n*** End Patch\n"
        self.assertDenied(self.run_hook(self.codex_event("apply_patch",
                                                         {"command": add_secret}),
                                        host="codex"), "fs-protected")
        move_out = ("*** Begin Patch\n*** Update File: normal/notes.txt\n"
                    "*** Move to: ../../outside.txt\n@@\n-benign notes\n+x\n"
                    "*** End Patch\n")
        self.assertDenied(self.run_hook(self.codex_event("apply_patch",
                                                         {"command": move_out}),
                                        host="codex"), "fs-sandbox")

    def test_patch_inside_writable_allowed_and_each_file_audited(self):
        patch = ("*** Begin Patch\n*** Add File: normal/a.txt\n+a\n"
                 "*** Update File: normal/notes.txt\n@@\n-benign notes\n+b\n"
                 "*** End Patch\n")
        self.assertSilentAllow(self.run_hook(
            self.codex_event("apply_patch", {"command": patch}), host="codex"))
        self.assertEqual([r["spelled_params"]["path"] for r in self.records()],
                         ["normal/a.txt", "normal/notes.txt"])

    def test_unparseable_or_remote_patch_denied(self):
        self.assertDenied(self.run_hook(self.codex_event("apply_patch",
                                                         {"command": "rm -rf /"}),
                                        host="codex"), "parse-error")
        remote = ("*** Begin Patch\n*** Environment ID: remote-1\n"
                  "*** Add File: normal/a.txt\n+a\n*** End Patch\n")
        self.assertDenied(self.run_hook(self.codex_event("apply_patch",
                                                         {"command": remote}),
                                        host="codex"), "hook-unsupported")

    def test_emit_allow_is_refused_for_codex(self):
        with mock.patch("sys.stdout", io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                self.run_hook(self.codex_event("Bash", {"command": "ls"}), host="codex",
                              extra_args=["--emit-allow"])
        self.assertEqual(raised.exception.code, 2)


class TestPatchPaths(unittest.TestCase):
    def test_every_header_and_both_spellings(self):
        patch = ("*** Begin Patch\n*** Add File: a.txt\n+x\n*** Delete File: b.txt\n"
                 "*** Update File: c.txt\n*** Move to: d.txt \n*** End Patch\n")
        self.assertEqual(hook.patch_paths(patch),
                         ["a.txt", "b.txt", "c.txt", "d.txt ", "d.txt"])


class TestShellSyntax(unittest.TestCase):
    def test_accepted_lines_are_plain_words(self):
        for line in ("ls", "ls -la normal", "grep -n -e 'a|b' notes.txt",
                     'grep -e "two words" notes.txt', "cat file\\ with\\ spaces",
                     "head --lines=5 notes.txt", "wc -l a b c", "grep -e 'it''s' x"):
            with self.subTest(line=line):
                self.assertIsNone(shell_syntax.problem(line))

    def test_refused_lines(self):
        for line in ("ls; id", "ls & id", "ls | id", "ls > f", "ls < f", "(ls)",
                     "ls $HOME", "ls `id`", "ls *", "ls ?", "ls [a]", "ls {a,b}",
                     "ls ~", "ls # comment", "! ls", "ls ^x", "cat =ls",
                     'ls "$HOME"', 'ls "`id`"', 'ls "\\$HOME"', "ls\nid", "ls\rid",
                     "ls \x00", "'open", '"open', "ls \\", "   "):
            with self.subTest(line=line):
                self.assertIsNotNone(shell_syntax.problem(line))


class TestShippedExamples(unittest.TestCase):
    """The settings and policy examples the docs point to stay valid."""

    def test_claude_settings_example_matches_mapped_tools(self):
        settings = json.loads((REPO / "examples/hooks/claude-code-settings.json")
                              .read_text())
        [group] = settings["hooks"]["PreToolUse"]
        matched = set(group["matcher"].split("|"))
        self.assertTrue({"Bash", "Monitor", "Read", "Write", "Edit", "MultiEdit",
                         "NotebookEdit", "WebFetch"} <= matched)
        [handler] = group["hooks"]
        self.assertEqual(handler["type"], "command")
        self.assertIn("vt-agent-firewall-hook", handler["command"])
        self.assertGreater(handler["timeout"], hook.DEFAULT_DEADLINE_SEC)

    def test_codex_config_example_matches_mapped_tools(self):
        import tomllib
        with open(REPO / "examples/hooks/codex-config.toml", "rb") as f:
            config = tomllib.load(f)
        [group] = config["hooks"]["PreToolUse"]
        self.assertEqual(group["matcher"], "^(Bash|apply_patch)$")
        [handler] = group["hooks"]
        self.assertIn("vt-agent-firewall-hook --host codex", handler["command"])
        self.assertGreater(handler["timeout"], hook.DEFAULT_DEADLINE_SEC)

    def test_example_policy_loads(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = Config(REPO / "examples/hooks/agent-firewall.json", base_dir=directory)
        self.assertEqual(cfg.network_mode, "deny_all")


if __name__ == "__main__":
    unittest.main()
