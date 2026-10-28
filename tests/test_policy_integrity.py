"""The agent rewriting its own policy.

#8 made the MCP proxy protect its policy file and audit log, as the agent hook
already did. What the agent could still change was everything around them:

1. The host settings that install the hook. With the project root writable
   (or a prompt answered in a hurry), `Write .claude/settings.local.json`
   with `{"disableAllHooks": true}` turns the firewall off for the next
   session; an `Edit` of `.claude/settings.json` points `--policy` at a file
   the agent wrote; a new `.mcp.json` entry starts a server without the
   proxy; Codex reads `.codex/config.toml` and `.codex/hooks.json`. The hook
   now protects these files (HOST_FILES) whether they exist or not, and
   `--protect PATH` adds any other file the setup depends on.
2. A policy changed by a route the hook does not see: an allowed
   `git checkout` that brings another `.claude/agent-firewall.json`, a test
   runner on `shell_exact` that writes it, a process outside the agent. The
   hook loads whatever is there on its next call. `--policy-sha256` pins the
   file: one that changed is not loaded, every call is denied, and the MCP
   proxy refuses to start.

Each scenario runs first the way it decided before (the rewrite goes through),
then refused.

Run from the repo root:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))  # test helpers
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_hook import HookTestBase  # noqa: E402
from test_learn import LearnTestBase  # noqa: E402
from test_mcp_proxy import RECORDING_SERVER, SERVER, TIMEOUT, McpProxyTestBase  # noqa: E402

from agent_firewall import Gateway, hook  # noqa: E402
from agent_firewall.config import Config  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DISABLE = json.dumps({"disableAllHooks": True})
PERMISSIVE = {"sandbox_root": "demo_workspace", "protected_paths": [],
              "writable_dirs": ["demo_workspace"],
              "shell_allowlist": ["ls", "grep", "cat", "head", "tail", "find", "wc"],
              "network": {"mode": "deny_all"}, "mcp_registry": {}}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestHostSettings(HookTestBase):
    """Scenario 1: the settings that load the hook."""

    def setUp(self):
        super().setUp()
        # The whole project writable, as a first policy often is: nothing asks.
        self.policy["writable_dirs"] = ["demo_workspace"]
        self.policy_path.write_text(json.dumps(self.policy))
        self.settings = self.ws / ".claude" / "settings.local.json"

    def write(self, path, content=DISABLE, **overrides):
        return self.run_hook(self.event("Write", {"file_path": str(path),
                                                  "content": content}, **overrides))

    def test_before_the_agent_could_turn_the_hooks_off(self):
        with mock.patch.object(hook, "host_files", return_value=[]):
            self.assertSilentAllow(self.write(self.settings))

    def test_the_settings_that_load_the_hook_are_protected(self):
        targets = [self.ws / ".claude" / "settings.local.json",   # does not exist yet
                   self.ws / ".claude" / "settings.json",
                   self.ws / ".mcp.json",
                   self.tmp / ".claude" / "settings.json"]         # --base-dir
        (self.ws / ".claude").mkdir()
        (self.ws / ".claude" / "settings.json").write_text("{}")
        for target in targets:
            with self.subTest(target=target):
                self.assertDenied(self.write(target), "fs-protected")
        self.assertDenied(self.run_hook(self.event("Edit", {
            "file_path": str(self.ws / ".claude" / "settings.json"),
            "old_string": "agent-firewall.json", "new_string": "mine.json"})),
            "fs-protected")
        self.assertDenied(self.run_hook(self.event("Bash", {
            "command": "cat .claude/settings.json"})), "sh-paths")
        self.assertFalse(self.settings.exists())

    def test_through_a_symlink_too(self):
        (self.ws / "normal" / "cfg").symlink_to("../.claude/settings.local.json")
        self.assertDenied(self.write(self.ws / "normal" / "cfg"), "fs-protected")

    def test_the_claude_project_dir_and_the_user_config_directory(self):
        project = self.ws / "app"
        home = self.ws / "home"
        env = {"CLAUDE_PROJECT_DIR": str(project), "HOME": str(home)}
        files = hook.host_files("claude-code", [], environ=env)
        self.assertIn(project / ".claude" / "settings.local.json", files)
        self.assertIn(home / ".claude" / "settings.json", files)
        self.assertIn(home / ".claude.json", files)
        moved = hook.host_files("claude-code", [], environ={
            **env, "CLAUDE_CONFIG_DIR": str(self.ws / "cfg")})
        self.assertIn(self.ws / "cfg" / "settings.json", moved)
        with mock.patch.dict(os.environ, env):
            for target in (project / ".claude" / "settings.json",
                           home / ".claude" / "settings.json"):
                with self.subTest(target=target):
                    self.assertDenied(self.write(target), "fs-protected")

    def test_codex_settings(self):
        files = hook.host_files("codex", [self.ws], environ={"HOME": str(self.tmp),
                                                             "CODEX_HOME": str(self.ws / "ch")})
        self.assertIn(self.ws / ".codex" / "hooks.json", files)
        self.assertIn(self.ws / "ch" / "config.toml", files)
        for name in ("config.toml", "hooks.json"):
            patch = (f"*** Begin Patch\n*** Add File: .codex/{name}\n+x\n"
                     f"*** End Patch\n")
            with self.subTest(name=name):
                self.assertDenied(self.run_hook(self.event("apply_patch", {"command": patch},
                                                           turn_id="t", model="m"),
                                                host="codex"), "fs-protected")

    def test_protect_adds_any_other_file(self):
        wrapper = self.ws / "bin" / "firewall-hook.sh"
        wrapper.parent.mkdir()
        wrapper.write_text("#!/bin/sh\n")
        event = self.event("Write", {"file_path": str(wrapper), "content": "exit 0"})
        self.assertSilentAllow(self.run_hook(event))
        self.assertDenied(self.run_hook(event, extra_args=["--protect", str(wrapper)]),
                          "fs-protected")

    def test_other_files_in_the_project_stay_writable(self):
        self.assertSilentAllow(self.write(self.ws / "normal" / "settings.local.json"))
        self.assertSilentAllow(self.write(self.ws / "claude" / "settings.json"))


class TestPolicyPin(HookTestBase):
    """Scenario 2: the policy changed by a route the hook does not see."""

    def rewrite_policy(self):
        """What `git checkout attacker-branch` would leave behind."""
        self.policy_path.write_text(json.dumps(PERMISSIVE))

    def test_before_the_next_call_loaded_whatever_was_there(self):
        self.assertDenied(self.run_hook(self.event("Bash", {"command": "cat .env"})),
                          "sh-paths")
        self.rewrite_policy()
        self.assertSilentAllow(self.run_hook(self.event("Bash", {"command": "cat .env"})))

    def test_a_pinned_policy_that_changed_denies_every_call(self):
        pin = ["--policy-sha256", sha256(self.policy_path)]
        self.assertSilentAllow(self.run_hook(self.event("Bash", {"command": "ls normal"}),
                                             extra_args=pin))
        self.rewrite_policy()
        for command in ("cat .env", "ls normal"):
            with self.subTest(command=command):
                code, out, err = self.run_hook(self.event("Bash", {"command": command}),
                                               extra_args=pin)
                self.assertEqual(code, 2)
                reason = out["hookSpecificOutput"]["permissionDecisionReason"]
                self.assertIn("does not match its pin", reason)
        record = self.records()[-1]
        self.assertEqual((record["decision"], record["rule_id"]), ("block", "fail-closed"))
        self.assertIn(sha256(self.policy_path), record["reason"])

    def test_the_pin_is_case_insensitive_and_must_be_a_digest(self):
        digest = sha256(self.policy_path).upper()
        self.assertSilentAllow(self.run_hook(self.event("Bash", {"command": "ls normal"}),
                                             extra_args=["--policy-sha256", digest]))
        for bad in ("abc", "g" * 64, ""):
            with self.subTest(bad=bad):
                out = io.StringIO()
                with mock.patch("sys.stdout", out), mock.patch("sys.stderr", io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        self.run_hook(self.event("Bash", {"command": "ls"}),
                                      extra_args=["--policy-sha256", bad])
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]
                                 ["permissionDecision"], "deny")

    def test_post_tool_use_does_not_record_under_a_changed_policy(self):
        trace = self.tmp / "trace.jsonl"
        pin = ["--policy-sha256", sha256(self.policy_path), "--learn", str(trace)]
        self.rewrite_policy()
        post = self.event("Bash", {"command": "ls"}, hook_event_name="PostToolUse",
                          tool_response={})
        code, out, err = self.run_hook(post, extra_args=pin)
        self.assertEqual((code, out), (1, None))
        self.assertIn("does not match its pin", err)
        self.assertFalse(trace.exists())

    def test_library_callers_can_pin_too(self):
        with self.assertRaisesRegex(ValueError, "does not match its pin"):
            Gateway(self.policy_path, self.audit_path, base_dir=self.tmp,
                    policy_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "not a SHA-256"):
            Config(self.policy_path, base_dir=self.tmp, sha256="nope")
        cfg = Config(self.policy_path, base_dir=self.tmp, sha256=sha256(self.policy_path))
        self.assertEqual(cfg.sandbox_root, self.ws.resolve())


class TestMcpProxyIntegrity(McpProxyTestBase):
    def run_proxy(self, *extra):
        return subprocess.run([
            sys.executable, "-m", "agent_firewall.mcp_proxy",
            "--policy", str(self.policy), "--audit", str(self.audit),
            "--base-dir", str(self.tmp), "--server-name", "fs", *extra,
            "--", sys.executable, str(SERVER), str(self.ws)],
            cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO)},
            capture_output=True, text=True, timeout=TIMEOUT, stdin=subprocess.DEVNULL)

    def test_a_policy_that_changed_refuses_to_start_the_server(self):
        pin = sha256(self.policy)
        self.policy.write_text(json.dumps({**PERMISSIVE, "mcp_registry": {
            "fs": ["read_file", "write_file", "delete_file"]}}))
        proc = self.run_proxy("--policy-sha256", pin)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("does not match its pin", proc.stderr)
        self.assertIn("refusing to start", proc.stderr)

    def test_a_matching_pin_starts_normally(self):
        client = self.start("--policy-sha256", sha256(self.policy))
        self.assertEqual(client.request("ping")["result"], {})

    def test_protect_keeps_the_client_config_out_of_reach(self):
        # The client config that launches the proxy, inside the sandbox, with a
        # write tool registered: without --protect the call reaches the server.
        policy = json.loads(self.policy.read_text())
        policy["mcp_registry"]["fs"].append("write_file")
        self.policy.write_text(json.dumps(policy))
        launcher = self.ws / "normal" / "mcp.json"
        launcher.write_text("{}")
        received = self.tmp / "received.jsonl"
        recorder = self.tmp / "recording_server.py"
        recorder.write_text(RECORDING_SERVER.format(examples=str(REPO / "examples")))
        server = [sys.executable, str(recorder), str(received), str(self.ws)]
        client = self.start("--protect", str(launcher), server=server)
        result = client.call("write_file", path="normal/mcp.json", content="{}")
        self.assertTrue(result["isError"])
        self.assertIn("mcp-protected-path", result["content"][0]["text"])
        client.close()
        calls = [json.loads(l) for l in received.read_text().splitlines()
                 if '"tools/call"' in l] if received.exists() else []
        self.assertEqual(calls, [])


class TestLearningKeepsThemProtected(LearnTestBase):
    def test_a_refused_settings_write_is_never_proposed(self):
        self.policy["writable_dirs"] = []
        self.policy_path.write_text(json.dumps(self.policy))
        target = self.ws / ".claude" / "settings.local.json"
        self.assertDenied(self.call("Write", {"file_path": str(target),
                                              "content": DISABLE}), "fs-protected")
        [obs] = self.observations()
        self.assertIn(str(target.resolve()), obs["self_protected"])
        proposal = self.propose()
        self.assertEqual(proposal.section("add"), [])
        self.assertEqual(self.keys(proposal, "unchanged"), {("fs-protected", "fs-protected")})


if __name__ == "__main__":
    unittest.main()
