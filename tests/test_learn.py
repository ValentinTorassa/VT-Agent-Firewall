"""Learning mode (agent_firewall/learn.py): recording, ask mode, proposals, CLI.

The hook records observations with `--learn TRACE`; `vt-agent-firewall-propose`
turns them into a proposed policy. These tests hold the promises the docs make:
enforce mode answers exactly as without --learn, ask mode never relaxes more
than the allowlist and the MCP registry, the proposal never grants anything
risky and never relaxes a safety rule, and nothing is ever written over the
policy.

Run from the repo root:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))  # test helpers
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_hook import HookTestBase  # noqa: E402

from agent_firewall import ActionRequest, Decision, Gateway, hook, learn  # noqa: E402
from scripts import run_learning_demo  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SAFETY_KEYS = ("sandbox_root", "protected_paths", "shell_forbidden_args", "network",
               "mcp_registry")


class LearnTestBase(HookTestBase):
    def setUp(self):
        super().setUp()
        self.trace = self.tmp / "state" / "trace.jsonl"

    def learn(self, payload, mode="enforce", extra_args=(), policy=None):
        return self.run_hook(payload, policy=policy, extra_args=[
            "--learn", str(self.trace), "--learn-mode", mode, *extra_args])

    def call(self, tool, tool_input, session="s1", mode="enforce", **overrides):
        return self.learn(self.event(tool, tool_input, session_id=session, **overrides),
                          mode=mode)

    def observations(self):
        if not self.trace.exists():
            return []
        return [json.loads(line) for line in self.trace.read_text().splitlines() if line]

    def propose(self, policy=None, **kwargs):
        return learn.propose(policy or self.policy_path, [self.trace],
                             base_dir=self.tmp, **kwargs)

    def keys(self, proposal, section):
        return {(g.policy_key, g.key) for g in proposal.section(section)}


class TestRecording(LearnTestBase):
    EVENTS = [
        ("Bash", {"command": "ls normal"}),
        ("Bash", {"command": "cat .env"}),
        ("Write", {"file_path": "canary/must-remain.txt", "content": "x"}),
        ("Bash", {"command": "python3 x.py"}),
        ("WebFetch", {"url": "https://example.com/", "prompt": "x"}),
    ]

    def test_enforce_mode_answers_exactly_as_without_learn(self):
        for tool, tool_input in self.EVENTS:
            if "file_path" in tool_input:
                tool_input = {**tool_input,
                              "file_path": str(self.ws / tool_input["file_path"])}
            with self.subTest(tool=tool, tool_input=tool_input):
                event = self.event(tool, tool_input)
                self.assertEqual(self.run_hook(event), self.learn(event))

    def test_one_observation_per_decision_with_provenance(self):
        self.call("Bash", {"command": "ls normal"})
        self.call("Bash", {"command": "cat .env"})
        self.call("Write", {"file_path": str(self.ws / "canary" / "x.txt"), "content": "x"})
        audit = self.records()
        observations = self.observations()
        self.assertEqual(len(observations), 3)
        for record, obs in zip(audit, observations):
            self.assertEqual((obs["decision"], obs["rule_id"], obs["tool"],
                              obs["normalized"], obs["correlation_id"]),
                             (record["decision"], record["rule_id"], record["tool"],
                              record["normalized"], record["correlation_id"]))
            self.assertEqual((obs["v"], obs["mode"], obs["host"], obs["session_id"]),
                             (1, "enforce", "claude-code", "s1"))
            self.assertEqual(obs["sandbox_root"], str(self.ws.resolve()))
            self.assertEqual(len(obs["policy_sha256"]), 64)
            self.assertIn(str(self.trace.resolve()), obs["self_protected"])
        self.assertEqual([o["tainted"] for o in observations], [False, True, False])

    def test_written_content_is_kept_as_a_digest(self):
        self.call("Write", {"file_path": str(self.ws / "normal" / "out.txt"),
                            "content": "synthetic secret body"})
        self.assertNotIn("synthetic secret body", self.trace.read_text())
        [obs] = self.observations()
        self.assertEqual(obs["normalized"]["content"]["bytes"], 21)

    def test_codex_patch_and_malformed_input_are_observed(self):
        patch = ("*** Begin Patch\n*** Add File: normal/a.txt\n+a\n"
                 "*** Add File: normal/b.txt\n+b\n*** End Patch\n")
        out = io.StringIO()
        code = hook.main(["--policy", str(self.policy_path),
                          "--audit", str(self.audit_path),
                          "--base-dir", str(self.tmp), "--host", "codex",
                          "--learn", str(self.trace)],
                         stdin=io.BytesIO(json.dumps(self.event(
                             "apply_patch", {"command": patch})).encode()),
                         stdout=out, stderr=io.StringIO())
        self.assertEqual(code, 0)
        self.learn(b"not json")
        observations = self.observations()
        self.assertEqual([o["normalized"].get("spelled") for o in observations[:2]],
                         ["normal/a.txt", "normal/b.txt"])
        self.assertEqual((observations[2]["rule_id"], observations[2]["decision"]),
                         ("parse-error", "block"))

    def test_the_trace_is_protected_from_the_agent(self):
        # Kept inside the sandbox on purpose: an agent that could rewrite its own
        # trace could get itself allowlisted.
        self.trace = self.ws / "normal" / "trace.jsonl"
        self.call("Bash", {"command": "ls normal"})
        self.assertDenied(self.call("Read", {"file_path": str(self.trace)}), "fs-protected")
        self.assertDenied(self.call("Write", {"file_path": str(self.trace),
                                              "content": "{}"}), "fs-protected")
        self.assertDenied(self.call("Bash", {"command": "cat normal/trace.jsonl"}),
                          "sh-paths")

    def test_an_unavailable_trace_denies_even_an_allowed_call(self):
        self.trace.mkdir(parents=True)        # a directory cannot be appended to
        self.assertDenied(self.call("Bash", {"command": "ls normal"}), "fail-closed")
        [record] = self.records()
        self.assertIn("learning trace", record["reason"])

    def test_learn_mode_arguments(self):
        for extra in (["--learn-mode", "ask"],                       # no --learn
                      ["--learn", str(self.trace), "--learn-mode", "ask",
                       "--host", "codex"]):
            with self.subTest(extra=extra):
                out = io.StringIO()
                with mock.patch("sys.stdout", out), mock.patch("sys.stderr", io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        hook.main(["--policy", str(self.policy_path),
                                   "--audit", str(self.audit_path), *extra],
                                  stdin=io.BytesIO(b"{}"))
                self.assertEqual(raised.exception.code, 2)
                self.assertIn('"deny"', out.getvalue())


class TestAskMode(LearnTestBase):
    def test_an_allowlist_refusal_is_asked_and_audited_truthfully(self):
        code, out, _ = self.call("Bash", {"command": "python3 tools/check.py"}, mode="ask")
        self.assertEqual(code, 0)
        decision = out["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "ask")
        self.assertIn("LEARNING MODE", decision["permissionDecisionReason"])
        self.assertIn("runs code", decision["permissionDecisionReason"])
        [record] = self.records()
        # The host may run it after a yes, so the audit must not say "blocked".
        self.assertEqual((record["decision"], record["rule_id"], record["outcome"]),
                         ("require_approval", "learn-ask", "delegated"))
        self.assertEqual(record["rules_matched"], ["sh-allowlist", "learn-ask"])
        [obs] = self.observations()
        self.assertEqual((obs["mode"], obs["rule_id"]), ("ask", "learn-ask"))

    def test_an_unregistered_mcp_tool_is_asked_but_its_paths_still_checked(self):
        code, out, _ = self.call("mcp__demo__summarize", {"text": "x"}, mode="ask")
        self.assertEqual((code, out["hookSpecificOutput"]["permissionDecision"]),
                         (0, "ask"))
        self.assertDenied(self.call("mcp__evil__read", {"path": "../.env"}, session="s2",
                                    mode="ask"), "mcp-unknown-tool")

    def test_every_other_refusal_stays_a_denial(self):
        cases = [
            ("Read", {"file_path": str(self.ws / ".env")}, "fs-protected"),
            ("Write", {"file_path": str(self.tmp / "out.txt"), "content": "x"},
             "fs-sandbox"),
            ("Bash", {"command": "base64 .env"}, "sh-allowlist"),         # names a secret
            ("Bash", {"command": "python3 ../../outside.py"}, "sh-allowlist"),  # escapes
            ("Bash", {"command": "cat normal/notes.txt | wc -l"}, "sh-syntax"),
            ("Bash", {"command": "find normal -delete"}, "sh-args"),
            ("Bash", {"command": "grep -r KEY ."}, "sh-recursive"),
            ("WebFetch", {"url": "https://example.com/", "prompt": "x"}, "net-deny-all"),
            ("WebSearch", {"query": "x"}, "unknown-tool"),
        ]
        for number, (tool, tool_input, rule) in enumerate(cases):
            with self.subTest(tool=tool, tool_input=tool_input):
                # A fresh session each time: taint must not be what denies here.
                self.assertDenied(self.call(tool, tool_input, session=f"fresh-{number}",
                                            mode="ask"), rule)

    def test_asking_stops_once_the_session_went_for_a_secret(self):
        self.assertDenied(self.call("Read", {"file_path": str(self.ws / ".env")},
                                    session="hijacked", mode="ask"), "fs-protected")
        self.assertDenied(self.call("Bash", {"command": "python3 x.py"},
                                    session="hijacked", mode="ask"), "sh-allowlist")
        code, out, _ = self.call("Bash", {"command": "python3 x.py"}, session="other",
                                 mode="ask")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_bypass_permissions_mode_denies_instead_of_asking(self):
        self.assertDenied(self.call("Bash", {"command": "python3 x.py"}, mode="ask",
                                    permission_mode="bypassPermissions"),
                          "approval-denied")

    def test_relax_can_never_produce_an_allow(self):
        gateway = Gateway(self.policy_path, self.audit_path, base_dir=self.tmp)
        self.addCleanup(gateway.audit.close)

        def allow_everything(decision):
            decision.decision = Decision.ALLOW
            return decision

        req = ActionRequest(actor="t", tool="shell.run",
                            params={"command_line": "curl http://x", "cwd": str(self.ws)})
        with self.assertRaises(ValueError):
            gateway.decide(req, relax=allow_everything)


class TestProposal(LearnTestBase):
    def test_writes_generalize_to_the_first_directory_under_the_sandbox(self):
        for path in ("reports/2026/a.md", "reports/b.md", "TODO.md",
                     ".github/workflows/ci.yml"):
            self.call("Write", {"file_path": str(self.ws / path), "content": "x"})
        self.call("Write", {"file_path": str(self.ws / "normal" / "ok.md"), "content": "x"})
        proposal = self.propose()
        self.assertEqual(self.keys(proposal, "add"),
                         {("writable_dirs", "demo_workspace/reports")})
        [grant] = proposal.section("add")
        self.assertEqual((grant.seen, len(grant.sessions)), (2, 1))
        self.assertEqual(self.keys(proposal, "decide"),
                         {("writable_dirs", "demo_workspace/TODO.md"),
                          ("writable_dirs", "demo_workspace/.github/workflows/ci.yml")})
        self.assertEqual(proposal.policy["writable_dirs"],
                         ["demo_workspace/normal", "demo_workspace/reports"])
        self.assertEqual(proposal.before, {"allow": 1, "require_approval": 4})
        self.assertEqual(proposal.after, {"allow": 3, "require_approval": 2})

    def test_risky_binaries_are_never_proposed(self):
        commands = ["python3 tools/check.py", "node x.js", "sh -c ls", "bash x.sh",
                    "curl https://example.com", "wget https://example.com",
                    "rm normal/notes.txt", "mv normal/notes.txt normal/n.txt",
                    "sed -i s/a/b/ normal/notes.txt", "git status", "git push",
                    "sort normal/notes.txt", "env", "printenv", "npm test", "make",
                    "tee normal/x", "chmod 777 normal", "xargs", "awk 1 normal/notes.txt"]
        for command in commands:
            self.call("Bash", {"command": command})
        proposal = self.propose()
        self.assertEqual(proposal.policy["shell_allowlist"], self.policy["shell_allowlist"])
        self.assertEqual(proposal.section("add"), [])
        decide = {g.key: g.why for g in proposal.section("decide")}
        self.assertEqual(set(decide), {c.split()[0] for c in commands})
        self.assertIn("runs code", decide["python3"])
        self.assertIn("network", decide["curl"])
        self.assertIn("writes or deletes files", decide["rm"])
        self.assertIn("reads secrets", decide["printenv"])
        self.assertTrue(all("no argument grammar" in why for why in decide.values()))

    def test_a_binary_with_a_grammar_is_proposed_when_nothing_else_refuses_it(self):
        narrow = {**self.policy, "shell_allowlist": ["ls", "cat"]}
        policy = self.tmp / "narrow.json"
        policy.write_text(json.dumps(narrow))
        self.learn(self.event("Bash", {"command": "head -n 5 normal/notes.txt"}),
                   policy=policy)
        self.learn(self.event("Bash", {"command": "grep -r KEY ."}), policy=policy)
        proposal = self.propose(policy=policy)
        self.assertEqual(self.keys(proposal, "add"), {("shell_allowlist", "head")})
        self.assertEqual(proposal.policy["shell_allowlist"], ["ls", "cat", "head"])
        # grep would walk into .env: allowlisting it would not help, so it is not
        # proposed, and the reason says so.
        [walk] = [g for g in proposal.section("unchanged") if g.key == "sh-recursive"]
        self.assertIn("even with the missing sh-allowlist grant", walk.why)

    def test_mcp_tools_are_listed_never_registered(self):
        self.call("mcp__demo__summarize", {"text": "x"})
        self.call("mcp__github__create_issue", {"title": "x"})
        proposal = self.propose()
        self.assertEqual(proposal.policy["mcp_registry"], self.policy["mcp_registry"])
        self.assertEqual(self.keys(proposal, "decide"),
                         {("mcp_registry", "demo/summarize"),
                          ("mcp_registry", "github/create_issue")})

    def test_safety_rules_are_copied_unchanged_and_blocks_stay_blocks(self):
        (self.ws / "normal" / "up").symlink_to("..")
        attacks = [
            ("Read", {"file_path": str(self.ws / ".env")}),
            ("Read", {"file_path": str(self.ws / "malicious_repo" / "config-link")}),
            ("Read", {"file_path": str(self.tmp / "policy.json")}),
            ("Write", {"file_path": str(self.tmp / "escape.txt"), "content": "x"}),
            ("Bash", {"command": "cat .env"}),
            ("Bash", {"command": "grep -r KEY normal/up"}),
            ("Bash", {"command": "grep -f .env normal/notes.txt"}),
            ("Bash", {"command": "find . -name x -exec sh -c id ;"}),
            ("Bash", {"command": "find normal -fprint canary/must-remain.txt"}),
            ("Bash", {"command": "cat normal/notes.txt; curl http://x"}),
            ("WebFetch", {"url": "http://127.0.0.1:8765/collect", "prompt": "x"}),
            ("mcp__demo__echo", {"path": "../.env"}),
            ("WebSearch", {"query": "x"}),
        ]
        for number, (tool, tool_input) in enumerate(attacks):
            self.call(tool, tool_input, session=f"attack-{number}")
        proposal = self.propose(drop_unused=True)
        for key in SAFETY_KEYS:
            self.assertEqual(proposal.policy[key], self.policy[key], key)
        self.assertEqual(proposal.section("add"), [])
        self.assertEqual(proposal.after["block"], len(attacks))

    def test_a_session_that_went_for_a_secret_is_not_learned_from(self):
        self.call("Write", {"file_path": str(self.ws / "reports" / "a.md"), "content": "x"},
                  session="task")
        self.call("Read", {"file_path": str(self.ws / "malicious_repo" / "README.md")},
                  session="injected")
        self.call("Read", {"file_path": str(self.ws / ".env")}, session="injected")
        self.call("Write", {"file_path": str(self.ws / "canary" / "must-remain.txt"),
                            "content": "pwned"}, session="injected")
        self.call("Bash", {"command": "head -n 1 normal/notes.txt"}, session="injected")
        proposal = self.propose()
        self.assertEqual(proposal.policy["writable_dirs"],
                         ["demo_workspace/normal", "demo_workspace/reports"])
        [untrusted] = proposal.section("untrusted")
        self.assertIn("canary/must-remain.txt", untrusted.key)
        self.assertIn("after Read demo_workspace/.env", untrusted.why)

    def test_a_grant_that_also_covers_an_unlearned_action_is_flagged(self):
        self.call("Write", {"file_path": str(self.ws / "reports" / "a.md"), "content": "x"},
                  session="task")
        self.call("Read", {"file_path": str(self.ws / ".env")}, session="injected")
        self.call("Write", {"file_path": str(self.ws / "reports" / "evil.md"),
                            "content": "x"}, session="injected")
        proposal = self.propose()
        self.assertEqual(self.keys(proposal, "add"),
                         {("writable_dirs", "demo_workspace/reports")})
        [note] = proposal.notes
        self.assertIn("would also allow 1 action(s) that were not learned from", note)
        self.assertIn("reports/evil.md", note)

    def test_the_hooks_own_files_stay_protected_on_replay(self):
        # The hook protected the trace at run time; replaying without that
        # would turn the attempt into a writable-directory proposal.
        self.trace = self.ws / "firewall" / "trace.jsonl"
        self.assertDenied(self.call("Write", {"file_path": str(self.trace),
                                              "content": "{}"}), "fs-protected")
        proposal = self.propose()
        self.assertEqual(proposal.section("add"), [])
        self.assertEqual(self.keys(proposal, "unchanged"),
                         {("fs-protected", "fs-protected")})

    def test_a_refusal_at_approval_is_never_learned(self):
        self.call("Write", {"file_path": str(self.ws / "canary" / "x.txt"), "content": "x"},
                  permission_mode="bypassPermissions")
        proposal = self.propose()
        self.assertEqual(proposal.section("add"), [])
        self.assertEqual(self.keys(proposal, "unchanged"),
                         {("approval-denied", "approval-denied")})

    def test_unused_grants_are_reported_and_dropped_only_on_request(self):
        self.call("Bash", {"command": "ls normal"})
        kept = self.propose()
        self.assertEqual(kept.policy["shell_allowlist"], self.policy["shell_allowlist"])
        self.assertEqual({g.key for g in kept.section("unused")},
                         {"grep", "cat", "head", "tail", "find", "wc",
                          "demo_workspace/normal"})
        dropped = self.propose(drop_unused=True)
        self.assertEqual(dropped.policy["shell_allowlist"], ["ls"])
        self.assertEqual(dropped.policy["writable_dirs"], [])
        self.assertEqual(dropped.policy["protected_paths"], self.policy["protected_paths"])

    def test_ask_mode_traces_give_the_same_proposal(self):
        self.call("Bash", {"command": "python3 x.py"}, mode="ask")
        self.call("Write", {"file_path": str(self.ws / "reports" / "a.md"), "content": "x"},
                  mode="ask")
        proposal = self.propose()
        self.assertEqual(self.keys(proposal, "decide"), {("shell_allowlist", "python3")})
        self.assertEqual(self.keys(proposal, "add"),
                         {("writable_dirs", "demo_workspace/reports")})
        self.assertEqual(proposal.notes, [])

    def test_unusable_traces_are_refused(self):
        self.call("Bash", {"command": "ls normal"})
        good = self.trace.read_text()
        cases = {
            "not json": "{nope\n",
            "other version": json.dumps({**json.loads(good), "v": 2}) + "\n",
            "missing tool": json.dumps({**json.loads(good), "tool": None}) + "\n",
            "other sandbox": json.dumps({**json.loads(good),
                                         "sandbox_root": "/elsewhere"}) + "\n",
            "empty": "",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                self.trace.write_text(text)
                with self.assertRaises(learn.TraceError):
                    self.propose()


class TestCorpus(unittest.TestCase):
    """Learning from any case of the attack corpus grants nothing."""

    def test_no_attack_in_the_corpus_turns_into_a_grant(self):
        data = json.loads((REPO / "corpus/attacks.json").read_text())
        for case in data["cases"]:
            with self.subTest(case=case["id"]), \
                    tempfile.TemporaryDirectory(prefix="vt-learn-corpus-") as directory:
                temp = Path(directory)
                shutil.copytree(REPO / "demo_workspace", temp / "demo_workspace",
                                symlinks=True)
                for link, target in case.get("setup", {}).get("symlinks", []):
                    (temp / "demo_workspace" / link).symlink_to(target)
                policy = json.loads((REPO / "policies/default.json").read_text())
                policy["protected_paths"] += case.get("policy", {}).get(
                    "protected_paths_add", [])
                policy_path = temp / "policy.json"
                policy_path.write_text(json.dumps(policy))
                gateway = Gateway(policy_path, temp / "audit.jsonl", base_dir=temp)
                trace = learn.TraceWriter(temp / "trace.jsonl", "enforce", gateway.config,
                                          policy_path)
                try:
                    for step in case["steps"]:
                        record = gateway.decide(
                            ActionRequest(actor="corpus", tool=step["tool"],
                                          params=step["params"]),
                            approval="deny", approval_note="corpus", session_id=case["id"])
                        trace.observe(record, tainted=gateway.session.tainted)
                finally:
                    trace.close()
                    gateway.audit.close()
                proposal = learn.propose(policy_path, [temp / "trace.jsonl"],
                                         base_dir=temp)
                self.assertEqual(proposal.policy, policy)
                self.assertEqual(proposal.section("add"), [])
                self.assertEqual(proposal.after, proposal.before)


class TestCli(LearnTestBase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        code = learn.main([*args], stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_writes_the_proposal_and_explains_each_rule(self):
        self.call("Write", {"file_path": str(self.ws / "reports" / "a.md"), "content": "x"})
        self.call("Bash", {"command": "python3 x.py"})
        out = self.tmp / "proposed.json"
        code, report, err = self.run_cli("--policy", str(self.policy_path), "--base-dir",
                                         str(self.tmp), "--out", str(out), str(self.trace))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out.read_text())["writable_dirs"],
                         ["demo_workspace/normal", "demo_workspace/reports"])
        self.assertIn("Nothing has been applied", report)
        self.assertRegex(report, r"\+ writable_dirs +demo_workspace/reports +1 time, "
                                 r"1 session")
        self.assertRegex(report, r"shell_allowlist +python3 +1 time")
        self.assertIn("Replayed against the proposal: allow 0 -> 1", report)

    def test_never_writes_over_the_policy(self):
        self.call("Write", {"file_path": str(self.ws / "reports" / "a.md"), "content": "x"})
        original = self.policy_path.read_text()
        link = self.tmp / "link.json"
        link.symlink_to(self.policy_path)
        for target in (self.policy_path, link):
            with self.subTest(out=target):
                code, _, err = self.run_cli("--policy", str(self.policy_path),
                                            "--base-dir", str(self.tmp),
                                            "--out", str(target), str(self.trace))
                self.assertEqual(code, 1)
                self.assertIn("is the policy itself", err)
        self.assertEqual(self.policy_path.read_text(), original)

    def test_errors_exit_1_without_writing(self):
        self.call("Bash", {"command": "ls normal"})
        out = self.tmp / "proposed.json"
        code, _, err = self.run_cli("--policy", str(self.policy_path),   # no --base-dir
                                    "--out", str(out), str(self.trace))
        self.assertEqual(code, 1)
        self.assertIn("--base-dir", err)
        self.assertFalse(out.exists())
        code, _, err = self.run_cli("--policy", str(self.policy_path), "--base-dir",
                                    str(self.tmp), str(self.tmp / "missing.jsonl"))
        self.assertEqual((code, "cannot read trace" in err), (1, True))

    def test_console_script_is_registered(self):
        with open(REPO / "pyproject.toml", "rb") as f:
            scripts = tomllib.load(f)["project"]["scripts"]
        self.assertEqual(scripts["vt-agent-firewall-propose"], "agent_firewall.learn:main")

    def test_learning_demo_script(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            code = run_learning_demo.main(["--out-dir", str(self.tmp / "demo")])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertRegex(text, r"\+ writable_dirs +demo_workspace/reports")
        self.assertIn("after Read demo_workspace/.env", text)
        proposed = json.loads((self.tmp / "demo" / "proposed-policy.json").read_text())
        default = json.loads((REPO / "policies/default.json").read_text())
        self.assertEqual(proposed["shell_allowlist"], default["shell_allowlist"])
        self.assertEqual(proposed["writable_dirs"],
                         default["writable_dirs"] + ["demo_workspace/reports"])
        for key in SAFETY_KEYS:
            self.assertEqual(proposed[key], default[key], key)


if __name__ == "__main__":
    unittest.main()
