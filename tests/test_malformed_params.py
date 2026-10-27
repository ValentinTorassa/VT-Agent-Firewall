"""Params of the wrong type are refused, never raised (issue #12).

A library caller of `Gateway` can send what no agent host would: a `url` that
is an int, `args` that is a dict, bytes anywhere. Each is a malformed request,
blocked with `parse-error` before any rule runs, and none of them may stop the
gateway: the audit still records it, and the next request is decided as usual.

Run from the repo root:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # test helpers
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_gateway import GatewayTestBase  # noqa: E402

from agent_firewall import ActionRequest  # noqa: E402
from agent_firewall.policy import PolicyEngine  # noqa: E402
from agent_firewall.session import SessionState  # noqa: E402

NOT_STRINGS = {"int": 123, "float": 1.5, "bool": True, "None": None,
               "list": ["normal/notes.txt"], "dict": {"path": "normal/notes.txt"},
               "bytes": b"normal/notes.txt"}

# A valid request per tool, and the params of it that must be strings.
VALID = {
    "fs.read": ({"path": "normal/notes.txt", "cwd": "."}, ("path", "cwd")),
    "fs.write": ({"path": "normal/out.txt", "content": "x", "cwd": "."},
                 ("path", "content", "cwd")),
    "shell.run": ({"command": "ls", "args": ["normal"], "cwd": "."},
                  ("command", "cwd")),
    "net.request": ({"url": "https://example.com/", "method": "GET", "body": "x"},
                    ("url", "method", "body")),
    "mcp.call": ({"server": "demo", "tool": "ping", "arguments": {}},
                 ("server", "tool")),
    "mcp.resource": ({"server": "demo", "uri": "file:///x"}, ("server", "uri")),
    "api.call": ({"audience": "a", "operation": "b", "arguments": {}},
                 ("audience", "operation")),
}


class MalformedBase(GatewayTestBase):
    def assertParseError(self, record, msg=None):
        self.assertEqual((record["decision"], record["rule_id"]),
                         ("block", "parse-error"), msg or record["reason"])
        self.assertEqual(record["outcome"], "not_executed")

    def assertStillWorks(self):
        r = self.gw.handle(self.req("fs.read", path="normal/notes.txt"))
        self.assertEqual((r["decision"], r["rule_id"], r["outcome"]),
                         ("allow", "fs-read-ok", "executed"))


class TestEveryToolChecksItsParams(MalformedBase):
    def test_a_string_param_of_another_type_is_a_parse_error(self):
        for tool, (valid, keys) in VALID.items():
            for key in keys:
                for name, value in NOT_STRINGS.items():
                    with self.subTest(tool=tool, key=key, type=name):
                        self.assertParseError(self.gw.handle(
                            self.req(tool, {**valid, key: value})))
        self.assertStillWorks()

    def test_the_issue_cases(self):
        for url in (None, 123, ["https://x"], {"u": 1}, b"https://x"):
            with self.subTest(url=url):
                self.assertParseError(self.gw.handle(self.req("net.request", url=url)))

    def test_shell_command_line_must_be_a_string(self):
        for value in (123, ["ls"], {"ls": 1}, b"ls", None):
            with self.subTest(value=value):
                self.assertParseError(self.gw.handle(
                    self.req("shell.run", command_line=value, via_shell=True)))

    def test_shell_args_must_be_a_list_of_words(self):
        for args in ({"normal": 1}, "normal", [["normal"]], [None], [True],
                     [b"normal"], [{"a": 1}], [1.5]):
            with self.subTest(args=args):
                self.assertParseError(self.gw.handle(
                    self.req("shell.run", command="ls", args=args)))

    def test_numbers_in_args_are_written_as_spelled(self):
        r = self.gw.handle(self.req("shell.run", command="head",
                                    args=["-n", 1, "normal/notes.txt"]))
        self.assertEqual((r["decision"], r["rule_id"]), ("allow", "sh-ok"))
        self.assertEqual(r["normalized"]["args"], ["-n", "1", "normal/notes.txt"])

    def test_via_shell_must_be_a_boolean(self):
        # A truthy string must not read as "checked", nor 0 as "not via a shell".
        for value in ("false", "yes", 0, 1, None, []):
            with self.subTest(value=value):
                self.assertParseError(self.gw.handle(
                    self.req("shell.run", command_line="ls", via_shell=value)))

    def test_params_must_be_an_object(self):
        for params in (None, [], "path", 5):
            with self.subTest(params=params):
                self.assertParseError(self.gw.handle(
                    ActionRequest(actor="test", tool="fs.read", params=params)))

    def test_missing_required_params_are_still_a_parse_error(self):
        for tool in VALID:
            with self.subTest(tool=tool):
                self.assertParseError(self.gw.handle(self.req(tool, {})))


class TestTheGatewayKeepsWorking(MalformedBase):
    def test_bytes_are_audited_by_type_not_content(self):
        r = self.gw.handle(self.req("fs.write", path="normal/out.txt",
                                    content=b"synthetic-secret"))
        self.assertParseError(r)
        [record] = self.records()
        self.assertEqual(record["spelled_params"]["content"],
                         {"unserializable": "bytes", "bytes": 16})
        self.assertNotIn("synthetic-secret", self.audit_path.read_text())
        self.assertFalse((self.ws / "normal" / "out.txt").exists())
        self.assertStillWorks()

    def test_a_key_that_is_not_a_string(self):
        self.assertParseError(self.gw.handle(self.req("mcp.call", {
            "server": "demo", "tool": "echo", "arguments": {1: "x", "text": b"y"}})))
        self.assertStillWorks()
        keys = self.records()[0]["spelled_params"]["arguments"]
        self.assertEqual(set(keys), {"<int> 1", "text"})

    def test_a_cycle_in_the_params(self):
        arguments = {"text": "x"}
        arguments["self"] = arguments
        r = self.gw.handle(self.req("mcp.call", server="demo", tool="echo",
                                    arguments=arguments))
        self.assertParseError(r)
        self.assertStillWorks()

    def test_nesting_too_deep_to_walk(self):
        nested = "x"
        for _ in range(sys.getrecursionlimit() + 100):
            nested = {"a": nested}
        r = self.gw.handle(self.req("mcp.call", server="demo", tool="echo",
                                    arguments={"text": nested}))
        self.assertParseError(r)
        self.assertStillWorks()
        self.assertEqual(len(self.records()), 3)  # the refusal + intent/executed

    def test_evaluate_never_raises(self):
        engine = PolicyEngine(self.gw.config)
        for tool, (valid, keys) in VALID.items():
            for key in keys:
                for value in NOT_STRINGS.values():
                    d = engine.evaluate(ActionRequest(
                        actor="test", tool=tool, params={**valid, key: value}),
                        SessionState())
                    self.assertEqual(d.rule_id, "parse-error")


if __name__ == "__main__":
    unittest.main()
