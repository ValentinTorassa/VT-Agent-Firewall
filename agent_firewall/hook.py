"""Agent hook: the gateway's policy in front of an agent host's own tools.

The MCP proxy only sees MCP tools. Claude Code's built-in tools (Bash, Read,
Write, Edit, ...) and Codex's shell and `apply_patch` never pass through it, and
they are where an agent reads secrets and runs commands. Both hosts run a
`PreToolUse` hook before each tool call: a command that receives the call as
JSON on stdin and answers. This module is that command.

    vt-agent-firewall-hook --policy policy.json --audit audit.jsonl [--host codex]

Each call becomes one or more ActionRequests, evaluated by the same
PolicyEngine and written to the same audit log before the host runs anything:

    Bash, Monitor(command)        shell.run, marked via_shell (the host uses a shell)
    Read                          fs.read
    Write, Edit, MultiEdit,       fs.write
    NotebookEdit
    WebFetch, Monitor(ws)         net.request
    mcp__<server>__<tool>         mcp.call (the policy's mcp_registry)
    apply_patch (Codex)           fs.write, once per file the patch touches
    anything else                 unknown tool: default-deny

The hook never runs the tool; the host does. `allow` stays silent by default, so
the host's own permission rules and prompts still apply: the hook only narrows.
`require_approval` becomes Claude Code's `ask` prompt. Codex cannot ask from a
hook (it ignores `ask` and runs the tool), so there it is denied.

Learning mode (`--learn TRACE`, agent_firewall/learn.py) also appends one
observation per request to TRACE for `vt-agent-firewall-propose`. The policy is
still enforced; `--learn-mode ask` (Claude Code only) asks instead of denying a
call refused only by the shell allowlist or the MCP registry. Registered for
`PostToolUse` as well, the same command appends a `ran` record for each tool
call the host ran, so the proposal can tell an ask you approved from one you
refused. That event comes after the fact: the hook never answers it (no JSON,
never exit 2) and only records; without --learn it does nothing.

Fail-closed: unparseable input, a tool it cannot map, an unreadable policy, an
unavailable audit log or learning trace, an internal error or the hook's own
deadline all deny.
A denial is given both ways the hosts understand: JSON on stdout and exit code
2 with the reason on stderr. Any other non-zero exit would let the tool run,
so every error path ends in that same denial.

PostToolUse has nothing left to deny. A `ran` record that cannot be written is
missing, and the proposal treats an ask without one as refused: the evidence
fails closed. The hook then exits 1, which the host shows the user as a hook
error without telling the model anything.

Protocols: https://code.claude.com/docs/en/hooks (PreToolUse, PostToolUse) and
https://developers.openai.com/codex/hooks (PreToolUse).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import learn
from .audit import AuditLogger, AuditUnavailable
from .config import Config
from .gateway import Gateway
from .models import ActionRequest
from .session import TaintStore, TaintUnavailable

HOSTS = ("claude-code", "codex")
MAX_INPUT_BYTES = 64 * 1024 * 1024
DEFAULT_DEADLINE_SEC = 20.0
REASON_MAX_CHARS = 2000

# Codex apply_patch file headers (codex-rs/apply-patch/src/parser.rs).
PATCH_FILE_MARKERS = ("*** Add File:", "*** Delete File:", "*** Update File:",
                      "*** Move to:")
PATCH_ENVIRONMENT_MARKER = "*** Environment ID:"


class Refusal(Exception):
    """The hook input cannot be translated into an ActionRequest."""

    def __init__(self, reason: str, rule_id: str = "parse-error"):
        super().__init__(reason)
        self.rule_id = rule_id
        self.reason = reason


class DeadlineExceeded(BaseException):
    """BaseException so no `except Exception` on the way can swallow it."""


@dataclass
class Verdict:
    decision: str        # allow | ask | deny; PostToolUse: recorded | error
    reason: str


class NoApprover:
    """The hook never prompts on its own: approval is the host's prompt."""

    def approve(self, decision) -> bool:
        return False


# -- translation: host tool call -> ActionRequests --------------------------------

def translate(event: dict, host: str) -> list[ActionRequest]:
    tool = event.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise Refusal("hook input has no tool_name")
    cwd = event.get("cwd")
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        raise Refusal("hook input has no absolute cwd")
    tool_input = event.get("tool_input")
    correlation = event.get("tool_use_id")
    if not isinstance(correlation, str) or not correlation:
        correlation = uuid.uuid4().hex[:12]

    def request(surface: str, **params) -> ActionRequest:
        return ActionRequest(actor=host, tool=surface, params=params,
                             correlation_id=correlation)

    if tool.startswith("mcp__"):
        server, sep, name = tool[len("mcp__"):].partition("__")
        if not (server and sep and name):
            raise Refusal(f"cannot split MCP tool name {tool!r} into server and tool")
        return [request("mcp.call", server=server, tool=name,
                        arguments=_object(tool, tool_input))]

    args = _object(tool, tool_input)
    if tool == "Bash" or (host == "claude-code" and tool == "Monitor"
                          and "ws" not in args):
        return [request("shell.run", command_line=_string(tool, args, "command"),
                        cwd=cwd, via_shell=True)]
    if host == "codex" and tool == "apply_patch":
        patch = _string(tool, args, "command")
        return [request("fs.write", path=path, content=patch, cwd=cwd)
                for path in patch_paths(patch)]
    if host == "claude-code":
        if tool == "Read":
            return [request("fs.read", path=_string(tool, args, "file_path"), cwd=cwd)]
        if tool == "Write":
            return [request("fs.write", path=_string(tool, args, "file_path"),
                            content=_string(tool, args, "content"), cwd=cwd)]
        if tool == "Edit":
            return [request("fs.write", path=_string(tool, args, "file_path"),
                            content=_string(tool, args, "new_string"), cwd=cwd)]
        if tool == "MultiEdit":   # legacy tool: one file, several edits
            edits = args.get("edits")
            if not isinstance(edits, list):
                raise Refusal("MultiEdit: tool_input.edits must be a list")
            return [request("fs.write", path=_string(tool, args, "file_path"),
                            content=json.dumps(edits, sort_keys=True), cwd=cwd)]
        if tool == "NotebookEdit":
            source = args.get("new_source", "")
            if not isinstance(source, str):
                raise Refusal("NotebookEdit: tool_input.new_source must be a string")
            return [request("fs.write", path=_string(tool, args, "notebook_path"),
                            content=source, cwd=cwd)]
        if tool == "WebFetch":
            return [request("net.request", url=_string(tool, args, "url"),
                            method="GET")]
        if tool == "Monitor":
            ws = args.get("ws")
            if not isinstance(ws, dict):
                raise Refusal("Monitor: tool_input.ws must be an object")
            return [request("net.request", url=_string(tool, ws, "url"),
                            method="GET")]
    # No mapping: the policy answers `unknown-tool` (default-deny). The host
    # prefix keeps host tool names out of the gateway's own tool namespace.
    return [request(f"{host}:{tool}")]


def patch_paths(patch: str) -> list[str]:
    """Every file a Codex patch may create, change, delete or move to.

    Over-inclusive on purpose: any line that looks like a file header after
    trimming counts, and a name with surrounding spaces is checked both as
    written and trimmed, so the set is never smaller than what Codex writes.
    """
    paths: list[str] = []
    for line in patch.splitlines():
        left = line.lstrip()
        if left.startswith(PATCH_ENVIRONMENT_MARKER):
            raise Refusal("the patch targets another environment "
                          "(*** Environment ID); its paths cannot be checked here",
                          rule_id="hook-unsupported")
        for marker in PATCH_FILE_MARKERS:
            if left.startswith(marker):
                raw = left[len(marker):]
                if raw.startswith(" "):
                    raw = raw[1:]
                for name in dict.fromkeys((raw, raw.strip())):
                    if name and name not in paths:
                        paths.append(name)
    if not paths:
        raise Refusal("apply_patch: no file header found in the patch")
    return paths


def _object(tool: str, value) -> dict:
    if not isinstance(value, dict):
        raise Refusal(f"{tool}: tool_input must be a JSON object")
    return value


def _string(tool: str, args: dict, key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value:
        raise Refusal(f"{tool}: tool_input.{key} must be a non-empty string")
    return value


# -- evaluation -------------------------------------------------------------------

def evaluate(args: argparse.Namespace, raw: bytes, event: dict | None = None) -> Verdict:
    """PreToolUse. `event` is `raw` already parsed, when main could parse it."""
    host = args.host
    try:
        gateway = Gateway(args.policy, args.audit, approver=NoApprover(),
                          base_dir=args.base_dir)
    except Exception as e:  # unreadable or invalid policy
        reason = f"agent firewall: cannot load policy {args.policy}: {e}"
        _audit_without_policy(args.audit, host, reason)
        return Verdict("deny", reason)
    trace = None
    taint = None
    try:
        # Self-protection: the agent may neither read nor rewrite the policy
        # that judges it, the log that records it, the record of its own taint
        # or the trace a policy will be proposed from.
        own = _own_files(args)
        gateway.config.protected.update(own)
        try:
            taint = TaintStore(taint_path(args.audit))
        except TaintUnavailable as e:
            req = ActionRequest(actor=host, tool=f"{host}:hook-input",
                                params={"input": _digest(raw)})
            record = gateway.refuse(req, "fail-closed", f"{e}; failing closed",
                                    host=host)
            return Verdict("deny", _blocked(record))
        if args.learn:
            try:
                trace = learn.TraceWriter(args.learn, args.learn_mode, gateway.config,
                                          args.policy, self_protected=own)
            except learn.TraceUnavailable as e:
                req = ActionRequest(actor=host, tool=f"{host}:hook-input",
                                    params={"input": _digest(raw)})
                record = gateway.refuse(req, "fail-closed", f"{e}; failing closed",
                                        host=host)
                return Verdict("deny", _blocked(record))
        return _evaluate_event(gateway, host, raw, trace, event, taint)
    finally:
        if trace is not None:
            trace.close()
        if taint is not None:
            taint.close()
        if gateway.audit is not None:
            gateway.audit.close()


def taint_path(audit: str) -> str:
    """Where the hook keeps tainted sessions: next to its audit log."""
    return os.path.realpath(audit) + ".tainted"


def _own_files(args: argparse.Namespace) -> list[Path]:
    files = (args.policy, args.audit, taint_path(args.audit), args.learn)
    return [Path(os.path.realpath(p)) for p in files if p]


def _evaluate_event(gateway: Gateway, host: str, raw: bytes,
                    trace: learn.TraceWriter | None = None,
                    event: dict | None = None,
                    taint: TaintStore | None = None) -> Verdict:
    extra: dict = {"host": host}

    def observed(record: dict) -> Verdict | None:
        """Write the observation; a trace that cannot be written denies."""
        if trace is None:
            return None
        try:
            trace.observe(record, tainted=gateway.session.tainted)
        except learn.TraceUnavailable as e:
            return Verdict("deny", f"agent firewall: {e}; failing closed")
        return None

    try:
        if event is None:
            event = parse_event(raw)
        for key in ("session_id", "permission_mode", "agent_type"):
            if isinstance(event.get(key), str):
                extra[key] = event[key]
        if isinstance(event.get("tool_name"), str):
            extra["host_tool"] = event["tool_name"]
        if event.get("hook_event_name") != "PreToolUse":
            raise Refusal(f"expected a PreToolUse event, got "
                          f"{event.get('hook_event_name')!r}")
        requests = translate(event, host)
    except Refusal as refusal:
        surface = f"{host}:{extra.get('host_tool', 'hook-input')}"
        req = ActionRequest(actor=host, tool=surface, params={"input": _digest(raw)})
        record = gateway.refuse(req, refusal.rule_id, refusal.reason, **extra)
        return observed(record) or Verdict("deny", _blocked(record))

    if host == "claude-code" and extra.get("permission_mode") != "bypassPermissions":
        approval, note = "delegate", ""
    elif host == "claude-code":
        approval, note = "deny", ("in bypassPermissions mode a hook's ask is not "
                                  "guaranteed to reach a human, so it is denied")
    else:
        approval, note = "deny", ("Codex hooks cannot ask for approval (Codex "
                                  "ignores permissionDecision ask), so it is denied")

    # Each hook call is a new process, so a session's taint lives in the
    # store: a session that went for a protected path or carried a secret
    # value in an earlier call is tainted in this one from the start.
    session_id = extra.get("session_id")
    tainted_before = bool(taint is not None and session_id
                          and taint.tainted(session_id))
    gateway.session.tainted = tainted_before

    def remember(verdict: Verdict, record: dict) -> Verdict:
        """Keep a taint this call caused for the session's later calls. A
        taint that cannot be recorded denies this call."""
        if taint is None or not session_id or tainted_before \
                or not gateway.session.tainted:
            return verdict
        try:
            taint.mark(session_id, host=host, host_tool=extra.get("host_tool"),
                       correlation_id=record.get("correlation_id"),
                       rule_id=record.get("rule_id"))
        except TaintUnavailable as e:
            return Verdict("deny", f"agent firewall: {e}; failing closed")
        return verdict

    # Ask mode stops asking once the session has gone for a protected path
    # (the trace remembers it across hook calls) or has no id to check.
    relax = None
    if trace is not None and trace.mode == "ask" and session_id \
            and not tainted_before and not trace.session_tainted(session_id):
        relax = learn.ask_instead_of_block(gateway.config)
    asks: list[str] = []
    record: dict = {}
    for req in requests:
        record = gateway.decide(req, approval=approval, approval_note=note,
                                relax=relax, **extra)
        failed = observed(record)
        if failed:
            return remember(failed, record)
        if record["decision"] == "block":
            return remember(Verdict("deny", _blocked(record)), record)
        if record["decision"] == "require_approval":
            asks.append(f"agent firewall requires approval ({record['rule_id']}): "
                        f"{record['reason']}")
    if asks:
        return remember(Verdict("ask", "; ".join(asks)), record)
    return remember(Verdict("allow", "agent firewall: allowed by policy"), record)


def parse_event(raw: bytes) -> dict:
    if len(raw) > MAX_INPUT_BYTES:
        raise Refusal(f"hook input is larger than {MAX_INPUT_BYTES} bytes")
    try:
        event = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise Refusal(f"hook input is not JSON: {e}") from None
    if not isinstance(event, dict):
        raise Refusal("hook input is not a JSON object")
    return event


# -- PostToolUse: the host ran the tool --------------------------------------------

def record_ran(args: argparse.Namespace, event: dict) -> Verdict:
    """Append a `ran` record to the learning trace: the host ran this call, so
    if the hook asked, the human said yes.

    Nothing is decided and nothing is audited: the tool already ran. A record
    that cannot be written is simply missing, and the proposal treats an ask
    without one as refused. The record holds ids only, never `tool_response`.
    """
    if not args.learn:
        return Verdict("recorded", "nothing to record without --learn")
    ids = {key: event.get(key) for key in ("session_id", "tool_use_id", "tool_name")}
    missing = [key for key, value in ids.items() if not (isinstance(value, str) and value)]
    if missing:
        return Verdict("error", f"agent firewall: PostToolUse event without "
                                f"{', '.join(missing)}; not recorded")
    try:
        config = Config(args.policy, base_dir=args.base_dir)
    except Exception as e:  # unreadable or invalid policy
        return Verdict("error", f"agent firewall: cannot load policy {args.policy}: {e}; "
                                f"PostToolUse not recorded")
    try:
        trace = learn.TraceWriter(args.learn, args.learn_mode, config, args.policy,
                                  self_protected=_own_files(args))
    except learn.TraceUnavailable as e:
        return Verdict("error", f"agent firewall: {e}; PostToolUse not recorded")
    try:
        trace.ran(host=args.host, host_tool=ids["tool_name"],
                  session_id=ids["session_id"], correlation_id=ids["tool_use_id"])
    except learn.TraceUnavailable as e:
        return Verdict("error", f"agent firewall: {e}; PostToolUse not recorded")
    finally:
        trace.close()
    return Verdict("recorded", "")


def _audit_without_policy(audit_path: str, host: str, reason: str) -> None:
    """Best effort: leave a trace of a denial the policy never saw."""
    try:
        logger = AuditLogger(audit_path)
    except AuditUnavailable:
        return
    try:
        logger.log({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "actor": host,
                    "host": host, "decision": "block", "rule_id": "fail-closed",
                    "rules_matched": ["fail-closed"], "risk": "high",
                    "reason": reason, "outcome": "not_executed"})
    except OSError:
        pass
    finally:
        logger.close()


def _blocked(record: dict) -> str:
    return f"Blocked by agent firewall ({record['rule_id']}): {record['reason']}"


def _digest(raw: bytes) -> dict:
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


# -- output -----------------------------------------------------------------------

def emit(verdict: Verdict, host: str, emit_allow: bool, stdout, stderr) -> int:
    reason = verdict.reason
    if len(reason) > REASON_MAX_CHARS:
        reason = reason[:REASON_MAX_CHARS] + "…"
    decision = verdict.decision
    if decision == "ask" and host != "claude-code":
        decision = "deny"          # never hand Codex an answer it would ignore
    if decision not in ("allow", "ask"):
        # Exit 2 blocks in both hosts whatever happens to stdout; Claude Code
        # takes the JSON reason, Codex the stderr one.
        _write(stdout, _json("deny", reason))
        _write(stderr, reason + "\n")
        return 2
    if decision == "ask":
        _write(stdout, _json("ask", reason))
    elif emit_allow:
        _write(stdout, _json("allow", reason))
    return 0


def emit_post(verdict: Verdict, stderr) -> int:
    """PostToolUse: the tool already ran, so the answer must not change what the
    agent sees. No JSON on stdout (it could add context or replace the tool's
    output) and never exit 2 (its stderr goes to the model). A failure is exit 1:
    the host shows the first stderr line to the user as a hook error and goes on.
    """
    if verdict.decision == "recorded":
        return 0
    reason = verdict.reason
    if len(reason) > REASON_MAX_CHARS:
        reason = reason[:REASON_MAX_CHARS] + "…"
    _write(stderr, reason + "\n")
    return 1


def _json(decision: str, reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}) + "\n"


def _write(stream, text: str) -> None:
    try:
        stream.write(text)
        stream.flush()
    except (OSError, ValueError):
        pass


# -- entry point ------------------------------------------------------------------

class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse would exit 2 with a usage dump; keep the exit code (it denies)
        # and make the reason readable.
        reason = f"agent firewall hook: bad arguments ({message}); denying"
        print(_json("deny", reason), end="")
        print(reason, file=sys.stderr)
        raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="vt-agent-firewall-hook",
                     description="PreToolUse hook for Claude Code and Codex: the "
                                 "agent firewall's policy in front of the host's "
                                 "own tools. Reads one hook event on stdin. With "
                                 "--learn, also register it for PostToolUse: it "
                                 "records which calls ran and answers nothing.")
    parser.add_argument("--policy", required=True, help="policy JSON file")
    parser.add_argument("--audit", required=True, help="append-only audit JSONL")
    parser.add_argument("--host", choices=HOSTS, default="claude-code",
                        help="hook protocol to speak (default: claude-code)")
    parser.add_argument("--base-dir", help="resolve relative policy paths here")
    parser.add_argument("--emit-allow", action="store_true",
                        help="Claude Code only: answer an allowed call with an "
                             "explicit allow, which skips Claude Code's own "
                             "permission prompt (default: stay silent)")
    parser.add_argument("--learn", metavar="TRACE",
                        help="learning mode: also append one observation per "
                             "request to TRACE (JSONL) for vt-agent-firewall-propose, "
                             "and on a PostToolUse event a record that the call ran "
                             "(an ask counts only then); the policy is still enforced")
    parser.add_argument("--learn-mode", choices=learn.MODES, default="enforce",
                        help="enforce (default): decide exactly as without --learn. "
                             "ask (Claude Code only, NOT protective for what you "
                             "approve): a call refused only by the shell allowlist or "
                             "the MCP registry, that nothing else in the policy "
                             "refuses, gets Claude Code's prompt instead of a denial")
    parser.add_argument("--deadline", type=float, default=DEFAULT_DEADLINE_SEC,
                        help="deny when the decision takes longer than this many "
                             f"seconds (default {DEFAULT_DEADLINE_SEC:g}); keep it "
                             "below the hook timeout in the host's settings")
    return parser


def main(argv: list[str] | None = None, stdin=None, stdout=None, stderr=None) -> int:
    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    args = build_parser().parse_args(argv)
    if args.emit_allow and args.host != "claude-code":
        build_parser().error("--emit-allow is for Claude Code only (Codex rejects "
                             "an allow without updatedInput)")
    if args.learn_mode != "enforce" and not args.learn:
        build_parser().error("--learn-mode needs --learn TRACE")
    if args.learn_mode == "ask" and args.host != "claude-code":
        build_parser().error("--learn-mode ask is for Claude Code only (Codex cannot "
                             "ask from a hook, so every ask would be a denial)")
    post = False
    try:
        with _deadline(args.deadline):
            raw = stdin.read(MAX_INPUT_BYTES + 1)
            raw = raw if isinstance(raw, bytes) else raw.encode()
            try:
                event = parse_event(raw)
            except Refusal:
                event = None             # evaluate() refuses it, and audits that
            post = event is not None and event.get("hook_event_name") == "PostToolUse"
            verdict = record_ran(args, event) if post else evaluate(args, raw, event)
    except DeadlineExceeded:
        verdict = Verdict("deny", f"agent firewall: no decision within "
                                  f"{args.deadline:g}s; failing closed")
    except BaseException as e:  # anything unexpected denies, even ^C
        verdict = Verdict("deny", f"agent firewall: internal error "
                                  f"({type(e).__name__}: {e}); failing closed")
    if post:
        return emit_post(verdict, stderr)
    return emit(verdict, args.host, args.emit_allow, stdout, stderr)


class _deadline:
    """SIGALRM-based deadline, so the hook denies before the host's timeout
    cancels it (a cancelled hook lets the tool call proceed)."""

    def __init__(self, seconds: float):
        self.seconds = seconds
        self.armed = (seconds > 0 and hasattr(signal, "setitimer")
                      and threading.current_thread() is threading.main_thread())

    def __enter__(self):
        if self.armed:
            self.previous = signal.signal(signal.SIGALRM, self._fire)
            signal.setitimer(signal.ITIMER_REAL, self.seconds)
        return self

    def __exit__(self, *exc):
        if self.armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self.previous)
        return False

    @staticmethod
    def _fire(signum, frame):
        raise DeadlineExceeded()


if __name__ == "__main__":
    raise SystemExit(main())
