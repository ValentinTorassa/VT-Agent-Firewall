"""Learning mode: record what an agent attempts, then propose a policy.

Writing a least-privilege policy from scratch is hard, so people fall back to
allow-all. Learning mode starts from the policy you have and from what a real
session attempted, observing before blocking:

    record    vt-agent-firewall-hook --learn TRACE appends one observation per
              request: the normalized action and what the policy decided.
              Registered for PostToolUse too, it adds a `ran` record for each
              tool call the host ran, so an ask counts only once you said yes
    propose   vt-agent-firewall-propose replays the observations against the
              policy and writes a proposed policy and a report; it never
              applies anything

Two recording modes, chosen on the hook:

- `enforce` (default): the policy decides exactly as without --learn. The agent
  stays protected; the trace shows what it needed and was refused.
- `ask` (Claude Code only): a call refused ONLY because its binary is not on
  the allowlist or its MCP tool is not registered, and that the rest of the
  policy would let through, becomes Claude Code's permission prompt instead of
  a denial (rule `learn-ask`). What you approve runs outside those two rules:
  this mode does not protect you from what you approve. Every other refusal
  stays a denial (protected paths, the sandbox, network, shell syntax, unknown
  options), nothing runs without a human saying yes, and once a session has
  named or reached a protected path the hook stops asking for it (the trace
  carries that taint from one hook call to the next).

The proposal allows only what the firewall itself can bound:

- a writable directory: the first directory under the sandbox root that the
  agent asked to write in, never the root itself or a hidden directory; the
  protected paths inside it stay blocked;
- a shell binary with an argument grammar (argv.py): it only reads, and every
  file it may open is checked.

A binary without a grammar (an interpreter, a network client, a binary that
writes) is proposed for `shell_ask`: each call becomes a human's decision,
never an allow. Allowing it without asking is listed for a human decision, as
the exact commands the session ran (`shell_exact`), and so are the network
origins it fetched (`network.allow`), MCP tools, and writes in the root or in a
hidden directory, each with how often it was seen. Nothing a rule refuses for
safety is relaxed: protected paths, the sandbox, network, forbidden arguments
and API decisions are copied unchanged, and the proposal is replayed against
every observation to check it. What a session attempted after it named or
reached a protected path is not used as evidence: that session may be
following an injection. Neither is an ask without a `ran` record: the human
may have said no.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shlex
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from . import argv as argv_grammar
from . import network
from .audit import AuditLogger, AuditUnavailable, fcntl
from .config import Config
from .models import ActionRequest, Decision, PolicyDecision
from .policy import PolicyEngine
from .session import SessionState

# Version 2 adds `kind`: "decision" (one per request, as in version 1) or "ran"
# (the host ran a tool call: a PostToolUse event). Version 1 traces still read;
# they have no `ran` records, so none of their asks counts as evidence.
TRACE_VERSION = 2
READABLE_VERSIONS = (1, 2)
MODES = ("enforce", "ask")
# The only refusals a policy edit could lift, so the only ones `ask` mode asks
# about. Everything else is refused for a reason no observation can change.
LIFTABLE = frozenset({"sh-allowlist", "mcp-unknown-tool"})
STRICTNESS = {"allow": 0, "require_approval": 1, "block": 2}

# Report labels only. Whether a binary is proposed depends on one thing, an
# argument grammar in argv.py; these words tell the reviewer why the others are
# not. A binary missing from this table is still not proposed.
RISK_LABELS = {
    "runs code": frozenset({
        "python", "python3", "node", "deno", "bun", "ruby", "perl", "php", "bash", "sh",
        "zsh", "dash", "fish", "ksh", "env", "xargs", "make", "npm", "npx", "pnpm",
        "yarn", "pip", "pip3", "uv", "uvx", "poetry", "cargo", "go", "java", "gcc", "cc",
        "clang", "docker", "podman", "kubectl", "awk", "gawk", "sed", "osascript",
        "sudo", "su", "doas", "nohup", "timeout", "nice", "watch", "git", "tar",
        "pytest", "tox", "vim", "vi", "emacs", "less", "open", "xdg-open"}),
    "network": frozenset({
        "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "rsync", "ftp",
        "telnet", "socat", "git", "gh", "dig", "nslookup", "host", "ping", "aws",
        "gcloud", "az", "npm", "npx", "pnpm", "yarn", "pip", "pip3", "uv", "uvx",
        "docker", "podman", "kubectl"}),
    "writes or deletes files": frozenset({
        "rm", "rmdir", "mv", "cp", "dd", "truncate", "shred", "chmod", "chown", "chgrp",
        "ln", "mkdir", "touch", "tee", "install", "sed", "tar", "zip", "unzip", "patch",
        "git", "sort", "split", "uniq"}),
    "reads secrets": frozenset({
        "env", "printenv", "security", "gpg", "pass", "op", "bw", "vault", "aws",
        "gcloud", "az", "gh", "keyctl", "ssh-add"}),
}

UNCHANGED_WHY = {
    "fs-protected": "protected paths are never relaxed by learning",
    "fs-sandbox": "outside the sandbox: widen sandbox_root by hand if you mean it",
    "sh-paths": "the command names a protected path or leaves the sandbox",
    "sh-recursive": "the walk would reach a protected path or leave the sandbox",
    "sh-args": "options outside the binary's grammar, or forbidden",
    "sh-syntax": "a host shell would expand the line; no policy allows that, the "
                 "agent has to send simple commands",
    "net-deny-all": "network.allow only covers GET and HEAD without a body to a URL "
                    "it can read unambiguously: this request is none of those",
    "net-allowlist": "network.allow only covers GET and HEAD without a body to a URL "
                     "it can read unambiguously: this request is none of those",
    "taint-session": "the request names a protected path",
    "sh-allowlist": "the first word is not a program a policy can name (VAR=value, "
                    "whitespace or a control character): the agent has to send the "
                    "command without it",
    "unknown-tool": "a tool the firewall has no policy for",
    "mcp-protected-path": "an MCP argument names a protected path",
    "mcp-sandbox": "an MCP argument leaves the sandbox",
    "parse-error": "input the firewall could not parse",
    "hook-unsupported": "a call the hook cannot check",
    "fail-closed": "the audit store was unavailable",
}


# -- recording ----------------------------------------------------------------------

class TraceUnavailable(Exception):
    """The learning trace cannot be opened or written; the hook denies."""


class TraceWriter:
    """Appends one observation per decided request to a JSONL trace.

    An observation keeps what the audit record keeps (normalized params, written
    content as a digest) plus what the proposal checks: the recording mode, the
    sandbox root, a digest of the policy file and the paths the hook protected
    at run time (the policy, the audit log, the trace itself). `ran()` appends
    the record of a tool call the host ran (PostToolUse).
    """

    def __init__(self, path: str | Path, mode: str, config: Config,
                 policy_path: str | Path, self_protected=()):
        if mode not in MODES:
            raise ValueError(f"unknown learning mode {mode!r}")
        self.mode = mode
        self.sandbox_root = str(config.sandbox_root)
        self.self_protected = sorted(str(p) for p in self_protected)
        try:
            self.policy_sha256 = hashlib.sha256(Path(policy_path).read_bytes()).hexdigest()
            self._log = AuditLogger(path)
        except (OSError, AuditUnavailable) as e:
            raise TraceUnavailable(f"cannot open learning trace {path}: "
                                   f"{e.__cause__ or e}") from e

    def observe(self, record: dict, tainted: bool = False) -> None:
        """`record` is the audit record of one decision; `tainted` says whether
        the request named or reached a protected path."""
        decision = record.get("decision")
        observation = {
            "v": TRACE_VERSION,
            "kind": "decision",
            "ts": record.get("ts"),
            "mode": self.mode,
            "host": record.get("host"),
            "host_tool": record.get("host_tool"),
            "session_id": record.get("session_id"),
            "correlation_id": record.get("correlation_id"),
            # A record the audit store failed to write has no tool.
            "tool": record.get("tool") or "unrecorded",
            "normalized": record.get("normalized") or {},
            "decision": decision if decision in STRICTNESS else "block",
            "rule_id": record.get("rule_id") or "fail-closed",
            "rules_matched": record.get("rules_matched", []),
            "tainted": bool(tainted),
            **self._provenance(),
        }
        self._write(observation)

    def ran(self, host: str, host_tool: str, session_id: str,
            correlation_id: str) -> None:
        """The host ran this tool call (PostToolUse): the call's ids only.

        It never holds the tool's input or output (`tool_response` can carry a
        file's contents); the proposal matches it to the decision by session,
        tool_use_id and tool name.
        """
        self._write({
            "v": TRACE_VERSION,
            "kind": "ran",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "mode": self.mode,
            "host": host,
            "host_tool": host_tool,
            "session_id": session_id,
            "correlation_id": correlation_id,
            **self._provenance(),
        })

    def _provenance(self) -> dict:
        return {"sandbox_root": self.sandbox_root, "policy_sha256": self.policy_sha256,
                "self_protected": self.self_protected}

    def _write(self, line: dict) -> None:
        try:
            self._log.log(line)
        except OSError as e:
            raise TraceUnavailable(f"cannot write learning trace: {e}") from e

    def session_tainted(self, session_id: str) -> bool:
        """Has this session named or reached a protected path in an earlier
        call? A line that cannot be read counts as yes."""
        try:
            with open(self._log.path, encoding="utf-8") as fh:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        obs = json.loads(line)
                    except json.JSONDecodeError:
                        return True
                    if not isinstance(obs, dict):
                        return True
                    if obs.get("session_id") == session_id and obs.get("tainted"):
                        return True
        except (OSError, UnicodeDecodeError):
            return True
        return False

    def close(self) -> None:
        self._log.close()


# -- what a refusal would become with the one grant it lacks --------------------------

def with_grant(config: Config, decision: PolicyDecision) -> Config | None:
    """`config` plus the single grant that would lift this refusal, or None
    when no policy edit can lift it."""
    n = decision.normalized
    if decision.rule_id == "sh-allowlist" and isinstance(n.get("binary"), str):
        alt = copy.copy(config)
        alt.shell_allowlist = config.shell_allowlist | {n["binary"]}
        return alt
    if decision.rule_id == "mcp-unknown-tool" and isinstance(n.get("server"), str) \
            and isinstance(n.get("tool"), str):
        alt = copy.copy(config)
        alt.mcp_registry = {**config.mcp_registry,
                            n["server"]: config.mcp_registry.get(n["server"], set())
                            | {n["tool"]}}
        return alt
    return None


def would_decide(config: Config, decision: PolicyDecision) -> PolicyDecision | None:
    """The decision with the missing grant, or None if no grant would lift it.
    A request that names or reaches a protected path counts as blocked."""
    alt = with_grant(config, decision)
    if alt is None:
        return None
    state = SessionState()
    would = PolicyEngine(alt).evaluate(decision.request, state)
    if state.tainted and would.decision != Decision.BLOCK:
        would.decision = Decision.BLOCK
    return would


def risk_labels(binary: str) -> list[str]:
    return [label for label, names in RISK_LABELS.items() if binary in names]


def ask_instead_of_block(config: Config):
    """Gateway.decide `relax` for `--learn-mode ask`: a refusal in LIFTABLE that
    the rest of the policy would let through becomes `require_approval`. It
    never produces an allow."""
    def relax(decision: PolicyDecision) -> PolicyDecision:
        if decision.decision != Decision.BLOCK or decision.rule_id not in LIFTABLE:
            return decision
        would = would_decide(config, decision)
        if would is None or would.decision == Decision.BLOCK:
            return decision
        labels = risk_labels(decision.normalized.get("binary", ""))
        note = f" [{', '.join(labels)}]" if labels else ""
        return PolicyDecision(
            request=decision.request, decision=Decision.REQUIRE_APPROVAL,
            rule_id="learn-ask",
            reason=(f"LEARNING MODE (ask), this rule is not enforced now: the policy "
                    f"blocks this ({decision.rule_id}: {decision.reason}){note}. "
                    f"Approve only what you would add to the policy"),
            risk="high", rules_matched=[*decision.rules_matched, "learn-ask"],
            normalized=would.normalized)
    return relax


def _with(config: Config, **changes) -> Config:
    alt = copy.copy(config)
    for name, value in changes.items():
        setattr(alt, name, value)
    return alt


def _decide_with(config: Config, request: ActionRequest) -> PolicyDecision:
    """`request` against `config`; naming or reaching a protected path blocks."""
    state = SessionState()
    would = PolicyEngine(config).evaluate(request, state)
    if state.tainted and would.decision != Decision.BLOCK:
        would.decision = Decision.BLOCK
    return would


def exact_candidate(config: Config, decision: PolicyDecision):
    """(the shell_exact entry for this shell request, its decision with that
    entry), or None when no entry can name it (a VAR=value word first). A
    program spelled with a path is written as the file it resolves to."""
    n = decision.normalized
    binary, args, cwd = n.get("binary"), n.get("args"), n.get("cwd")
    if not (isinstance(binary, str) and isinstance(args, list)
            and isinstance(cwd, str)):
        return None
    program = binary
    if "/" in binary:
        resolved = Path(os.path.realpath(Path(cwd) / binary))
        try:
            program = resolved.relative_to(config.base_dir).as_posix()
        except ValueError:
            program = str(resolved)
    entry = [program, *map(str, args)]
    try:
        exact = Config.exact_entry(config.base_dir, entry)
    except ValueError:
        return None
    alt = _with(config, shell_exact=[*config.shell_exact, exact])
    return entry, _decide_with(alt, decision.request)


def can_ask(binary: str) -> bool:
    """Can this program go on shell_ask (a bare name, no path, no VAR=value)?"""
    try:
        Config._programs([binary], "shell_ask")
    except ValueError:
        return False
    return True


def network_candidate(config: Config, decision: PolicyDecision):
    """(the origin of this request, its decision with that origin on
    network.allow), or None when the allowlist could never match the URL."""
    target = network.origin_of(decision.normalized.get("url"))
    if target is None:
        return None
    entry = network.parse_entry(target.origin())
    alt = _with(config, network_mode="allowlist",
                network_allow=[*config.network_allow, entry])
    return target, _decide_with(alt, decision.request)


def _ask_why(binary: str) -> str:
    return "; ".join(risk_labels(binary) + [
        "no argument grammar: asked about call by call, never allowed (still "
        "denied where nobody can answer, as in Codex)"])


def _exact_why(binary: str) -> str:
    why = risk_labels(binary) + [
        "this exact argv runs without asking: the firewall checks the argv, not "
        "what the program does"]
    if "/" in binary:
        why.append("a program spelled with a path cannot go on shell_ask, so this "
                   "is the only grant for it")
    return "; ".join(why)


def _network_why(target: network.Target, config: Config) -> str:
    why = []
    if network.is_local(target):
        why.append("the machine itself or its network (an IP address, localhost or "
                   "a single-label name)")
    if target.scheme in ("http", "ws"):
        why.append("cleartext")
    why.append("GET and HEAD to this origin, any path, without asking: data can "
               "still leave in the URL")
    if config.network_mode != "allowlist":
        why.append('also set network.mode to "allowlist"')
    return "; ".join(why)


# -- reading traces -----------------------------------------------------------------

class TraceError(ValueError):
    """A trace that cannot be used: malformed, another version, another sandbox."""


class ProposalError(RuntimeError):
    """The proposal failed its own replay check; nothing is written."""


@dataclass
class Observation:
    where: str                 # trace file:line
    session: str
    mode: str
    tool: str
    normalized: dict
    recorded: tuple[str, str]  # (decision, rule_id) when it was recorded
    host_tool: str | None
    policy_sha256: str | None
    self_protected: list[str]
    ran: bool = False          # a `ran` record (PostToolUse) matches it

    @property
    def asked(self) -> bool:
        """Recorded as an ask: the host prompted a human, who may have said no."""
        return self.recorded[0] == "require_approval"


def read_traces(paths, sandbox_root: Path) -> list[Observation]:
    """Decision observations from every trace, each marked `ran` when a `ran`
    record with the same session, tool_use_id and tool name exists in any of
    them."""
    observations: list[Observation] = []
    keys: list[tuple | None] = []
    ran: set[tuple] = set()
    for path in paths:
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as e:
            raise TraceError(f"cannot read trace {path}: {e}") from None
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            where = f"{path}:{number}"
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as e:
                raise TraceError(f"{where}: not JSON ({e.msg})") from None
            if not isinstance(raw, dict) or raw.get("v") not in READABLE_VERSIONS:
                raise TraceError(f"{where}: not a trace record of version "
                                 f"{' or '.join(map(str, READABLE_VERSIONS))}")
            if raw.get("sandbox_root") != str(sandbox_root):
                raise TraceError(f"{where}: recorded with sandbox "
                                 f"{raw.get('sandbox_root')}, but this policy's sandbox "
                                 f"is {sandbox_root} (use the hook's --base-dir)")
            kind = raw.get("kind", "decision")        # version 1 has decisions only
            if kind == "ran":
                key = _ran_key(raw)
                if key is None:
                    raise TraceError(f"{where}: a ran record needs session_id, "
                                     f"correlation_id and host_tool")
                ran.add(key)
                continue
            if kind != "decision":
                raise TraceError(f"{where}: unknown record kind {kind!r}")
            if not (isinstance(raw.get("tool"), str)
                    and isinstance(raw.get("normalized"), dict)
                    and raw.get("mode") in MODES
                    and raw.get("decision") in STRICTNESS
                    and isinstance(raw.get("rule_id"), str)
                    and isinstance(raw.get("self_protected", []), list)):
                raise TraceError(f"{where}: missing or invalid tool, normalized, mode, "
                                 f"decision or rule_id")
            session = raw.get("session_id")
            if not isinstance(session, str) or not session:
                session = f"{path} (no session id)"
            observations.append(Observation(
                where=where, session=session, mode=raw["mode"], tool=raw["tool"],
                normalized=raw["normalized"], recorded=(raw["decision"], raw["rule_id"]),
                host_tool=raw.get("host_tool") if isinstance(raw.get("host_tool"), str)
                else None,
                policy_sha256=raw.get("policy_sha256"),
                self_protected=[p for p in raw.get("self_protected", [])
                                if isinstance(p, str)]))
            keys.append(_ran_key(raw))
    for obs, key in zip(observations, keys):
        obs.ran = key is not None and key in ran
    return observations


def _ran_key(raw: dict) -> tuple | None:
    """What ties a `ran` record to its decision: the host's session, its
    tool_use_id (the decision's correlation_id) and the tool name. A record
    without all three matches nothing."""
    key = (raw.get("session_id"), raw.get("correlation_id"), raw.get("host_tool"))
    return key if all(isinstance(k, str) and k for k in key) else None


def replay_request(obs: Observation) -> ActionRequest | None:
    """The request again, from its normalized params; None when it cannot be
    replayed (input the hook refused, a host tool without a mapping)."""
    n = obs.normalized
    try:
        if obs.tool in ("fs.read", "fs.write"):
            params = {"path": n["path"], "cwd": n["cwd"]}
            if obs.tool == "fs.write":
                params["content"] = ""
        elif obs.tool == "shell.run" and "binary" in n:
            params = {"command": n["binary"], "args": list(n["args"]), "cwd": n["cwd"]}
        elif obs.tool == "shell.run":
            params = {"command_line": n["command_line"], "cwd": n["cwd"],
                      "via_shell": True}
        elif obs.tool == "net.request":
            params = {"url": n["url"], "method": n.get("method", "GET")}
        elif obs.tool == "mcp.call":
            params = {"server": n["server"], "tool": n["tool"],
                      "arguments": n["arguments"]}
        else:
            return None
    except (KeyError, TypeError):
        return None
    return ActionRequest(actor="learn-replay", tool=obs.tool, params=params)


@dataclass
class Replayed:
    decision: str
    rule_id: str
    tainted: bool
    policy: PolicyDecision | None    # None when it could not be replayed


def replay(config: Config, obs: Observation) -> Replayed:
    req = replay_request(obs)
    if req is None:
        decision, rule = obs.recorded
        return Replayed("block" if rule == "learn-ask" else decision, rule, False, None)
    state = SessionState()
    d = PolicyEngine(config).evaluate(req, state)
    return Replayed(d.decision.value, d.rule_id, state.tainted, d)


# -- the proposal -------------------------------------------------------------------

@dataclass
class Group:
    section: str     # add | unused | decide | untrusted | unchanged
    policy_key: str  # the policy key, or the rule id for `unchanged`
    key: str
    why: str
    seen: int = 0
    sessions: set = field(default_factory=set)
    examples: list = field(default_factory=list)

    def add(self, obs: Observation, example: str) -> None:
        self.seen += 1
        self.sessions.add(obs.session)
        if example not in self.examples and len(self.examples) < 3:
            self.examples.append(example)


@dataclass
class Proposal:
    policy: dict
    groups: list[Group]
    observations: int
    sessions: int
    modes: Counter
    before: Counter
    after: Counter
    notes: list[str]

    def section(self, name: str) -> list[Group]:
        return [g for g in self.groups if g.section == name]


def propose(policy_path: str | Path, trace_paths, base_dir: str | Path | None = None,
            drop_unused: bool = False) -> Proposal:
    policy_path = Path(policy_path)
    policy_bytes = policy_path.read_bytes()
    raw = json.loads(policy_bytes.decode("utf-8"))
    config = Config(policy_path, base_dir=base_dir)
    observations = read_traces(trace_paths, config.sandbox_root)
    if not observations:
        raise TraceError("the traces hold no observations")
    # The hook protected its own files at run time; so does the replay.
    for obs in observations:
        config.protected.update(Path(p) for p in obs.self_protected)

    def show(path: Path) -> str:
        try:
            return path.relative_to(config.base_dir).as_posix() or "."
        except ValueError:
            return str(path)

    def describe(obs: Observation) -> str:
        n, verb = obs.normalized, obs.host_tool or obs.tool
        if obs.tool in ("fs.read", "fs.write") and isinstance(n.get("path"), str):
            return f"{verb} {show(Path(n['path']))}"
        if obs.tool == "shell.run" and isinstance(n.get("binary"), str):
            return f"{verb} {shlex.join([n['binary'], *map(str, n.get('args', []))])}"
        if obs.tool == "shell.run" and isinstance(n.get("command_line"), str):
            return f"{verb} {n['command_line']}"
        if obs.tool == "net.request" and isinstance(n.get("url"), str):
            return f"{verb} {n['url']}"
        if obs.tool == "mcp.call":
            return f"{verb} {n.get('server')}/{n.get('tool')}"
        return verb

    groups: dict[tuple[str, str, str], Group] = {}

    def group(section: str, field_: str, key: str, why: str) -> Group:
        return groups.setdefault((section, field_, key), Group(section, field_, key, why))

    tainted_by: dict[str, str] = {}
    unconfirmed = 0                  # asks no `ran` record confirms
    used_bins: set[str] = set()
    used_asks: set[str] = set()
    used_exact: set[tuple] = set()
    used_net: set[str] = set()
    used_dirs: set[Path] = set()
    new_dirs: set[Path] = set()
    new_bins: set[str] = set()
    new_asks: set[str] = set()
    befores: list[Replayed] = []
    evidence: list[bool] = []        # may this observation support a grant?
    drifted = 0
    sha = hashlib.sha256(policy_bytes).hexdigest()
    other_policy = sum(1 for obs in observations if obs.policy_sha256 != sha)

    for obs in observations:
        before = replay(config, obs)
        befores.append(before)
        recorded = obs.recorded
        if recorded[1] == "learn-ask":
            recorded = ("block", before.rule_id if before.rule_id in LIFTABLE else "?")
        refused = recorded[1] == "approval-denied"
        if (before.decision, before.rule_id) != recorded and not refused:
            drifted += 1
        example = describe(obs)
        if before.tainted and obs.session not in tainted_by:
            tainted_by[obs.session] = example
        clean = obs.session not in tainted_by
        # An ask is a yes only if the host then ran the call: without a `ran`
        # record the human may have said no (or the call failed or never came).
        confirmed = obs.ran or not obs.asked
        unconfirmed += not confirmed
        evidence.append(clean and not refused and confirmed)
        untrusted = (f"session {obs.session}, after {tainted_by[obs.session]}"
                     if not clean else None if confirmed
                     else "asked, and no PostToolUse record shows it was approved and ran")
        d = before.policy

        if refused:
            group("unchanged", "approval-denied", "approval-denied",
                  "refused at approval (by a human, a timeout or a host that cannot "
                  "ask): a no is never learned as a yes").add(obs, example)
            continue

        if before.decision == "allow":
            if before.rule_id == "sh-ok":
                used_bins.add(d.normalized["binary"])
            elif before.rule_id == "sh-exact":
                n = d.normalized
                hit = config.exact_command([n["binary"], *n["args"]], Path(n["cwd"]))
                if hit is not None:
                    used_exact.add(hit.argv)
            elif before.rule_id == "net-ok":
                hit, _ = network.match(config.network_allow, d.normalized["url"],
                                       d.normalized["method"], None)
                if hit is not None:
                    used_net.add(hit.text)
            elif before.rule_id == "fs-write-ok":
                path = Path(d.normalized["path"])
                used_dirs.update(w for w in config.writable_dirs
                                 if w == path or w in path.parents)
            continue

        if before.rule_id == "fs-write-scope" and d is not None:
            path = Path(d.normalized["path"])
            target, why = _writable_candidate(config, path)
            if untrusted:
                group("untrusted", "writable_dirs", example, untrusted).add(obs, example)
            elif target is None:
                group("decide", "writable_dirs", show(path), why).add(obs, example)
            else:
                new_dirs.add(target)
                group("add", "writable_dirs", show(target), why).add(obs, example)
            continue

        if before.rule_id == "sh-ask" and d is not None:
            # Already asked about. The one thing left to propose is allowing the
            # exact command without asking, and that is a human's decision.
            used_asks.add(d.normalized["binary"])
            candidate = exact_candidate(config, d)
            if candidate is not None and candidate[1].decision != Decision.BLOCK:
                if untrusted:
                    group("untrusted", "shell_exact", example, untrusted).add(obs, example)
                else:
                    group("decide", "shell_exact", json.dumps(candidate[0]),
                          _exact_why(d.normalized["binary"])).add(obs, example)
            continue

        if before.rule_id == "sh-allowlist" and d is not None \
                and not argv_grammar.has_grammar(d.normalized["binary"]):
            # No grammar, so never the allowlist: ask about the binary, and list
            # its exact commands for a human to allow.
            binary = d.normalized["binary"]
            candidate = exact_candidate(config, d)
            if candidate is None:
                group("unchanged", "sh-allowlist", "sh-allowlist",
                      UNCHANGED_WHY["sh-allowlist"]).add(obs, example)
                continue
            entry, would = candidate
            if would.decision == Decision.BLOCK:
                rule = would.rule_id
                group("unchanged", rule, rule,
                      f"{UNCHANGED_WHY.get(rule, 'a refusal learning does not relax')} "
                      f"(even with the missing sh-allowlist grant)").add(obs, example)
                continue
            if untrusted:
                group("untrusted", "shell_ask" if can_ask(binary) else "shell_exact",
                      example, untrusted).add(obs, example)
                continue
            if can_ask(binary):
                new_asks.add(binary)
                group("add", "shell_ask", binary, _ask_why(binary)).add(obs, example)
            group("decide", "shell_exact", json.dumps(entry),
                  _exact_why(binary)).add(obs, example)
            continue

        if before.rule_id in ("net-deny-all", "net-allowlist") and d is not None:
            candidate = network_candidate(config, d)
            if candidate is None or candidate[1].decision == Decision.BLOCK:
                rule = before.rule_id
                group("unchanged", rule, rule, UNCHANGED_WHY[rule]).add(obs, example)
            elif untrusted:
                group("untrusted", "network.allow", example, untrusted).add(obs, example)
            else:
                target = candidate[0]
                group("decide", "network.allow", target.origin(),
                      _network_why(target, config)).add(obs, example)
            continue

        if before.rule_id in LIFTABLE and d is not None:
            would = would_decide(config, d)
            if would is None or would.decision == Decision.BLOCK:
                rule = would.rule_id if would is not None else before.rule_id
                group("unchanged", rule, rule,
                      f"{UNCHANGED_WHY.get(rule, 'a refusal learning does not relax')} "
                      f"(even with the missing {before.rule_id} grant)").add(obs, example)
                continue
            field_ = ("shell_allowlist" if before.rule_id == "sh-allowlist"
                      else "mcp_registry")
            key = (d.normalized["binary"] if field_ == "shell_allowlist"
                   else f"{d.normalized['server']}/{d.normalized['tool']}")
            if untrusted:
                group("untrusted", field_, example, untrusted).add(obs, example)
            elif field_ == "shell_allowlist":
                new_bins.add(key)
                group("add", field_, key, "has an argument grammar: it only reads, and "
                      "every file it may open is checked").add(obs, example)
            else:
                group("decide", field_, key, "the firewall checks an MCP tool's path "
                      "arguments, not what the tool does: registering it is a decision "
                      "about that server").add(obs, example)
            continue

        rule = before.rule_id
        why = UNCHANGED_WHY.get(rule, "a refusal learning does not relax")
        group("unchanged", rule, rule, why).add(obs, example)

    proposed = copy.deepcopy(raw)
    if new_dirs:
        proposed["writable_dirs"] = [*raw.get("writable_dirs", []),
                                     *sorted(show(p) for p in new_dirs)]
    if new_bins:
        proposed["shell_allowlist"] = [*raw.get("shell_allowlist", []), *sorted(new_bins)]
    if new_asks:
        proposed["shell_ask"] = [*raw.get("shell_ask", []), *sorted(new_asks)]

    unused_bins = [b for b in raw.get("shell_allowlist", []) if b not in used_bins]
    unused_dirs = [e for e in raw.get("writable_dirs", [])
                   if Config._abs(config.base_dir, e) not in used_dirs]
    unused_asks = [b for b in raw.get("shell_ask", []) if b not in used_asks]
    unused_exact = [e for e in raw.get("shell_exact", []) if tuple(e) not in used_exact]
    raw_net = raw.get("network", {})
    unused_net = [e for e in (raw_net.get("allow") or []) if e not in used_net] \
        if config.network_mode == "allowlist" else []
    for b in unused_bins:
        group("unused", "shell_allowlist", b, "allowlisted, never used")
    for e in unused_dirs:
        group("unused", "writable_dirs", e, "writable, never written")
    for b in unused_asks:
        group("unused", "shell_ask", b, "asked about, never seen")
    for e in unused_exact:
        group("unused", "shell_exact", json.dumps(e), "allowed exactly, never run")
    for e in unused_net:
        group("unused", "network.allow", e, "allowed, never fetched")
    if drop_unused:
        proposed["shell_allowlist"] = [b for b in proposed["shell_allowlist"]
                                       if b not in unused_bins]
        proposed["writable_dirs"] = [e for e in proposed["writable_dirs"]
                                     if e not in unused_dirs]
        if unused_asks:
            proposed["shell_ask"] = [b for b in proposed["shell_ask"]
                                     if b not in unused_asks]
        if unused_exact:
            proposed["shell_exact"] = [e for e in proposed["shell_exact"]
                                       if e not in unused_exact]
        if unused_net:
            proposed["network"] = {**proposed["network"],
                                   "allow": [e for e in proposed["network"]["allow"]
                                             if e not in unused_net]}

    # Check the proposal against every observation before anyone sees it: the
    # only decisions allowed to get looser are the grants listed above.
    proposed_config = Config.from_raw(proposed, config.base_dir)
    proposed_config.protected = set(config.protected)
    after_counts: Counter = Counter()
    unlearned_allowed: list[str] = []
    unlearned_asked: list[str] = []
    for obs, before, usable in zip(observations, befores, evidence):
        after = replay(proposed_config, obs)
        after_counts[after.decision] += 1
        if STRICTNESS[after.decision] >= STRICTNESS[before.decision]:
            continue
        d = after.policy
        granted = d is not None and (
            (before.rule_id == "sh-allowlist" and d.normalized.get("binary") in new_bins)
            or (before.rule_id == "sh-allowlist" and after.rule_id == "sh-ask"
                and d.normalized.get("binary") in new_asks)
            or (before.rule_id == "fs-write-scope"
                and any(t == Path(d.normalized["path"])
                        or t in Path(d.normalized["path"]).parents for t in new_dirs)))
        if not granted:
            raise ProposalError(f"{obs.where}: the proposal would turn {before.decision} "
                                f"({before.rule_id}) into {after.decision} "
                                f"({after.rule_id}) for {describe(obs)}; not proposing")
        unlearned = unlearned_allowed if after.decision == "allow" else unlearned_asked
        if not usable and describe(obs) not in unlearned:
            unlearned.append(describe(obs))

    notes = []
    if unconfirmed and not any(obs.ran for obs in observations):
        notes.append(f"these traces hold no PostToolUse records (recorded by 0.3.0, or "
                     f"the hook is not registered for PostToolUse), so none of their "
                     f"{unconfirmed} ask(s) is learned from. Register the same hook "
                     f"command for PostToolUse and record again (docs/LEARNING.md).")
    elif unconfirmed:
        notes.append(f"{unconfirmed} ask(s) have no PostToolUse record: refused at the "
                     f"prompt, failed or interrupted. They are not learned from.")
    if other_policy:
        notes.append(f"{other_policy} observation(s) were recorded under a different "
                     f"policy file; every decision here is recomputed against this one.")
    if unlearned_allowed:
        shown = "; ".join(unlearned_allowed[:3])
        notes.append(f"the proposed grants would also allow {len(unlearned_allowed)} "
                     f"action(s) that were not learned from (refused at approval, "
                     f"asked and not confirmed as run, or after the session went for a "
                     f"protected path): {shown}. Check that each grant is what you "
                     f"want.")
    if unlearned_asked:
        shown = "; ".join(unlearned_asked[:3])
        notes.append(f"the proposed shell_ask entries would also ask about "
                     f"{len(unlearned_asked)} action(s) that were not learned from "
                     f"(refused at approval, asked and not confirmed as run, or after "
                     f"the session went for a protected path): {shown}.")
    if drifted:
        notes.append(f"{drifted} observation(s) decide differently now than when they "
                     f"were recorded (the policy or the files changed).")
    order = {"add": 0, "unused": 1, "decide": 2, "untrusted": 3, "unchanged": 4}
    ordered = sorted(groups.values(), key=lambda g: (order[g.section], g.policy_key,
                                                     -g.seen, g.key))
    return Proposal(policy=proposed, groups=ordered, observations=len(observations),
                    sessions=len({o.session for o in observations}),
                    modes=Counter(o.mode for o in observations),
                    before=Counter(b.decision for b in befores), after=after_counts,
                    notes=notes)


def _writable_candidate(config: Config, path: Path) -> tuple[Path | None, str]:
    """The directory a write generalizes to, or None and why it does not."""
    try:
        rel = path.relative_to(config.sandbox_root)
    except ValueError:
        return None, "outside the sandbox"
    if len(rel.parts) < 2:
        return None, ("a file in the sandbox root: only a writable root would cover "
                      "it, and that makes every file writable")
    top = rel.parts[0]
    if top.startswith("."):
        return None, (f"inside the hidden directory {top} (VCS, CI or tool settings, "
                      f"which can run code): keep asking")
    target = config.sandbox_root / top
    inside = [p for p in config.protected if p == target or target in p.parents]
    why = "the first directory under the sandbox root that the agent wrote in"
    if inside:
        why += f"; the {len(inside)} protected path(s) inside it stay blocked"
    return target, why


# -- report -------------------------------------------------------------------------

SECTIONS = [
    ("add", "Proposed grants"),
    ("unused", "Granted but never used in these traces"),
    ("decide", "Needs your decision (not proposed: the firewall cannot bound it)"),
    ("untrusted", "Not learned from"),
    ("unchanged", "Unchanged: learning never relaxes these"),
]


def render(proposal: Proposal, policy: str, out: str | None,
           drop_unused: bool = False) -> str:
    lines = []
    modes = ", ".join(f"{mode} {count}" for mode, count in sorted(proposal.modes.items()))
    lines.append(f"Policy proposal from {proposal.observations} observation(s) in "
                 f"{proposal.sessions} session(s) ({modes}), against {policy}.")
    lines.append("Nothing has been applied. Review each line and copy what you accept.")
    if proposal.modes.get("ask"):
        lines.append("Some observations were recorded in ask mode: the allowlist and "
                     "the MCP registry were asked about, not enforced.")
    for note in proposal.notes:
        lines.append(f"Note: {note}")
    for section, title in SECTIONS:
        found = proposal.section(section)
        if section == "unused" and found:
            lines += ["", title + (" (removed: --drop-unused)" if drop_unused
                                   else " (kept; --drop-unused removes them)")]
            by_field: dict[str, list[str]] = {}
            for g in found:
                by_field.setdefault(g.policy_key, []).append(g.key)
            mark = "-" if drop_unused else " "
            for field_, keys in by_field.items():
                lines.append(f"  {mark} {field_:<16} {', '.join(keys)}")
            continue
        if not found and section not in ("add",):
            continue
        lines += ["", title]
        if not found:
            lines.append("  (none)")
        for g in found:
            mark = "+" if section == "add" else " "
            times = f"{g.seen} time{'s' if g.seen != 1 else ''}"
            sessions = f"{len(g.sessions)} session{'s' if len(g.sessions) != 1 else ''}"
            if section == "untrusted":
                lines.append(f"    {g.key}  ({times})")
                lines.append(f"        {g.why}")
                continue
            label = g.key if section != "unchanged" else ""
            lines.append(f"  {mark} {g.policy_key:<16} {label:<28} "
                         f"{times}, {sessions}".rstrip())
            lines.append(f"        {g.why}")
            if g.policy_key != "shell_exact":   # the entry is the example
                lines.append(f"        e.g. {'; '.join(g.examples)}")
    b, a = proposal.before, proposal.after
    lines += ["", "Replayed against the proposal: " + ", ".join(
        f"{name} {b.get(key, 0)} -> {a.get(key, 0)}"
        for key, name in (("allow", "allow"), ("require_approval", "ask"),
                          ("block", "block"))) + "."]
    if out:
        lines.append(f"Proposed policy written to {out}. Compare: diff -u {policy} {out}")
    else:
        lines.append("Pass --out FILE to write the proposed policy.")
    return "\n".join(lines) + "\n"


# -- CLI ----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vt-agent-firewall-propose",
        description="Turn learning traces recorded by `vt-agent-firewall-hook --learn` "
                    "into a proposed policy and a report. An ask counts only when the "
                    "trace shows it ran (the hook registered for PostToolUse). Nothing "
                    "is applied: review the report and copy what you accept.")
    parser.add_argument("traces", nargs="+", metavar="TRACE",
                        help="learning trace(s); several are merged")
    parser.add_argument("--policy", required=True,
                        help="the policy to start from (normally the one the hook used)")
    parser.add_argument("--base-dir", help="resolve relative policy paths here "
                                           "(the hook's --base-dir)")
    parser.add_argument("--out", help="write the proposed policy to this file "
                                      "(never over --policy)")
    parser.add_argument("--drop-unused", action="store_true",
                        help="also remove allowlisted binaries and writable "
                             "directories that no observation used")
    return parser


def main(argv: list[str] | None = None, stdout=None, stderr=None) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    args = build_parser().parse_args(argv)
    if args.out and _same_file(args.out, args.policy):
        print("vt-agent-firewall-propose: --out is the policy itself; a proposal is "
              "for review, write it somewhere else", file=stderr)
        return 1
    try:
        proposal = propose(args.policy, args.traces, base_dir=args.base_dir,
                           drop_unused=args.drop_unused)
    except (TraceError, ProposalError, OSError, ValueError, KeyError, TypeError) as e:
        print(f"vt-agent-firewall-propose: {e}", file=stderr)
        return 1
    stdout.write(render(proposal, policy=args.policy, out=args.out,
                        drop_unused=args.drop_unused))
    if args.out:
        Path(args.out).write_text(json.dumps(proposal.policy, indent=2) + "\n",
                                  encoding="utf-8")
    return 0


def _same_file(a: str, b: str) -> bool:
    if os.path.realpath(a) == os.path.realpath(b):
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
