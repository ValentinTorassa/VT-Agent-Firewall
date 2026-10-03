"""Gateway orchestration: request -> policy -> (approve?) -> audit -> execute.

Ordering invariants:
- Denied actions are audited BEFORE returning; they never execute.
- Allowed actions get a durable `intent` record (fsynced, with an action_id)
  BEFORE dispatch, then an `executed` or `error` record with the same
  action_id. If the intent cannot be written, the action is not dispatched.
  A crash between the two leaves an unresolved intent, never an invisible
  side effect.
- If any audit write fails, the gateway poisons itself and denies everything
  afterwards (fail-closed). If the audit store cannot even be opened at
  startup, every request is denied with `fail-closed`.
- Audit records keep a SHA-256 and length for written content and at most a
  short preview of network bodies, unless verbose audit is enabled.
- `decide()` is the same pipeline without the executor, for an agent host that
  runs its own tools (the Claude Code / Codex hook). An allowed action gets a
  durable `delegated` record before the host may run it; the gateway never
  sees the result, so there is no `executed` record to pair it with.
"""

from __future__ import annotations

import copy
import hashlib
import sys
import time
import uuid
from pathlib import Path

from .approval import TerminalApprover
from .audit import AuditLogger, AuditUnavailable
from .config import Config
from .executor import Executor
from .models import ActionRequest, Decision, PolicyDecision
from .policy import PolicyEngine
from .session import SessionState


class Gateway:
    def __init__(self, config_path: str | Path, audit_path: str | Path,
                 approver=None, base_dir: str | Path | None = None,
                 broker=None, subject: str | None = None, apis=None,
                 mcp_backends=None, audit_verbose: bool | None = None):
        self.config = Config(config_path, base_dir=base_dir)
        # Verbose audit keeps written content and bodies in full: for local
        # debugging only, never for a shared log.
        self.audit_verbose = (self.config.audit_verbose if audit_verbose is None
                              else audit_verbose)
        self.policy = PolicyEngine(self.config)
        # broker/subject/apis enable `api.call`: delegated credentials minted
        # per call. Without them every api.call fails closed in the executor.
        # mcp_backends maps an MCP server name to a live connection (the MCP
        # proxy); servers without one keep the simulated demo behavior.
        self.executor = Executor(broker=broker, subject=subject, apis=apis,
                                 mcp_backends=mcp_backends)
        self.approver = approver or TerminalApprover(self.config.approval_timeout_sec)
        self.session = SessionState()
        self._broken = False
        try:
            self.audit = AuditLogger(audit_path)
        except AuditUnavailable as e:
            print(f"FAIL-CLOSED: {e}", file=sys.stderr)
            self.audit = None
            self._broken = True

    def handle(self, req: ActionRequest) -> dict:
        """Decide, execute if allowed, audit. Returns the audit record."""
        return self.handle_with_result(req)[0]

    def handle_with_result(self, req: ActionRequest) -> tuple[dict, object]:
        """Same as `handle`, plus the full executor result (None unless executed).

        The audit record only keeps a 200-character preview; callers that relay
        the result (the MCP proxy) need all of it.
        """
        if self._broken:
            return self._record(self._fail_closed(req), outcome="not_executed"), None

        decision = self.policy.evaluate(req, self.session)

        if decision.decision == Decision.REQUIRE_APPROVAL:
            if self.approver.approve(decision):
                decision.decision = Decision.ALLOW
                decision.rules_matched.append("approval-granted")
            else:
                self._deny_approval(decision, "human denied or approval timed out")

        if decision.decision == Decision.BLOCK:
            # Audit-first: the attempt is recorded before we return.
            return self._record(decision, outcome="not_executed"), None

        action_id = uuid.uuid4().hex
        try:
            # fsync the intent before dispatch. A crash thereafter leaves an
            # explicit unresolved action rather than an invisible side effect.
            self._record(decision, outcome="intent", action_id=action_id, strict=True)
        except AuditUnavailable:
            return self._unrecorded_block(decision, action_id), None

        try:
            result = self.executor.execute(decision.request.tool,
                                           decision.normalized)
            extra = {}
            if isinstance(result, dict) and "token" in result:
                # Delegated call: audit which token was used (claims only,
                # never the bearer value), then preview the API's answer.
                extra["token"] = result["token"]
                result = result["result"]
            return self._record(decision, outcome="executed", action_id=action_id,
                                result_preview=str(result)[:200], **extra), result
        except Exception as e:  # executor errors are audited, not hidden
            return self._record(decision, outcome="error", action_id=action_id,
                                error=str(e)), None

    def decide(self, req: ActionRequest, approval: str = "delegate",
               approval_note: str = "no approval channel", **extra) -> dict:
        """Decide and audit, never execute: the agent host runs the tool.

        `approval="delegate"` leaves `require_approval` for the host to ask a
        human (the hook answers "ask"); anything else turns it into
        `approval-denied` with `approval_note` as the reason. `extra` fields
        (host, session, tool name) go into the audit record.
        """
        if self._broken:
            return self._record(self._fail_closed(req), outcome="not_executed", **extra)
        decision = self.policy.evaluate(req, self.session)
        if decision.decision == Decision.REQUIRE_APPROVAL and approval != "delegate":
            self._deny_approval(decision, approval_note)
        if decision.decision == Decision.BLOCK:
            return self._record(decision, outcome="not_executed", **extra)
        try:
            # Durable before the host may act, like the executor's intent record.
            return self._record(decision, outcome="delegated", strict=True, **extra)
        except AuditUnavailable:
            return self._unrecorded_block(decision, uuid.uuid4().hex)

    def refuse(self, req: ActionRequest, rule_id: str, reason: str, **extra) -> dict:
        """Audit a request that never reached the policy because it could not
        be translated into one (malformed input). Always a block."""
        decision = PolicyDecision(request=req, decision=Decision.BLOCK,
                                  rule_id=rule_id, reason=reason, risk="high",
                                  rules_matched=[rule_id], normalized={})
        return self._record(decision, outcome="not_executed", **extra)

    @staticmethod
    def _fail_closed(req: ActionRequest) -> PolicyDecision:
        return PolicyDecision(
            request=req, decision=Decision.BLOCK, rule_id="fail-closed",
            reason="audit store unavailable; refusing to act unaudited",
            risk="high", rules_matched=["fail-closed"], normalized={},
        )

    @staticmethod
    def _deny_approval(decision: PolicyDecision, note: str) -> None:
        decision.decision = Decision.BLOCK
        decision.rules_matched.append("approval-denied")
        decision.rule_id = "approval-denied"
        decision.reason += f"; {note}"

    def _unrecorded_block(self, decision: PolicyDecision, action_id: str) -> dict:
        return {
            "correlation_id": decision.request.correlation_id,
            "action_id": action_id,
            "decision": Decision.BLOCK.value,
            "rule_id": "fail-closed",
            "reason": "audit intent unavailable; refusing to execute",
            "outcome": "not_executed",
        }

    def _record(self, decision: PolicyDecision, outcome: str,
                strict: bool = False, **extra) -> dict:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "correlation_id": decision.request.correlation_id,
            "actor": decision.request.actor,
            "tool": decision.request.tool,
            "spelled_params": self._audit_view(decision.request.tool,
                                               decision.request.params),
            "normalized": self._audit_view(decision.request.tool,
                                           decision.normalized),
            "decision": decision.decision.value,
            "rule_id": decision.rule_id,
            "rules_matched": decision.rules_matched,
            "risk": decision.risk,
            "reason": decision.reason,
            "outcome": outcome,
            **extra,
        }
        if self.audit is not None:
            try:
                self.audit.log(record)
            except Exception as e:
                # Before dispatch, strict mode blocks execution. After dispatch,
                # the durable intent remains and the outcome is unresolved.
                self._broken = True
                self.audit.poison(record)
                print(f"FAIL-CLOSED from now on: {e}", file=sys.stderr)
                if strict:
                    raise AuditUnavailable("audit intent unavailable") from e
        return record

    BODY_PREVIEW_CHARS = 64

    def _audit_view(self, tool: str, params):
        """What the audit log keeps of a request's params. The executor still
        gets the real ones; only the record is minimized."""
        if self.audit_verbose or not isinstance(params, dict):
            return params
        view = copy.deepcopy(params)
        if tool == "fs.write" and isinstance(view.get("content"), str):
            view["content"] = _digest(view["content"])
        if tool == "net.request" and isinstance(view.get("body"), str):
            body = view["body"]
            if len(body) > self.BODY_PREVIEW_CHARS:
                view["body"] = body[:self.BODY_PREVIEW_CHARS] + "…"
                view["body_digest"] = _digest(body)
        return view

    @staticmethod
    def health_check(config_path: str | Path = "policies/default.json",
                     base_dir: str | Path | None = None) -> list[str]:
        """Static sanity checks; raises on the first problem."""
        cfg = Config(config_path, base_dir=base_dir)
        ok = []
        if not cfg.sandbox_root.is_dir():
            raise RuntimeError(f"sandbox missing: {cfg.sandbox_root}")
        ok.append(f"sandbox: {cfg.sandbox_root}")
        for p in sorted(cfg.protected):
            if not p.exists():
                raise RuntimeError(f"protected path missing: {p}")
        ok.append(f"protected: {len(cfg.protected)} paths present")
        for d in cfg.writable_dirs:
            if not d.is_dir():
                raise RuntimeError(f"writable dir missing: {d}")
        ok.append(f"writable: {[str(d) for d in cfg.writable_dirs]}")
        if cfg.network_mode != "deny_all":
            raise RuntimeError(f"unexpected network mode: {cfg.network_mode}")
        ok.append("network: deny_all")
        ok.append(f"mcp registry: {sorted(cfg.mcp_registry)}")
        return ok


def _digest(text: str) -> dict:
    data = text.encode("utf-8", errors="replace")
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
