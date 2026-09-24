"""Gateway orchestration: request -> policy -> (approve?) -> audit -> execute.

Ordering invariants:
- Denied actions are audited BEFORE returning; they never execute.
- Allowed actions execute and are then audited with their outcome. If the
  audit write fails, the gateway poisons itself and denies everything
  afterwards (fail-closed).
- If the audit store cannot even be opened at startup, every request is
  denied with `fail-closed`.
"""

from __future__ import annotations

import sys
import time
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
                 approver=None, base_dir: str | Path | None = None):
        self.config = Config(config_path, base_dir=base_dir)
        self.policy = PolicyEngine(self.config)
        self.executor = Executor()
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
        if self._broken:
            decision = PolicyDecision(
                request=req, decision=Decision.BLOCK, rule_id="fail-closed",
                reason="audit store unavailable; refusing to act unaudited",
                risk="high", rules_matched=["fail-closed"], normalized={},
            )
            return self._record(decision, outcome="not_executed")

        decision = self.policy.evaluate(req, self.session)

        if decision.decision == Decision.REQUIRE_APPROVAL:
            if self.approver.approve(decision):
                decision.decision = Decision.ALLOW
                decision.rules_matched.append("approval-granted")
            else:
                decision.decision = Decision.BLOCK
                decision.rules_matched.append("approval-denied")
                decision.rule_id = "approval-denied"
                decision.reason += "; human denied or approval timed out"

        if decision.decision == Decision.BLOCK:
            # Audit-first: the attempt is recorded before we return.
            return self._record(decision, outcome="not_executed")

        try:
            result = self.executor.execute(decision.request.tool,
                                           decision.normalized)
            return self._record(decision, outcome="executed",
                                result_preview=str(result)[:200])
        except Exception as e:  # executor errors are audited, not hidden
            return self._record(decision, outcome="error", error=str(e))

    def _record(self, decision: PolicyDecision, outcome: str, **extra) -> dict:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "correlation_id": decision.request.correlation_id,
            "actor": decision.request.actor,
            "tool": decision.request.tool,
            "spelled_params": decision.request.params,
            "normalized": decision.normalized,
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
            except OSError as e:
                # We acted but could not audit: poison the gateway.
                self._broken = True
                self.audit.poison(record)
                print(f"FAIL-CLOSED from now on: {e}", file=sys.stderr)
        return record

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
