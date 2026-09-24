"""Human approval on the terminal.

The prompt shows the NORMALIZED action (canonical path, parsed argv) —
never the agent's own description of what it wants to do. Timeout or a
non-interactive stdin denies.
"""

from __future__ import annotations

import select
import sys

from .models import PolicyDecision


class TerminalApprover:
    def __init__(self, timeout_sec: int = 30):
        self.timeout_sec = timeout_sec

    def approve(self, decision: PolicyDecision) -> bool:
        print("\n=== HUMAN APPROVAL REQUIRED ===")
        print(f"rule:   {decision.rule_id} ({decision.reason})")
        print(f"tool:   {decision.request.tool}")
        print(f"action: {decision.normalized}")
        if not sys.stdin.isatty():
            print("non-interactive stdin: denied")
            return False
        print(f"approve? [y/N] ({self.timeout_sec}s timeout) ", end="", flush=True)
        ready, _, _ = select.select([sys.stdin], [], [], self.timeout_sec)
        if not ready:
            print("\ntimeout: denied")
            return False
        answer = sys.stdin.readline().strip().lower()
        return answer in ("y", "yes")
