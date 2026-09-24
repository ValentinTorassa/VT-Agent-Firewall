"""Canonical contract: ActionRequest -> PolicyDecision.

Every action the agent wants to perform is expressed as an ActionRequest.
The policy engine answers with a PolicyDecision. The executor only ever sees
the *normalized* params from the decision, never the spelled ones.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class ActionRequest:
    actor: str               # e.g. "agent"
    tool: str                # fs.read | fs.write | shell.run | net.request | mcp.call
    params: dict             # spelled params, treated as hostile input
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass
class PolicyDecision:
    request: ActionRequest
    decision: Decision
    rule_id: str             # primary rule that determined the outcome
    reason: str
    risk: str                # low | medium | high
    rules_matched: list[str]  # every rule that fired, in evaluation order
    normalized: dict          # canonical params the executor is allowed to use
