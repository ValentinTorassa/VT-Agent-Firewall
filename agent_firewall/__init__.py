"""Local security gateway between an AI agent and its external capabilities.

Prototype only. Not production-ready. See README.md.
"""

from .models import ActionRequest, Decision, PolicyDecision
from .gateway import Gateway

__all__ = ["ActionRequest", "Decision", "PolicyDecision", "Gateway"]
