"""Local security gateway between an AI agent and its external capabilities.

Prototype only. Not production-ready. See README.md.
"""

from .credentials import AccessToken, CredentialError, TokenBroker
from .models import ActionRequest, Decision, PolicyDecision
from .gateway import Gateway

__all__ = ["AccessToken", "ActionRequest", "CredentialError", "Decision",
           "Gateway", "PolicyDecision", "TokenBroker"]
