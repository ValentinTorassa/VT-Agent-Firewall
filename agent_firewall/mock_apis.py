"""Mock resource servers for the delegation demo and tests.

Each one behaves like a real API that trusts the broker: it accepts a bearer
token only if `introspect` says it is active, meant for this audience, and
carries the scope the operation needs. No network, no real side effects: calls
are recorded so tests can prove an operation never happened.
"""

from __future__ import annotations

from .credentials import TokenBroker


class MockApi:
    def __init__(self, audience: str, operations: dict[str, str],
                 broker: TokenBroker):
        self.audience = audience
        self.operations = operations   # operation -> required scope
        self.broker = broker
        self.calls: list[dict] = []    # what actually executed

    def call(self, bearer: str, operation: str, arguments: dict) -> dict:
        scope = self.operations.get(operation)
        if scope is None:
            raise PermissionError(f"{self.audience}: unknown operation {operation!r}")
        check = self.broker.introspect(bearer, self.audience, scope)
        if not check["active"]:
            raise PermissionError(f"{self.audience}: {check['reason']}")
        self.calls.append({"operation": operation, "arguments": arguments,
                           "sub": check["sub"], "act": check["act"],
                           "jti": check["jti"]})
        return {"ok": True, "operation": operation}


def demo_apis(broker: TokenBroker) -> dict[str, MockApi]:
    """The two services used in the talk: a calendar and a mailbox."""
    return {
        "calendar-api": MockApi("calendar-api", {
            "events.read": "calendar.read",
            "events.write": "calendar.write",
        }, broker),
        "mail-api": MockApi("mail-api", {
            "messages.read": "mail.read",
            "messages.send": "mail.send",
            "messages.delete": "mail.delete",
        }, broker),
    }
