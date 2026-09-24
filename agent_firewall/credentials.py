"""Delegated credentials: a token broker that the agent never talks to.

Model (RFC 8693 token exchange, in-process and simplified):

- The user delegates access once. The result is a Grant: which audiences and
  scopes were consented to, plus the refresh token that goes with them. The
  refresh token is created and kept inside the broker; no method returns it.
- For every tool call the gateway asks the broker to *exchange* that grant for
  an access token narrowed to exactly one audience and the scopes that one call
  needs, naming the agent as the actor. Tokens live minutes, not days.
- Resource servers validate tokens with `introspect` (RFC 7662 style): active,
  audience, scope, expiry, revocation.

What this does NOT do yet: sender-constrained tokens (DPoP). A stolen access
token is usable by anyone until it expires, which is why the lifetime is short.
"""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass, field

DEFAULT_TTL_SEC = 300


class CredentialError(Exception):
    """The broker refused to mint a token (no grant, revoked, or out of scope)."""


@dataclass
class Grant:
    subject: str
    audiences: dict[str, frozenset[str]]
    revoked: bool = False
    # Never exposed: repr=False keeps it out of logs, tracebacks and audit records.
    _refresh_token: str = field(default_factory=lambda: secrets.token_urlsafe(32),
                                repr=False)


@dataclass(frozen=True)
class AccessToken:
    value: str = field(repr=False)
    jti: str
    sub: str               # the user the agent acts for
    act: str               # the actor: which agent is calling
    aud: str               # the one resource server this token is valid for
    scope: frozenset[str]  # only what this call needs
    tool: str              # which tool call it was minted for
    exp: float

    def claims(self) -> dict:
        """What is safe to log: everything except the bearer value."""
        return {"jti": self.jti, "sub": self.sub, "act": self.act,
                "aud": self.aud, "scope": sorted(self.scope),
                "tool": self.tool, "exp": int(self.exp)}


class TokenBroker:
    def __init__(self, ttl_sec: int = DEFAULT_TTL_SEC, clock=time.time):
        self.ttl_sec = ttl_sec
        self.clock = clock
        self._grants: dict[str, Grant] = {}
        self._tokens: dict[str, AccessToken] = {}

    # -- delegation -------------------------------------------------------

    def delegate(self, subject: str, audiences: dict[str, set[str]]) -> None:
        """Record the user's consent. Replaces any earlier grant for them."""
        self._grants[subject] = Grant(
            subject=subject,
            audiences={aud: frozenset(scopes) for aud, scopes in audiences.items()})

    def revoke(self, subject: str) -> None:
        """Withdraw consent: no new tokens, and every live token stops working."""
        grant = self._grants.get(subject)
        if grant is not None:
            grant.revoked = True

    # -- token exchange -----------------------------------------------------

    def exchange(self, subject: str, actor: str, tool: str, audience: str,
                 scopes: set[str]) -> AccessToken:
        grant = self._grants.get(subject)
        if grant is None or grant.revoked:
            raise CredentialError(f"no active delegation from {subject!r}")
        if not scopes:
            raise CredentialError("refusing to mint a token with no scope")
        granted = grant.audiences.get(audience)
        if granted is None:
            raise CredentialError(f"{subject!r} never delegated access to {audience!r}")
        missing = set(scopes) - granted
        if missing:
            raise CredentialError(
                f"{subject!r} did not delegate {sorted(missing)} on {audience!r}")
        token = AccessToken(
            value=secrets.token_urlsafe(32), jti=uuid.uuid4().hex[:16],
            sub=subject, act=actor, aud=audience, scope=frozenset(scopes),
            tool=tool, exp=self.clock() + self.ttl_sec)
        self._tokens[token.value] = token
        return token

    # -- validation (the resource server's side) ------------------------------

    def introspect(self, value: str, audience: str, scope: str) -> dict:
        token = self._tokens.get(value)
        if token is None:
            return {"active": False, "reason": "unknown token"}
        grant = self._grants.get(token.sub)
        if grant is None or grant.revoked:
            return {"active": False, "reason": "delegation revoked"}
        if self.clock() >= token.exp:
            return {"active": False, "reason": "token expired"}
        if token.aud != audience:
            return {"active": False,
                    "reason": f"token is for {token.aud!r}, not {audience!r}"}
        if scope not in token.scope:
            return {"active": False,
                    "reason": f"scope {scope!r} not in {sorted(token.scope)}"}
        return {"active": True, **token.claims()}
