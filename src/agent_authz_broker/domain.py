"""The vocabulary of the authorization decision. Deliberately small.

Every type here exists because ADR-001's threat model needs it, and nothing here exists because it
looked like good modelling. The one idea worth stating up front is the direction of trust:
:class:`TokenClaims` is **what the client asserted**, and :class:`AuthzResult` is **what the server
concluded**. They are different types on purpose, so that no code can drift into treating a claim as
a conclusion — the leaf's ``scope`` claim is the single most dangerous field in this system, and it
lives on the untrusted side of that line.
"""

from __future__ import annotations

import enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "IRREVERSIBLE_TOOLS",
    "TOOL_SCOPES",
    "AuthzResult",
    "Decision",
    "DelegationLink",
    "DenialReason",
    "TokenClaims",
]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Decision(enum.StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"


#: Every way this server can refuse, as a closed set.
#:
#: A ``Literal`` rather than free text so a reason cannot be invented at a call site, and so the
#: console, the audit table and the tests all name refusals identically. A denial whose reason is
#: a sentence somebody typed is a denial nobody can aggregate or test against.
DenialReason = Literal[
    "signature_invalid",
    "issuer_unknown",
    "token_expired",
    "token_malformed",
    "audience_mismatch",
    "insufficient_effective_scope",
    "delegation_malformed",
    "approval_required",
    "approval_expired",
    "approval_already_consumed",
    "unknown_tool",
]


class DelegationLink(_Frozen):
    """One hop in the chain: who delegated, and what they held when they did.

    ``scopes`` is what *that principal* had. The attenuation rule intersects these, so a link with a
    narrow set narrows everything below it however wide the leaf's own claim is.
    """

    subject: str
    scopes: frozenset[str]


class TokenClaims(_Frozen):
    """What the presented token asserts. **Untrusted until the server has checked it.**

    Constructed only by the token verifier, after the signature and issuer are confirmed — but the
    *content* is still the client's assertion. ``scopes`` in particular is a claim about authority,
    not authority itself.
    """

    issuer: str
    subject: str
    audience: tuple[str, ...]
    expires_at: int
    issued_at: int
    token_id: str
    scopes: frozenset[str]
    #: The delegation chain, root first. Empty for a token issued directly to its subject.
    chain: tuple[DelegationLink, ...] = ()

    @property
    def is_delegated(self) -> bool:
        return bool(self.chain)


class AuthzResult(_Frozen):
    """What the server concluded, with the evidence it concluded it from.

    ``effective_scopes`` is published even on a denial because it is the answer to the question a
    reader actually has — *what did it think I had?* — and because the console renders the
    attenuation rather than asserting it happened.
    """

    decision: Decision
    reason: DenialReason | None = None
    effective_scopes: frozenset[str] = frozenset()
    subject: str | None = None
    token_id: str | None = None
    #: Each link's contribution, root first, for the console's chain view.
    chain_scopes: tuple[frozenset[str], ...] = ()
    required_scope: str | None = None
    policy: str = Field(default="hardened", description="Which verifier produced this.")

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOWED


#: The scope each tool requires. One line per tool, in one place, so that "which scope does this
#: need" is never answered by reading a handler.
TOOL_SCOPES: dict[str, str] = {
    "read_account": "account:read",
    "flag_account": "account:flag",
    "issue_credit": "credit:issue",
}

#: Tools whose effect cannot be undone, and which therefore require a recorded human approval.
#:
#: `flag_account` is deliberately **not** here: it enqueues a review for a person rather than
#: acting. The blueprint is explicit that the fraud-adjacent action must never auto-block, and a
#: tool that only ever creates work for a human is not irreversible.
IRREVERSIBLE_TOOLS: frozenset[str] = frozenset({"issue_credit"})
