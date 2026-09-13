"""The authorization decision. Deterministic, pure, and the only place authority is computed.

Two policies run through one function, over one set of inputs, so the comparison the README
publishes is a difference in the *policy* and not a difference in the harness:

* :data:`NAIVE` — verify the signature, check expiry, read the leaf's ``scope`` claim. This is
  what a competent engineer writes when the brief is "check the token", and it is not a straw man:
  it is the check most guidance implies is enough. It has no opinion about audience and none about
  who delegated what.
* :data:`HARDENED` — additionally require the audience to name *this* server, and compute effective
  scope by intersecting the whole delegation chain.

**No database, no clock beyond the one passed in, no model.** Approval lives one layer up in
`effects.py`, because approval is durable state and this module is a function. Keeping it pure
is what lets the adversarial suite enumerate token shapes without a database at all.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_authz_broker.domain import (
    DENIAL_REASONS,
    TOOL_SCOPES,
    AuthzResult,
    Decision,
    DenialReason,
    TokenClaims,
)

# `Decision` is re-exported because `authz` is where a caller forms a decision; making them import
# the enum from `domain` while calling `authorize` here would be a seam with no meaning behind it.
__all__ = ["HARDENED", "NAIVE", "Decision", "Policy", "authorize", "effective_scopes"]


@dataclass(frozen=True, slots=True)
class Policy:
    """A named set of checks, so that "which verifier said this" is data rather than a code path."""

    name: str
    check_audience: bool
    attenuate_chain: bool


#: What this repository argues is the minimum a resource server must do.
HARDENED = Policy(name="hardened", check_audience=True, attenuate_chain=True)

#: The predeclared baseline from ADR-001. Signature and expiry only — both real checks, both passed
#: by every attack in the suite, which is the entire point.
NAIVE = Policy(name="naive", check_audience=False, attenuate_chain=False)


def effective_scopes(claims: TokenClaims, *, attenuate: bool) -> frozenset[str]:
    """The authority the server is willing to believe this token carries.

    Under attenuation this is the intersection of the leaf's claim with every link in the chain:

        effective = leaf ∩ act[0] ∩ act[1] ∩ … ∩ root

    Intersection is the whole rule. It is monotone — adding a hop can only remove authority — and
    there is deliberately no branch anywhere that puts a scope back. A scope missing from **any**
    ancestor is missing from the result no matter how loudly the leaf claims it, which is the
    difference between delegation and impersonation.

    Args:
        claims: The verified-but-untrusted claims.
        attenuate: False reproduces the naive policy, which reads the leaf and stops.

    Returns:
        The effective scope set.
    """
    if not attenuate:
        return claims.scopes
    granted = claims.scopes
    for link in claims.chain:
        granted &= link.scopes
    return granted


def authorize(
    policy: Policy,
    claims: TokenClaims | DenialReason,
    *,
    tool: str,
    audience: str | None = None,
    now: int | None = None,
) -> AuthzResult:
    """Decide whether this token authorises this tool, under this policy.

    ``claims`` accepts a :data:`DenialReason` as well, because a token that failed to verify has no
    claims to reason about and the caller should not have to invent some. Both policies refuse
    there: the naive verifier is naive about audience and delegation, not about cryptography.

    Args:
        policy: :data:`HARDENED` or :data:`NAIVE`.
        claims: Verified claims, or the reason verification failed.
        tool: The tool being called.
        audience: This server's own identifier. Required when the policy checks audience — passed in
            rather than imported so that a test cannot accidentally assert against the same constant
            the code reads.
        now: Unix seconds, for expiry. Injected so expiry-edge tests are not flaky.

    Returns:
        The decision, the reason when refused, and the effective scopes either way.
    """
    if isinstance(claims, str):
        # A raw bearer string is not a denial reason. Accepting any `str` here let a caller pass a
        # token where claims belong and receive a confident "denied" with the token as the reason --
        # fail-closed, but unreadable. The check costs nothing and names the mistake.
        if claims not in DENIAL_REASONS:
            raise TypeError(
                "authorize() takes verified claims or a DenialReason, not a raw token; "
                "call tokens.verify_token first"
            )
        return AuthzResult(decision=Decision.DENIED, reason=claims, policy=policy.name)

    required = TOOL_SCOPES.get(tool)
    if required is None:
        return AuthzResult(
            decision=Decision.DENIED,
            reason="unknown_tool",
            subject=claims.subject,
            token_id=claims.token_id,
            policy=policy.name,
        )

    granted = effective_scopes(claims, attenuate=policy.attenuate_chain)
    partial = AuthzResult(
        decision=Decision.DENIED,
        effective_scopes=granted,
        subject=claims.subject,
        token_id=claims.token_id,
        chain_scopes=tuple(link.scopes for link in claims.chain),
        required_scope=required,
        policy=policy.name,
    )

    if now is not None and claims.expires_at <= now:
        return partial.model_copy(update={"reason": "token_expired"})

    # Audience before scope, deliberately. A token minted for another server is not "a token
    # with the wrong permissions" -- it is not addressed to this server at all, and reporting it
    # as a scope problem would invite somebody to fix it by widening a scope.
    if policy.check_audience:
        if audience is None:
            raise ValueError("a policy that checks audience needs this server's own identifier")
        if audience not in claims.audience:
            return partial.model_copy(update={"reason": "audience_mismatch"})

    if required not in granted:
        return partial.model_copy(update={"reason": "insufficient_effective_scope"})

    return partial.model_copy(update={"decision": Decision.ALLOWED, "reason": None})
