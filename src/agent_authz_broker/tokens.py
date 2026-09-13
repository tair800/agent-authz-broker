"""Turning a bearer string into verified claims, or into the reason it is not one.

Two rules govern everything here.

**The signature is checked before anything else is read.** An unverified JWT is attacker-controlled
JSON; reading ``iss`` or ``aud`` out of it to decide *how* to verify would be trusting the thing
under verification. The issuer is resolved from a configured allow-list keyed on the unverified
header's ``kid`` only to *find a candidate key*, and the claim is then re-checked against the
verified payload.

**Audience is not checked here.** It would be easy to pass ``audience=`` to the JWT library and have
it refuse — and that is exactly what would make the naive/hardened comparison a lie, because the
naive policy would inherit an audience check it is supposed to lack. Verification answers *is this
token authentic*; `authz.py` answers *is it addressed to us and does it authorise this*. The split
is what makes the baseline honest.
"""

from __future__ import annotations

from typing import Any

import jwt
from jwt import PyJWK, PyJWKSet

from agent_authz_broker.domain import DelegationLink, DenialReason, TokenClaims

__all__ = ["ALGORITHMS", "verify_token"]

#: Asymmetric only. `none` and the HMAC family are absent: an HMAC-verified token would let anyone
#: holding the verification key mint one, which for a resource server is the same as no check.
ALGORITHMS = ["EdDSA", "RS256"]


def _scopes(raw: Any) -> frozenset[str]:
    """Read a scope claim in either spelling, and refuse to guess at anything else.

    RFC 8693 and OAuth spell this as a space-delimited string; plenty of issuers emit a list. Both
    are accepted. Anything else yields the empty set rather than a coerced one — an unreadable scope
    claim must not become a wide one.
    """
    if isinstance(raw, str):
        return frozenset(raw.split())
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        return frozenset(raw)
    return frozenset()


def _chain(payload: dict[str, Any]) -> tuple[tuple[DelegationLink, ...], DenialReason | None]:
    """Flatten RFC 8693 nested ``act`` claims into a root-first chain.

    ``act`` nests: the leaf's immediate delegator is the outermost ``act``, and *its* ``act`` is the
    one above. This walks to the root and reverses, so index 0 is the root principal.

    A malformed chain is refused rather than skipped. Silently ignoring an unparsable link would
    drop it out of the intersection, which turns a broken delegation into a *wider* authority —
    precisely backwards, and exactly the kind of fail-open a malicious client would aim for.
    """
    links: list[DelegationLink] = []
    node = payload.get("act")
    depth = 0
    while node is not None:
        if not isinstance(node, dict) or not isinstance(node.get("sub"), str):
            return (), "delegation_malformed"
        depth += 1
        if depth > 10:
            return (), "delegation_malformed"
        links.append(DelegationLink(subject=node["sub"], scopes=_scopes(node.get("scope"))))
        node = node.get("act")
    links.reverse()
    return tuple(links), None


def verify_token(
    token: str,
    *,
    jwks_by_issuer: dict[str, PyJWKSet],
    leeway: int = 0,
) -> TokenClaims | DenialReason:
    """Verify a bearer token's authenticity and return its claims, or why it is not authentic.

    Args:
        token: The raw bearer string.
        jwks_by_issuer: Trusted issuer -> its key set. An issuer absent from this mapping is
            unknown, and an unknown issuer is refused before any key is tried.
        leeway: Clock skew allowance in seconds, for expiry only.

    Returns:
        :class:`TokenClaims` when authentic, otherwise the :data:`DenialReason`. A reason rather
        than an exception because refusal is a normal outcome here, and an exception would tempt a
        caller into a bare ``except`` that swallows the difference between *expired* and *forged*.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return "token_malformed"

    # The unverified issuer selects a candidate key set and nothing else. It is re-read from the
    # verified payload below and compared, so a lie here buys an attacker a failed signature.
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return "token_malformed"
    claimed_issuer = unverified.get("iss")
    if not isinstance(claimed_issuer, str) or claimed_issuer not in jwks_by_issuer:
        return "issuer_unknown"

    key: PyJWK | None = None
    for candidate in jwks_by_issuer[claimed_issuer].keys:
        if candidate.key_id == header.get("kid"):
            key = candidate
            break
    if key is None:
        return "signature_invalid"

    try:
        payload = jwt.decode(
            token,
            key=key,
            algorithms=ALGORITHMS,
            issuer=claimed_issuer,
            leeway=leeway,
            # Audience is checked in authz.py, not here. See the module docstring: doing it here
            # would give the naive baseline an audience check it is defined not to have.
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": False,
                "require": ["iss", "sub", "aud", "exp", "iat", "jti"],
            },
        )
    except jwt.ExpiredSignatureError:
        return "token_expired"
    except jwt.InvalidIssuerError:
        return "issuer_unknown"
    except jwt.MissingRequiredClaimError:
        return "token_malformed"
    except jwt.InvalidSignatureError:
        return "signature_invalid"
    except jwt.PyJWTError:
        return "signature_invalid"

    audience = payload["aud"]
    audiences = (audience,) if isinstance(audience, str) else tuple(audience)
    if not all(isinstance(item, str) for item in audiences):
        return "token_malformed"

    chain, failure = _chain(payload)
    if failure is not None:
        return failure

    return TokenClaims(
        issuer=payload["iss"],
        subject=payload["sub"],
        audience=audiences,
        expires_at=int(payload["exp"]),
        issued_at=int(payload["iat"]),
        token_id=str(payload["jti"]),
        scopes=_scopes(payload.get("scope")),
        chain=chain,
    )
