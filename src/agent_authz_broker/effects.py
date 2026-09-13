"""The one path from a bearer token to an irreversible effect. There is deliberately no other.

Every MCP tool calls :func:`call_tool` and none of them re-implements any part of this. That is not
layering for its own sake: the moment a second path exists, the audit trail becomes a partial record
and a reviewer can no longer answer "could this have happened another way" by reading one function.

The order of the gates is the argument:

    verify signature -> audience -> effective scope -> approval -> consume -> effect

Each one is cheaper to evaluate than the next and refuses more traffic, but that is a side benefit.
The reason for the order is that each gate's answer is only meaningful once the previous one holds —
asking "does this token have the scope" about a token minted for another server is asking the wrong
question, and reporting the answer would invite somebody to fix an audience bug by widening a scope.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from jwt import PyJWKSet
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from agent_authz_broker.approvals import consume_approval, find_matching_approval
from agent_authz_broker.authz import HARDENED, Policy, authorize
from agent_authz_broker.db.models import AuditEvent, IrreversibleEffect, new_id
from agent_authz_broker.domain import IRREVERSIBLE_TOOLS, Decision, DenialReason
from agent_authz_broker.tokens import verify_token

__all__ = ["ToolOutcome", "call_tool"]


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    """What happened, and enough of why for the console and the audit trail to render it."""

    decision: Decision
    reason: DenialReason | None = None
    effective_scopes: frozenset[str] = frozenset()
    chain_scopes: tuple[frozenset[str], ...] = ()
    required_scope: str | None = None
    subject: str | None = None
    approval_id: str | None = None
    effect_id: str | None = None
    audit_id: str = ""
    policy: str = "hardened"
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOWED


async def _record(
    session: AsyncSession,
    *,
    tool: str,
    policy: str,
    decision: Decision,
    reason: DenialReason | None,
    subject: str | None,
    token_id: str | None,
    effective: frozenset[str],
    required: str | None,
    approval_id: str | None = None,
    effect_id: str | None = None,
) -> str:
    """Append one audit row. Called on every outcome, including every refusal."""
    event = AuditEvent(
        audit_id=new_id("aud"),
        subject=subject,
        token_id=token_id,
        tool=tool,
        policy=policy,
        decision=str(decision),
        reason=reason,
        required_scope=required,
        effective_scopes=" ".join(sorted(effective)),
        approval_id=approval_id,
        effect_id=effect_id,
    )
    session.add(event)
    await session.flush()
    return event.audit_id


async def call_tool(
    engine: AsyncEngine,
    *,
    token: str,
    tool: str,
    arguments: dict[str, Any],
    authority_jwks: dict[str, PyJWKSet],
    audience: str,
    policy: Policy = HARDENED,
    now: dt.datetime | None = None,
) -> ToolOutcome:
    """Run one tool call through every gate, and write at most one irreversible effect.

    Args:
        engine: The database. Consumption and effect share one transaction here.
        token: The raw bearer string the client presented. Untrusted.
        tool: Which tool. Not taken from the token.
        arguments: The tool's arguments. **Untrusted, and deliberately never consulted for
            authority** — there is no argument that can assert an approval, and the approval lookup
            below is keyed on the *verified* subject rather than on anything the caller sent.
        authority_jwks: Trusted issuer -> key set.
        audience: This server's own identity, from configuration.
        policy: HARDENED in production. NAIVE exists so the demonstration can run the same scenarios
            through the baseline and count what it would have permitted.
        now: Injected for deterministic expiry tests.

    Returns:
        The outcome. An effect id is present only when a row was actually written.
    """
    moment = now or dt.datetime.now(tz=dt.UTC)
    claims = verify_token(token, jwks_by_issuer=authority_jwks)
    verdict = authorize(
        policy,
        claims,
        tool=tool,
        audience=audience if policy.check_audience else None,
        now=int(moment.timestamp()),
    )

    async with AsyncSession(engine) as session, session.begin():
        token_id = verdict.token_id

        if not verdict.allowed:
            audit = await _record(
                session,
                tool=tool,
                policy=policy.name,
                decision=verdict.decision,
                reason=verdict.reason,
                subject=verdict.subject,
                token_id=token_id,
                effective=verdict.effective_scopes,
                required=verdict.required_scope,
            )
            return ToolOutcome(
                decision=verdict.decision,
                reason=verdict.reason,
                effective_scopes=verdict.effective_scopes,
                chain_scopes=verdict.chain_scopes,
                required_scope=verdict.required_scope,
                subject=verdict.subject,
                audit_id=audit,
                policy=policy.name,
            )

        # Reversible tools stop here: they are authorised by scope alone, which is the whole reason
        # `flag_account` enqueues a review instead of acting.
        if tool not in IRREVERSIBLE_TOOLS:
            audit = await _record(
                session,
                tool=tool,
                policy=policy.name,
                decision=Decision.ALLOWED,
                reason=None,
                subject=verdict.subject,
                token_id=token_id,
                effective=verdict.effective_scopes,
                required=verdict.required_scope,
            )
            return ToolOutcome(
                decision=Decision.ALLOWED,
                effective_scopes=verdict.effective_scopes,
                chain_scopes=verdict.chain_scopes,
                required_scope=verdict.required_scope,
                subject=verdict.subject,
                audit_id=audit,
                policy=policy.name,
                detail={"note": "reversible tool; no approval required"},
            )

        account = str(arguments.get("account", ""))
        amount = int(arguments.get("amount", 0))
        assert verdict.subject is not None  # noqa: S101 - an allowed verdict always carries one

        lookup = await find_matching_approval(
            session,
            subject=verdict.subject,
            tool=tool,
            account=account,
            amount=amount,
            now=moment,
        )
        if lookup.approval is None:
            reason: DenialReason = "approval_expired" if lookup.expired else "approval_required"
            audit = await _record(
                session,
                tool=tool,
                policy=policy.name,
                decision=Decision.DENIED,
                reason=reason,
                subject=verdict.subject,
                token_id=token_id,
                effective=verdict.effective_scopes,
                required=verdict.required_scope,
            )
            return ToolOutcome(
                decision=Decision.DENIED,
                reason=reason,
                effective_scopes=verdict.effective_scopes,
                chain_scopes=verdict.chain_scopes,
                required_scope=verdict.required_scope,
                subject=verdict.subject,
                audit_id=audit,
                policy=policy.name,
            )

        approval_id = lookup.approval.approval_id

        # The race is decided here, by the database. The loser of `consume_approval` must refuse:
        # retrying would be asking for an approval that has, correctly, already been spent.
        if not await consume_approval(session, approval_id, now=moment):
            audit = await _record(
                session,
                tool=tool,
                policy=policy.name,
                decision=Decision.DENIED,
                reason="approval_already_consumed",
                subject=verdict.subject,
                token_id=token_id,
                effective=verdict.effective_scopes,
                required=verdict.required_scope,
                approval_id=approval_id,
            )
            return ToolOutcome(
                decision=Decision.DENIED,
                reason="approval_already_consumed",
                effective_scopes=verdict.effective_scopes,
                chain_scopes=verdict.chain_scopes,
                required_scope=verdict.required_scope,
                subject=verdict.subject,
                approval_id=approval_id,
                audit_id=audit,
                policy=policy.name,
            )

        effect = IrreversibleEffect(
            effect_id=new_id("eff"),
            approval_id=approval_id,
            subject=verdict.subject,
            tool=tool,
            account=account,
            amount=amount,
            token_id=token_id or "",
        )
        session.add(effect)
        try:
            await session.flush()
        except IntegrityError:
            # The UNIQUE constraint on approval_id refused a second effect. Reaching this means the
            # conditional UPDATE above was somehow bypassed, so the constraint is the backstop that
            # actually holds -- and the request must still fail closed.
            await session.rollback()
            raise

        audit = await _record(
            session,
            tool=tool,
            policy=policy.name,
            decision=Decision.ALLOWED,
            reason=None,
            subject=verdict.subject,
            token_id=token_id,
            effective=verdict.effective_scopes,
            required=verdict.required_scope,
            approval_id=approval_id,
            effect_id=effect.effect_id,
        )
        return ToolOutcome(
            decision=Decision.ALLOWED,
            effective_scopes=verdict.effective_scopes,
            chain_scopes=verdict.chain_scopes,
            required_scope=verdict.required_scope,
            subject=verdict.subject,
            approval_id=approval_id,
            effect_id=effect.effect_id,
            audit_id=audit,
            policy=policy.name,
            detail={"account": account, "amount": amount},
        )
