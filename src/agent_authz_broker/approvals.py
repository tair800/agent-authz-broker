"""Durable approvals, and the one-time consumption that makes replay impossible.

The whole of scenario D lives in :func:`consume_approval`, and it is four lines of SQL rather than
any Python:

    UPDATE approval SET consumed_at = now()
     WHERE approval_id = :id AND consumed_at IS NULL
    RETURNING approval_id

``consumed_at IS NULL`` in the ``WHERE`` clause is the entire mechanism. PostgreSQL takes a row lock
for the duration of the update, so of two concurrent statements one matches a row and one matches
nothing — and the one that matched nothing learns this from ``rowcount``, not from having asked
first. There is no read-then-write window to lose a race in.

**Why not an in-process lock.** `asyncio.Lock` or `threading.Lock` would pass the concurrency test
exactly as written and fail the moment the service runs two workers, two containers, or one of each
during a rolling deploy. The test would still be green. ADR-001 therefore requires the mechanism to
be in the database, and this module has no lock in it.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agent_authz_broker.db.models import Approval, new_id

__all__ = [
    "ApprovalLookup",
    "consume_approval",
    "create_approval",
    "find_matching_approval",
    "get_approval",
    "list_approvals",
]


class ApprovalLookup:
    """The result of asking whether a matching approval exists, and why not when it does not.

    Three outcomes rather than an optional: *found*, *none matches*, and *one matches but it has
    expired*. Collapsing the last two into ``None`` would lose the distinction the console and the
    audit trail both need — "nobody approved this" and "somebody approved this yesterday" are
    different events, and only one of them suggests asking the same person again.
    """

    __slots__ = ("approval", "expired")

    def __init__(self, approval: Approval | None, *, expired: bool = False) -> None:
        self.approval = approval
        self.expired = expired


async def create_approval(
    session: AsyncSession,
    *,
    subject: str,
    tool: str,
    account: str,
    amount: int,
    approved_by: str,
    ttl_seconds: int = 900,
    now: dt.datetime | None = None,
) -> Approval:
    """Record a human's decision.

    Deliberately not reachable from MCP. A human calls this through the console API; the agent can
    ask for an approval to be created but cannot create one, which is the difference between
    requesting authority and minting it.
    """
    moment = now or dt.datetime.now(tz=dt.UTC)
    approval = Approval(
        approval_id=new_id("apr"),
        subject=subject,
        tool=tool,
        account=account,
        amount=amount,
        approved_by=approved_by,
        expires_at=moment + dt.timedelta(seconds=ttl_seconds),
    )
    session.add(approval)
    await session.flush()
    return approval


async def find_matching_approval(
    session: AsyncSession,
    *,
    subject: str,
    tool: str,
    account: str,
    amount: int,
    now: dt.datetime | None = None,
) -> ApprovalLookup:
    """Find an unconsumed approval bound to exactly this act.

    Every column in the filter is a binding ADR-001 requires, and the query is the enforcement: an
    approval for another subject, another tool, another account or another amount simply does not
    match, so there is no code path in which one is "close enough".

    Expiry is evaluated *after* the match rather than inside it, so that an expired approval can be
    reported as ``approval_expired`` instead of disappearing into ``approval_required``. A person
    who approved something two hours ago is owed a more useful answer than "no".
    """
    moment = now or dt.datetime.now(tz=dt.UTC)
    rows = (
        await session.execute(
            select(Approval)
            .where(
                Approval.subject == subject,
                Approval.tool == tool,
                Approval.account == account,
                Approval.amount == amount,
                Approval.consumed_at.is_(None),
            )
            .order_by(Approval.expires_at.desc())
        )
    ).scalars()

    expired_seen = False
    for approval in rows:
        if approval.expires_at > moment:
            return ApprovalLookup(approval)
        expired_seen = True
    return ApprovalLookup(None, expired=expired_seen)


async def consume_approval(
    session: AsyncSession, approval_id: str, *, now: dt.datetime | None = None
) -> bool:
    """Spend an approval, at most once, ever.

    Args:
        session: The session the caller will also write the effect in. Consumption and effect must
            share one transaction — consuming in a separate transaction would leave a window where
            the approval is spent and the effect never happened.
        approval_id: The approval to spend.
        now: Injected so a test can pin the timestamp.

    Returns:
        True if this caller won it. False if it was already consumed, which is the loser's answer in
        a race and must be treated as a refusal rather than retried.
    """
    moment = now or dt.datetime.now(tz=dt.UTC)
    result = await session.execute(
        update(Approval)
        .where(Approval.approval_id == approval_id, Approval.consumed_at.is_(None))
        .values(consumed_at=moment)
        .returning(Approval.approval_id)
    )
    return result.scalar_one_or_none() is not None


async def get_approval(session: AsyncSession, approval_id: str) -> Approval | None:
    return await session.get(Approval, approval_id)


async def list_approvals(session: AsyncSession, *, limit: int = 100) -> list[Approval]:
    rows = await session.execute(select(Approval).order_by(Approval.created_at.desc()).limit(limit))
    return list(rows.scalars())
