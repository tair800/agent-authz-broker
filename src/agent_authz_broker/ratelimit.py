"""A ceiling on how often one subject may invoke one tool. Counted in PostgreSQL.

**What is limited, exactly:** `(subject, tool, fixed 60-second window)`. The subject is the one the
token verified to — never one the caller supplied — so a caller cannot move itself into a fresh
bucket by asking differently. Two subjects never share a bucket and neither do two tools, because
the bucket *is* the primary key and there is no row for them to share.

**This is not DDoS protection and is not offered as any.** It bounds how often an *authenticated*
caller can reach the decision path. Unauthenticated floods are refused earlier, by the token
verifier, and nothing here helps with volume that never presents a usable token — that is a
platform concern, not an application one.

**Fixed window, and the weakness stated rather than rounded away.** A caller may spend a whole
allowance at the end of one window and a whole allowance at the start of the next, so the true worst
case across an arbitrary 60 seconds is **twice** the limit. A sliding window costs a row per request
to fix that; this costs one row per bucket. The bound this module promises is therefore *at most
`limit` per fixed window*, and that is the bound the tests assert.

**Why the database and not the process.** An in-process counter states a bound per worker: "30 per
minute" behind N workers is 30 x N, and the deployment that exposes it is the one nobody ran. The
same reasoning as one-approval-one-effect, for the same reason -- a guarantee that depends on how
many processes happen to be running is a guarantee that fails silently when that changes.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from agent_authz_broker.db.models import RateLimitCounter

__all__ = ["WINDOW_SECONDS", "consume_quota", "window_start"]

#: The fixed window, in seconds. One minute, because the limit is expressed per minute and a window
#: that does not match the unit it is quoted in is an invitation to misread the bound.
WINDOW_SECONDS = 60


def window_start(moment: dt.datetime) -> dt.datetime:
    """The start of the fixed window ``moment`` falls in.

    Truncation rather than "now minus 60 seconds": every caller in the same minute must land on the
    same bucket, or each one gets a private window and the limit means nothing.
    """
    epoch = int(moment.timestamp())
    return dt.datetime.fromtimestamp(epoch - (epoch % WINDOW_SECONDS), tz=dt.UTC)


async def consume_quota(
    session: AsyncSession,
    *,
    subject: str,
    tool: str,
    now: dt.datetime,
) -> int:
    """Claim one unit from this subject's bucket for this tool, and report which unit it is.

    One statement. ``INSERT … ON CONFLICT DO UPDATE … RETURNING`` is atomic in PostgreSQL, so
    concurrent callers are serialised by the row lock the upsert takes and each receives a distinct
    position — never the same number twice. Read-then-write in Python would hand two racing callers
    the same count and admit both past the ceiling, which is precisely the bug the concurrency test
    plants for.

    Args:
        session: The caller's session. The claim must share the transaction that goes on to write
            the effect, so that a rolled-back call does not spend quota it never used.
        subject: The **verified** subject. Never a value from a tool argument.
        tool: Which tool is being called.
        now: Injected so a test can pin the window rather than sleeping through one.

    Returns:
        This call's position in the window, counting from 1. The caller compares it with the
        configured limit; this function takes no view on what the limit should be, so that the
        decision and the counting are not tangled in one place.
    """
    statement = (
        insert(RateLimitCounter)
        .values(subject=subject, tool=tool, window_start=window_start(now), count=1)
        .on_conflict_do_update(
            index_elements=["subject", "tool", "window_start"],
            set_={"count": RateLimitCounter.count + 1},
        )
        .returning(RateLimitCounter.count)
    )
    return int((await session.execute(statement)).scalar_one())
