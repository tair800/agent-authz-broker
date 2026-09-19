"""The ceiling on how often one verified subject may call one tool.

`PORTFOLIO_BLUEPRINT.md` lists rate limiting among project 4's major features, and `rate-limit
tests` among its tests; `SKILL_MATRIX.md` marks it `○` — *present and real, but secondary* —
with project 4 as its only home. So it is required, and required to be **proven**, but it is
not load-bearing to the security claim: no rate limit stops a caller holding authority it
should not have. That is the audience check, the attenuation rule and the approval gate, and
none of them is weakened or replaced by anything here.

Every count below is `SELECT count(*) FROM irreversible_effect`. Two of these tests would pass
against a limiter that did nothing except return the right word, which is why the effect counts are
here at all.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from typing import Any

import pytest

from agent_authz_broker.ratelimit import WINDOW_SECONDS, window_start

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

LIMIT = 3
ACCOUNT = "ACC-1041"
AMOUNT = 500


async def _call(lab: Any, token: str, *, now: dt.datetime | None = None) -> Any:
    return await lab.call_issue_credit(
        token=token, account=ACCOUNT, amount=AMOUNT, now=now, rate_limit_per_minute=LIMIT
    )


async def test_below_the_limit_the_call_succeeds(lab: Any) -> None:
    """The permitted path is unaffected, which is the first thing a limiter can break."""
    approval = await lab.approve(
        subject="agent-7", tool="issue_credit", account=ACCOUNT, amount=AMOUNT
    )
    token = lab.valid_token(subject="agent-7")

    result = await _call(lab, token)

    assert result.decision.value == "allowed", result.reason
    assert await lab.effect_count() == 1
    assert await lab.approval_is_consumed(approval.approval_id) is True


async def test_above_the_limit_the_call_is_denied_and_writes_no_effect(lab: Any) -> None:
    """The bound, and the thing that makes it worth having.

    Each call needs its own approval, so that what stops the fourth one is the ceiling and not an
    approval already spent — a limiter can look like it works when the approval gate is what is
    actually refusing.
    """
    for _ in range(LIMIT + 1):
        await lab.approve(subject="agent-7", tool="issue_credit", account=ACCOUNT, amount=AMOUNT)
    token = lab.valid_token(subject="agent-7")

    outcomes = [await _call(lab, token) for _ in range(LIMIT + 1)]

    assert [o.decision.value for o in outcomes[:LIMIT]] == ["allowed"] * LIMIT
    assert outcomes[LIMIT].decision.value == "denied"
    assert outcomes[LIMIT].reason == "rate_limited"
    assert await lab.effect_count() == LIMIT, "a refused call still moved money"


async def test_independent_subjects_do_not_share_a_bucket(lab: Any) -> None:
    """The bucket is (subject, tool, window), so one caller cannot exhaust another's allowance.

    Without this, the limiter is a denial-of-service anyone can aim at anyone: spray a victim's
    subject at a tool and the victim is locked out.
    """
    for _ in range(LIMIT + 1):
        await lab.approve(subject="agent-7", tool="issue_credit", account=ACCOUNT, amount=AMOUNT)
    await lab.approve(subject="agent-9", tool="issue_credit", account=ACCOUNT, amount=AMOUNT)

    busy = lab.valid_token(subject="agent-7")
    for _ in range(LIMIT + 1):
        await _call(lab, busy)
    assert (await _call(lab, busy)).reason == "rate_limited"

    quiet = lab.valid_token(subject="agent-9")
    result = await _call(lab, quiet)

    assert result.decision.value == "allowed", result.reason


async def test_the_window_recovers(lab: Any) -> None:
    """A new window is a new allowance. Pinned rather than slept through.

    `now` is injected, so this asserts the window arithmetic instead of asserting that a test can
    wait sixty seconds — which would be the same assertion made slowly and flakily.
    """
    for _ in range(LIMIT + 2):
        await lab.approve(subject="agent-7", tool="issue_credit", account=ACCOUNT, amount=AMOUNT)
    token = lab.valid_token(subject="agent-7")

    first = dt.datetime.now(tz=dt.UTC)
    for _ in range(LIMIT):
        await _call(lab, token, now=first)
    assert (await _call(lab, token, now=first)).reason == "rate_limited"

    later = window_start(first) + dt.timedelta(seconds=WINDOW_SECONDS + 1)
    recovered = await _call(lab, token, now=later)

    assert recovered.decision.value == "allowed", recovered.reason


async def test_concurrent_calls_cannot_exceed_the_documented_bound(lab: Any) -> None:
    """The bound holds under a race, which is the only condition it is interesting under.

    Read-then-write in Python hands two racing callers the same count and admits both. The claim is
    a single `INSERT … ON CONFLICT DO UPDATE … RETURNING`, so every caller gets a distinct position
    in one sequence. Ten genuinely concurrent calls against a ceiling of three: exactly three
    effects, never four.
    """
    for _ in range(10):
        await lab.approve(subject="agent-7", tool="issue_credit", account=ACCOUNT, amount=AMOUNT)
    token = lab.valid_token(subject="agent-7")

    outcomes = await asyncio.gather(*(_call(lab, token) for _ in range(10)))

    allowed = [o for o in outcomes if o.decision.value == "allowed"]
    limited = [o for o in outcomes if o.reason == "rate_limited"]
    assert len(allowed) == LIMIT, f"the ceiling leaked under concurrency: {len(allowed)} allowed"
    assert len(limited) == 10 - LIMIT
    assert await lab.effect_count() == LIMIT


async def test_a_limit_of_zero_disables_the_ceiling_rather_than_refusing_everything(
    lab: Any,
) -> None:
    """0 means off. A config value that silently bricked the server would be a worse failure than
    no limiter at all, and `AAB_RATE_LIMIT_PER_MINUTE=0` is the documented way to turn it off."""
    for _ in range(3):
        await lab.approve(subject="agent-7", tool="issue_credit", account=ACCOUNT, amount=AMOUNT)
    token = lab.valid_token(subject="agent-7")

    outcomes = [
        await lab.call_issue_credit(
            token=token, account=ACCOUNT, amount=AMOUNT, rate_limit_per_minute=0
        )
        for _ in range(3)
    ]

    assert [o.decision.value for o in outcomes] == ["allowed"] * 3
    assert await lab.effect_count() == 3
