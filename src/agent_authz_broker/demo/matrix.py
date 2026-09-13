"""Run every scenario under both policies and write down what actually happened.

The console and the README both render this file. Neither of them contains a number.

That is not ceremony. The first version of the console shipped a hand-written fixture claiming the
naive verifier permitted an effect in the *no-approval* scenario — and it does not, because the two
policies differ only on audience and delegation, and the approval gate sits below both of them. A
reviewer caught it before anything was published. The lesson is the one this portfolio keeps
relearning: a matrix somebody typed is a claim, and a matrix a run wrote is evidence.

Every effect count here is ``SELECT count(*) FROM irreversible_effect`` after a clean database, so a
scenario cannot borrow an effect from the one before it.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from agent_authz_broker.approvals import create_approval
from agent_authz_broker.authz import HARDENED, NAIVE, Policy
from agent_authz_broker.db.models import Approval, AuditEvent, IrreversibleEffect
from agent_authz_broker.effects import call_tool
from agent_authz_broker.testauthority import TestAuthority

__all__ = ["SCENARIOS", "Scenario", "build_matrix"]

ACCOUNT = "ACC-1041"
AMOUNT = 500
READ = "account:read"
FLAG = "account:flag"
CREDIT = "credit:issue"


@dataclass(frozen=True, slots=True)
class Scenario:
    """One row of the security matrix.

    ``setup`` returns the bearer token and arranges whatever approval state the scenario needs, so
    that each row is self-contained and a reader can see the whole of what it tests in one place.
    """

    id: str
    title: str
    description: str
    is_attack: bool
    setup: Callable[[AsyncEngine, TestAuthority, str], Awaitable[str]]
    calls: int = 1
    expected_effects: int = 0
    """What ADR-001 requires of the hardened server. Usually zero -- but the replay scenario makes
    two calls and exactly ONE effect is the correct outcome, because the first call is legitimate
    and only the second must be refused. Counting any effect as a breach called that a failure, so
    the expectation is declared per scenario rather than assumed to be zero."""


async def _approve(engine: AsyncEngine, *, subject: str, ttl: int = 900) -> None:
    async with AsyncSession(engine) as session, session.begin():
        await create_approval(
            session,
            subject=subject,
            tool="issue_credit",
            account=ACCOUNT,
            amount=AMOUNT,
            approved_by="rita@demo.invalid",
            ttl_seconds=ttl,
        )


async def _valid(engine: AsyncEngine, authority: TestAuthority, audience: str) -> str:
    await _approve(engine, subject="agent-7")
    return authority.mint_delegated(
        chain=[("alice", [READ, FLAG, CREDIT])],
        subject="agent-7",
        audience=audience,
        scopes=[READ, CREDIT],
    )


async def _wrong_audience(engine: AsyncEngine, authority: TestAuthority, audience: str) -> str:
    await _approve(engine, subject="agent-7")
    return authority.mint_delegated(
        chain=[("alice", [READ, FLAG, CREDIT])],
        subject="agent-7",
        audience="https://other-service.example/mcp",
        scopes=[READ, CREDIT],
    )


async def _amplified(engine: AsyncEngine, authority: TestAuthority, audience: str) -> str:
    await _approve(engine, subject="agent-7")
    return authority.mint_delegated(
        chain=[("alice", [READ, FLAG])],
        subject="agent-7",
        audience=audience,
        scopes=[READ, FLAG, CREDIT],
    )


async def _no_approval(engine: AsyncEngine, authority: TestAuthority, audience: str) -> str:
    return authority.mint(subject="agent-7", audience=audience, scopes=[READ, CREDIT])


async def _expired_approval(engine: AsyncEngine, authority: TestAuthority, audience: str) -> str:
    await _approve(engine, subject="agent-7", ttl=-60)
    return authority.mint(subject="agent-7", audience=audience, scopes=[READ, CREDIT])


async def _replay(engine: AsyncEngine, authority: TestAuthority, audience: str) -> str:
    await _approve(engine, subject="agent-7")
    return authority.mint(subject="agent-7", audience=audience, scopes=[READ, CREDIT])


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="valid_request",
        title="Correct audience, attenuated scope, matching approval",
        description=(
            "The positive path. A suite that only proves refusals has shown a server that denies "
            "everything, which is easy."
        ),
        is_attack=False,
        setup=_valid,
        expected_effects=1,
    ),
    Scenario(
        id="wrong_audience",
        title="Valid token, minted for another resource server",
        description=(
            "Real signature, known issuer, unexpired, sufficient scope, approval on file. The only "
            "defect is who the token was minted for."
        ),
        is_attack=True,
        setup=_wrong_audience,
    ),
    Scenario(
        id="scope_amplification",
        title="Delegated token claims a scope its delegator never had",
        description=(
            "alice holds read and flag. The leaf claims read, flag and credit:issue. Effective "
            "authority is the intersection down the chain, not the leaf's claim."
        ),
        is_attack=True,
        setup=_amplified,
    ),
    Scenario(
        id="no_approval",
        title="Irreversible tool with no recorded human approval",
        description="Everything is correct except that no human ever approved this act.",
        is_attack=True,
        setup=_no_approval,
    ),
    Scenario(
        id="expired_approval",
        title="An approval that has expired",
        description="A human approved this, two hours ago. An approval is not good forever.",
        is_attack=True,
        setup=_expired_approval,
    ),
    Scenario(
        id="approval_replay",
        title="One approval, two calls",
        description=(
            "The same valid token and the same valid approval, presented twice. The approval is "
            "consumed by a conditional UPDATE, so the second call finds nothing to spend."
        ),
        is_attack=True,
        setup=_replay,
        calls=2,
        expected_effects=1,
    ),
)


async def _reset(engine: AsyncEngine) -> None:
    async with AsyncSession(engine) as session, session.begin():
        await session.execute(delete(IrreversibleEffect))
        await session.execute(delete(AuditEvent))
        await session.execute(delete(Approval))


async def _effects(engine: AsyncEngine) -> int:
    async with AsyncSession(engine) as session:
        total = await session.execute(select(func.count()).select_from(IrreversibleEffect))
        return int(total.scalar_one())


async def _run(
    engine: AsyncEngine,
    scenario: Scenario,
    policy: Policy,
    *,
    authority: TestAuthority,
    audience: str,
) -> dict[str, Any]:
    """One scenario, one policy, from a clean database."""
    await _reset(engine)
    token = await scenario.setup(engine, authority, audience)

    last: Any = None
    for _ in range(scenario.calls):
        last = await call_tool(
            engine,
            token=token,
            tool="issue_credit",
            arguments={"account": ACCOUNT, "amount": AMOUNT},
            authority_jwks={authority.issuer: authority.jwks()},
            audience=audience,
            policy=policy,
        )
    return {
        "decision": str(last.decision),
        "reason": last.reason,
        "effects": await _effects(engine),
    }


async def build_matrix(engine: AsyncEngine, *, audience: str, generated_at: str) -> dict[str, Any]:
    """Measure every scenario under both policies.

    Args:
        engine: A database this is allowed to clear between rows. In the deployment it is the demo
            database; never point it at anything else.
        audience: The resource server identity the hardened policy enforces.
        generated_at: Stamped by the caller, so this stays a pure function of the scenarios.

    Returns:
        The artifact the console and the README render.
    """
    authority = TestAuthority()
    rows: list[dict[str, Any]] = []
    naive_effects = 0
    hardened_effects = 0

    for scenario in SCENARIOS:
        naive = await _run(engine, scenario, NAIVE, authority=authority, audience=audience)
        hardened = await _run(engine, scenario, HARDENED, authority=authority, audience=audience)
        naive_effects += int(naive["effects"])
        hardened_effects += int(hardened["effects"])
        rows.append(
            {
                "id": scenario.id,
                "title": scenario.title,
                "description": scenario.description,
                "is_attack": scenario.is_attack,
                "expected_effects": scenario.expected_effects,
                "naive": naive,
                "hardened": hardened,
            }
        )

    await _reset(engine)
    attacks = [row for row in rows if row["is_attack"]]
    return {
        "generated_at": generated_at,
        "resource_server_url": audience,
        "scenarios": rows,
        "totals": {
            "naive_effects": naive_effects,
            "hardened_effects": hardened_effects,
            "attacks": len(attacks),
            # "Permitted" means MORE effects than ADR-001 allows for that scenario, not "any
            # effect". The replay row is the reason: two calls, one legitimate effect, and a naive
            # count of `> 0` reported the correct outcome as a breach.
            "attacks_permitted_by_naive": sum(
                1 for r in attacks if r["naive"]["effects"] > r["expected_effects"]
            ),
            "attacks_permitted_by_hardened": sum(
                1 for r in attacks if r["hardened"]["effects"] > r["expected_effects"]
            ),
        },
        "note": (
            "Both policies share one approval layer, so they differ only where the difference is a "
            "token check: audience and delegation attenuation. Scenarios that turn on approval are "
            "refused under both, and this table says so rather than overstating the baseline. "
            "In the replay row the reason differs from the concurrent case by design: a sequential "
            "second call finds no unconsumed approval at all (approval_required), while two "
            "genuinely concurrent calls race and the loser reports approval_already_consumed. Both "
            "fail closed."
        ),
    }


def _now() -> str:
    return dt.datetime.now(tz=dt.UTC).isoformat(timespec="seconds")
