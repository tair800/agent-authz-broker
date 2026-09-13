"""Run every scenario under both policies and write down what actually happened.

The console and the README both render this file. Neither of them contains a number.

That is not ceremony. The first version of the console shipped a hand-written fixture claiming the
naive verifier permitted an effect in the *no-approval* scenario — and it does not, because the two
policies differ only on audience and delegation, and the approval gate sits below both of them. A
reviewer caught it before anything was published. The lesson is the one this portfolio keeps
relearning: a matrix somebody typed is a claim, and a matrix a run wrote is evidence.

Every effect count here is ``SELECT count(*) FROM irreversible_effect`` after a clean database, so a
scenario cannot borrow an effect from the one before it.

**The other three console screens are written from this run too**, and for the same reason. They
were hand-authored once, and the hand-authored versions outlived the correction above: the audit
fixture still showed the naive verifier minting six effects, and the chain fixture still named
*alice* as the subject of tokens the scenarios mint for *agent-7*. Nothing propagated the fix,
because nothing had to. So the audit trail is now the ``audit_event`` rows this run wrote, the
approvals are the ``approval`` rows it left behind, and each chain is decoded from the token that
was actually presented — not a second description of it kept somewhere else.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from agent_authz_broker.approvals import create_approval
from agent_authz_broker.authz import HARDENED, NAIVE, Policy, effective_scopes
from agent_authz_broker.db.models import Approval, AuditEvent, IrreversibleEffect
from agent_authz_broker.domain import TOOL_SCOPES, TokenClaims
from agent_authz_broker.effects import call_tool
from agent_authz_broker.testauthority import TestAuthority
from agent_authz_broker.tokens import verify_token

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


async def _audit(engine: AsyncEngine) -> list[dict[str, Any]]:
    """The audit rows this run wrote, in the shape ``GET /api/v1/audit`` serves.

    Read before the next reset, because the next reset deletes them. The shape is duplicated from
    the endpoint deliberately: the console must render the fixture and the live read identically,
    and a divergence here would show up as a parse failure rather than as a quiet difference.
    """
    async with AsyncSession(engine) as session:
        rows = (await session.execute(select(AuditEvent).order_by(AuditEvent.at))).scalars()
        return [
            {
                "audit_id": row.audit_id,
                "at": row.at.isoformat(),
                "subject": row.subject,
                "tool": row.tool,
                "policy": row.policy,
                "decision": row.decision,
                "reason": row.reason,
                "required_scope": row.required_scope,
                "effective_scopes": row.effective_scopes.split() if row.effective_scopes else [],
                "approval_id": row.approval_id,
                "effect_id": row.effect_id,
            }
            for row in rows
        ]


async def _approvals(engine: AsyncEngine, *, now: dt.datetime) -> list[dict[str, Any]]:
    """The approval rows this run left behind, in the shape ``GET /api/v1/approvals`` serves."""
    async with AsyncSession(engine) as session:
        rows = (await session.execute(select(Approval).order_by(Approval.created_at))).scalars()
        return [
            {
                "approval_id": row.approval_id,
                "subject": row.subject,
                "tool": row.tool,
                "account": row.account,
                "amount": row.amount,
                "approved_by": row.approved_by,
                "expires_at": row.expires_at.isoformat(),
                "consumed_at": row.consumed_at.isoformat() if row.consumed_at else None,
                "state": (
                    "consumed"
                    if row.consumed_at
                    else ("expired" if row.expires_at <= now else "pending")
                ),
            }
            for row in rows
        ]


def _chain_of(scenario: Scenario, token: str, *, authority: TestAuthority) -> dict[str, Any]:
    """The delegation chain **in the token that was presented**, and where authority was lost.

    Decoded from the bearer string with the same verifier the server uses, then attenuated with the
    same :func:`effective_scopes`. There is no separate description of the chain anywhere: a
    scenario that changed who it delegates from would change this artifact on the next run, which
    is exactly what the hand-written fixture could not do.
    """
    claims = verify_token(token, jwks_by_issuer={authority.issuer: authority.jwks()})
    if not isinstance(claims, TokenClaims):
        raise AssertionError(f"{scenario.id}: its own token did not verify ({claims})")

    links: list[dict[str, Any]] = [
        {
            "subject": link.subject,
            "scopes": sorted(link.scopes),
            "role": "root" if index == 0 else "intermediate",
        }
        for index, link in enumerate(claims.chain)
    ]
    links.append({"subject": claims.subject, "scopes": sorted(claims.scopes), "role": "leaf"})

    effective = effective_scopes(claims, attenuate=True)
    return {
        "scenario": scenario.id,
        "title": scenario.title,
        "links": links,
        "effective_scopes": sorted(effective),
        "required_scope": TOOL_SCOPES["issue_credit"],
        "attenuated_away": sorted(claims.scopes - effective),
    }


async def _run(
    engine: AsyncEngine,
    scenario: Scenario,
    policy: Policy,
    *,
    authority: TestAuthority,
    audience: str,
) -> dict[str, Any]:
    """One scenario, one policy, from a clean database.

    Returns the row the matrix renders **and** the database state the run produced, because the
    state is gone the moment the next scenario resets. ``token`` comes back so the caller can decode
    the chain from the credential that was actually presented.
    """
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
        "_token": token,
        "_audit": await _audit(engine),
        "_approvals": await _approvals(engine, now=dt.datetime.now(tz=dt.UTC)),
    }


async def build_matrix(
    engine: AsyncEngine, *, audience: str, generated_at: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Measure every scenario under both policies.

    Args:
        engine: A database this is allowed to clear between rows. In the deployment it is the demo
            database; never point it at anything else.
        audience: The resource server identity the hardened policy enforces.
        generated_at: Stamped by the caller, so this stays a pure function of the scenarios.

    Returns:
        ``(matrix, console)``. The first is the artifact the README and the matrix screen render.
        The second is what the other three screens render — the audit rows this run wrote, the
        approvals it left behind, and each scenario's chain decoded from its own token. They are
        returned together because they are one measurement: a console assembled from a matrix
        measured here and screens written by hand somewhere else is how the two came to disagree.
    """
    authority = TestAuthority()
    rows: list[dict[str, Any]] = []
    trail: list[dict[str, Any]] = []
    approvals: list[dict[str, Any]] = []
    chains: dict[str, Any] = {}
    naive_effects = 0
    hardened_effects = 0

    for scenario in SCENARIOS:
        naive = await _run(engine, scenario, NAIVE, authority=authority, audience=audience)
        hardened = await _run(engine, scenario, HARDENED, authority=authority, audience=audience)
        naive_effects += int(naive["effects"])
        hardened_effects += int(hardened["effects"])

        chains[scenario.id] = _chain_of(scenario, hardened.pop("_token"), authority=authority)
        naive.pop("_token")
        trail.extend(naive.pop("_audit"))
        trail.extend(hardened.pop("_audit"))
        # The approvals screen shows one store, not two interleaved ones, so it shows the hardened
        # server's. Under the naive policy the approvals for scenarios A and B are consumed rather
        # than left pending -- which is the breach, and the audit trail above carries both policies
        # and says so. `frontend/fixtures/README.md` records this choice rather than leaving a
        # reader to infer it from a table with no column to tell the two stores apart.
        naive.pop("_approvals")
        approvals.extend(hardened.pop("_approvals"))

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
    matrix = {
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
    # Newest first, matching `GET /api/v1/audit`'s ordering, so the same screen reads the same way
    # whichever of the two it is attached to.
    trail.reverse()
    console = {
        "generated_at": generated_at,
        "audit": trail,
        "approvals": approvals,
        "chains": chains,
    }
    return matrix, console


def _now() -> str:
    return dt.datetime.now(tz=dt.UTC).isoformat(timespec="seconds")
