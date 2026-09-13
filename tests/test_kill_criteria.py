"""**The kill test.** Written and committed before the implementation it tests.

ADR-001 fixes five scenarios and the result each must produce. They are here, in executable form,
in a commit that predates the package — `git log --diff-filter=A` on this file against
`src/agent_authz_broker/` shows the order, and if they ever land together the pre-registration is
worth nothing and a reader should say so.

**Every count comes from `irreversible_effect` in PostgreSQL.** Not from a return value, not from a
verifier's own report, not from a log line. A component that grades itself is not evidence — the
question is only ever whether a row exists.

Until the package lands these skip, which is why `test_predeclaration.py` exists: it fails the build
if the package is importable while these are still skipped, so the skip cannot be quietly forgotten.
"""

from __future__ import annotations

import pytest

pytest.importorskip(
    "agent_authz_broker.authz",
    reason=(
        "predeclared in this commit; the implementation does not exist yet. "
        "tests/test_predeclaration.py fails the build if this skip outlives the package."
    ),
)

import asyncio

from agent_authz_broker.authz import Decision, authorize

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


THIS_SERVER = "https://broker.example/mcp"
ANOTHER_SERVER = "https://other-service.example/mcp"

READ = "account:read"
FLAG = "account:flag"
CREDIT = "credit:issue"


# --------------------------------------------------------------------------- A. audience confusion


async def test_A_valid_token_for_another_resource_server_is_refused(lab) -> None:
    """A token that is correct in every way except who it was minted for.

    Signature valid, issuer known, not expired, `credit:issue` present and properly attenuated, a
    matching approval on file. The only defect is `aud`. A server that checks the signature and the
    scope accepts this, and the agent has gained authority at a service nobody granted it.
    """
    token = lab.authority.mint(subject="alice", audience=ANOTHER_SERVER, scopes=[READ, CREDIT])
    approval = await lab.approve(subject="alice", tool="issue_credit", account="ACC-1", amount=500)

    result = await lab.call_issue_credit(token=token, account="ACC-1", amount=500)

    assert result.decision is Decision.DENIED
    assert result.reason == "audience_mismatch"
    assert await lab.effect_count() == 0, "a token minted for another resource server moved money"
    assert await lab.approval_is_consumed(approval.approval_id) is False


# ------------------------------------------------------------------ B. scope amplification by chain


async def test_B_delegated_token_cannot_gain_a_scope_an_ancestor_lacked(lab) -> None:
    """The leaf says `credit:issue`. The principal it acts for never had it.

    This is the case the leaf's own `scope` claim cannot be trusted for. The chain is
    alice[read, flag] -> agent[read, flag, credit:issue], and the intersection rule in ADR-001 makes
    the effective set [read, flag] however loudly the leaf claims otherwise.
    """
    token = lab.authority.mint_delegated(
        chain=[("alice", [READ, FLAG])],
        subject="agent-7",
        audience=THIS_SERVER,
        scopes=[READ, FLAG, CREDIT],
    )
    await lab.approve(subject="agent-7", tool="issue_credit", account="ACC-1", amount=500)

    result = await lab.call_issue_credit(token=token, account="ACC-1", amount=500)

    assert result.decision is Decision.DENIED
    assert result.reason == "insufficient_effective_scope"
    assert CREDIT not in result.effective_scopes
    assert await lab.effect_count() == 0, "a delegation amplified its own authority"


async def test_B_multi_hop_attenuation_takes_the_intersection_of_every_link(lab) -> None:
    """Three hops, and the scope missing from the middle one is missing from the result.

    alice[read, flag, credit] -> team-bot[read, flag] -> agent-7[read, flag, credit]. The middle
    link is the one that matters: an implementation that checked only the root and the leaf would
    allow this, and it is exactly the shape a real delegation bug takes.
    """
    token = lab.authority.mint_delegated(
        chain=[("alice", [READ, FLAG, CREDIT]), ("team-bot", [READ, FLAG])],
        subject="agent-7",
        audience=THIS_SERVER,
        scopes=[READ, FLAG, CREDIT],
    )
    await lab.approve(subject="agent-7", tool="issue_credit", account="ACC-1", amount=500)

    result = await lab.call_issue_credit(token=token, account="ACC-1", amount=500)

    assert result.decision is Decision.DENIED
    assert set(result.effective_scopes) == {READ, FLAG}
    assert await lab.effect_count() == 0


# ---------------------------------------------------------------------------- C. approval required


async def test_C_irreversible_tool_without_an_approval_does_nothing(lab) -> None:
    """Everything is right except that no human ever approved it."""
    token = lab.authority.mint(subject="alice", audience=THIS_SERVER, scopes=[READ, CREDIT])

    result = await lab.call_issue_credit(token=token, account="ACC-1", amount=500)

    assert result.decision is Decision.DENIED
    assert result.reason == "approval_required"
    assert await lab.effect_count() == 0


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("expired", "approval_expired"),
        ("other_tool", "approval_required"),
        ("other_account", "approval_required"),
        ("other_subject", "approval_required"),
        ("other_amount", "approval_required"),
        ("already_consumed", "approval_required"),
    ],
)
async def test_C_an_approval_that_does_not_match_is_not_an_approval(lab, mutation, reason) -> None:
    """Every binding in ADR-001's approval table, each one removed in turn.

    Parameterised rather than written six times because the point is the *set*: an approval that is
    bound to fewer things than this is an approval that authorises something nobody agreed to.
    """
    token = lab.authority.mint(subject="alice", audience=THIS_SERVER, scopes=[READ, CREDIT])
    await lab.approve_mutated(
        mutation, subject="alice", tool="issue_credit", account="ACC-1", amount=500
    )

    result = await lab.call_issue_credit(token=token, account="ACC-1", amount=500)

    assert result.decision is Decision.DENIED
    assert result.reason == reason
    assert await lab.effect_count() == 0


# ------------------------------------------------------------------- D. one approval, one effect


async def test_D_two_concurrent_calls_on_one_approval_produce_exactly_one_effect(lab) -> None:
    """The race, forced rather than hoped for.

    Two genuinely concurrent calls against real PostgreSQL, each with the same valid token and the
    same valid approval. The approval is consumed by a conditional UPDATE, so exactly one call can
    win it; the loser must fail closed rather than proceed unapproved.

    An in-process lock would pass this test and fail behind two web workers, which is why ADR-001
    says the mechanism has to be in the database.
    """
    token = lab.authority.mint(subject="alice", audience=THIS_SERVER, scopes=[READ, CREDIT])
    await lab.approve(subject="alice", tool="issue_credit", account="ACC-1", amount=500)

    first, second = await asyncio.gather(
        lab.call_issue_credit(token=token, account="ACC-1", amount=500),
        lab.call_issue_credit(token=token, account="ACC-1", amount=500),
    )

    decisions = sorted([first.decision, second.decision], key=str)
    assert decisions == sorted([Decision.ALLOWED, Decision.DENIED], key=str), (
        f"expected exactly one winner, got {first.decision} and {second.decision}"
    )
    loser = first if first.decision is Decision.DENIED else second
    assert loser.reason == "approval_already_consumed"
    assert await lab.effect_count() == 1, (
        "one approval authorised more than one irreversible effect"
    )


# ------------------------------------------------------------------------------ E. the happy path


async def test_E_the_correct_request_succeeds_exactly_once(lab) -> None:
    """Correct audience, properly attenuated scope, a matching unexpired approval.

    A security test suite that only proves things are refused has not shown the system works; it has
    shown a server that denies everything, which is easy.
    """
    token = lab.authority.mint_delegated(
        chain=[("alice", [READ, FLAG, CREDIT])],
        subject="agent-7",
        audience=THIS_SERVER,
        scopes=[READ, CREDIT],
    )
    approval = await lab.approve(
        subject="agent-7", tool="issue_credit", account="ACC-1", amount=500
    )

    result = await lab.call_issue_credit(token=token, account="ACC-1", amount=500)

    assert result.decision is Decision.ALLOWED, result.reason
    assert set(result.effective_scopes) == {READ, CREDIT}
    assert await lab.effect_count() == 1
    assert await lab.approval_is_consumed(approval.approval_id) is True


# ------------------------------------------------------------------------ token-level refusals


@pytest.mark.parametrize(
    ("flaw", "reason"),
    [
        ("expired", "token_expired"),
        ("bad_signature", "signature_invalid"),
        ("unknown_issuer", "issuer_unknown"),
        ("missing_scope", "insufficient_effective_scope"),
    ],
)
async def test_a_flawed_token_never_reaches_the_effect(lab, flaw, reason) -> None:
    token = lab.authority.mint_flawed(
        flaw, subject="alice", audience=THIS_SERVER, scopes=[READ, CREDIT]
    )
    await lab.approve(subject="alice", tool="issue_credit", account="ACC-1", amount=500)

    result = await lab.call_issue_credit(token=token, account="ACC-1", amount=500)

    assert result.decision is Decision.DENIED
    assert result.reason == reason
    assert await lab.effect_count() == 0


async def test_the_naive_verifier_is_the_one_that_fails(lab) -> None:
    """The comparison ADR-001 predeclared, on the same scenarios and the same database.

    A baseline is only worth publishing if it is what a competent engineer would actually write, and
    if it is run through the identical path. This asserts the direction of the result — the naive
    check lets A and B through — so that the README's matrix cannot drift from the code.
    """
    wrong_audience = lab.authority.mint(
        subject="alice", audience=ANOTHER_SERVER, scopes=[READ, CREDIT]
    )
    amplified = lab.authority.mint_delegated(
        chain=[("alice", [READ, FLAG])],
        subject="agent-7",
        audience=THIS_SERVER,
        scopes=[READ, FLAG, CREDIT],
    )

    assert authorize(lab.naive, wrong_audience, tool="issue_credit").decision is Decision.ALLOWED
    assert authorize(lab.naive, amplified, tool="issue_credit").decision is Decision.ALLOWED

    assert authorize(lab.hardened, wrong_audience, tool="issue_credit").decision is Decision.DENIED
    assert authorize(lab.hardened, amplified, tool="issue_credit").decision is Decision.DENIED
