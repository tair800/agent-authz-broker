"""The lab the kill test drives, and the only place its fixtures are defined.

`Lab` is a thin seam over the real thing and deliberately not a mock. Every call in it reaches the
same `effects.call_tool` an MCP tool reaches, against real PostgreSQL, and `effect_count()` is a
``SELECT count(*)`` rather than anything the system reports about itself. A harness that could
answer differently from production would make the whole suite a statement about the harness.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import pytest
import pytest_asyncio
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from agent_authz_broker.approvals import create_approval
from agent_authz_broker.authz import HARDENED, NAIVE
from agent_authz_broker.config import Settings
from agent_authz_broker.db.engine import async_dsn
from agent_authz_broker.db.models import (
    Approval,
    AuditEvent,
    Base,
    IrreversibleEffect,
    RateLimitCounter,
)
from agent_authz_broker.effects import ToolOutcome, call_tool
from agent_authz_broker.testauthority import TestAuthority
from agent_authz_broker.tokens import verify_token

THIS_SERVER = "https://broker.example/mcp"

READ, FLAG, CREDIT = "account:read", "account:flag", "credit:issue"

Mutation = Literal[
    "expired", "other_tool", "other_account", "other_subject", "other_amount", "already_consumed"
]


@dataclass(frozen=True, slots=True)
class ApprovalHandle:
    approval_id: str


class Lab:
    """One authority, one database, and the same call path the MCP tools use."""

    def __init__(self, engine: AsyncEngine, authority: TestAuthority) -> None:
        self.engine = engine
        self.authority = authority
        self.hardened = HARDENED
        self.naive = NAIVE
        self.jwks = {authority.issuer: authority.jwks()}

    def verify(self, token: str) -> Any:
        """Verified claims, or the reason they are not. The same call `effects.call_tool` makes."""
        return verify_token(token, jwks_by_issuer=self.jwks)

    async def call_issue_credit(
        self,
        *,
        token: str,
        account: str,
        amount: int,
        policy: Any = None,
        now: dt.datetime | None = None,
        rate_limit_per_minute: int = 0,
    ) -> ToolOutcome:
        """The same call path the MCP tools take.

        ``rate_limit_per_minute`` defaults to 0 -- off -- so the kill test measures authorization
        and nothing else. A ceiling silently applied to the suite that proves the security claim
        could turn a real authorization failure into a refusal for an unrelated reason, and the
        test would still be green.
        """
        return await call_tool(
            self.engine,
            token=token,
            tool="issue_credit",
            arguments={"account": account, "amount": amount},
            authority_jwks=self.jwks,
            audience=THIS_SERVER,
            policy=policy or self.hardened,
            now=now,
            rate_limit_per_minute=rate_limit_per_minute,
        )

    def valid_token(self, *, subject: str) -> str:
        """A token this server accepts: right audience, unexpired, correctly attenuated."""
        return self.authority.mint_delegated(
            chain=[("alice", [READ, FLAG, CREDIT])],
            subject=subject,
            audience=THIS_SERVER,
            scopes=[READ, CREDIT],
        )

    async def approve(
        self, *, subject: str, tool: str, account: str, amount: int
    ) -> ApprovalHandle:
        async with AsyncSession(self.engine) as session, session.begin():
            approval = await create_approval(
                session,
                subject=subject,
                tool=tool,
                account=account,
                amount=amount,
                approved_by="human@demo.invalid",
            )
            return ApprovalHandle(approval.approval_id)

    async def approve_mutated(
        self, mutation: Mutation, *, subject: str, tool: str, account: str, amount: int
    ) -> ApprovalHandle:
        """Record an approval that is wrong in exactly one of the ways ADR-001 binds against.

        Each mutation removes exactly one binding, so a failure names which binding stopped
        mattering rather than leaving a reader to guess.
        """
        now = dt.datetime.now(tz=dt.UTC)
        fields: dict[str, Any] = {
            "subject": subject,
            "tool": tool,
            "account": account,
            "amount": amount,
        }
        ttl = 900
        if mutation == "other_tool":
            fields["tool"] = "flag_account"
        elif mutation == "other_account":
            fields["account"] = "ACC-OTHER"
        elif mutation == "other_subject":
            fields["subject"] = "mallory"
        elif mutation == "other_amount":
            fields["amount"] = amount + 1
        elif mutation == "expired":
            ttl = -60

        async with AsyncSession(self.engine) as session, session.begin():
            approval = await create_approval(
                session, approved_by="human@demo.invalid", ttl_seconds=ttl, now=now, **fields
            )
            if mutation == "already_consumed":
                approval.consumed_at = now
            return ApprovalHandle(approval.approval_id)

    async def effect_count(self) -> int:
        """The number of irreversible effects, read from the table. The only grading input."""
        async with AsyncSession(self.engine) as session:
            total = await session.execute(select(func.count()).select_from(IrreversibleEffect))
            return int(total.scalar_one())

    async def approval_is_consumed(self, approval_id: str) -> bool:
        async with AsyncSession(self.engine) as session:
            approval = await session.get(Approval, approval_id)
            assert approval is not None
            return approval.consumed_at is not None


def _settings() -> Settings:
    return Settings()


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def engine() -> AsyncIterator[AsyncEngine]:
    """One engine and one schema for the whole session.

    Per-test it cost three minutes for seventeen tests, almost all of it `create_all` re-issuing
    DDL that had not changed. Isolation comes from the per-test truncate below, which is the thing
    that actually has to happen between tests.
    """
    created = create_async_engine(async_dsn(_settings()), poolclass=NullPool)
    async with created.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    try:
        yield created
    finally:
        await created.dispose()


@pytest_asyncio.fixture(loop_scope="session")
async def lab(engine: AsyncEngine) -> AsyncIterator[Lab]:
    """A clean database per test.

    Deleted in dependency order inside one transaction. Two tests sharing a leftover approval would
    make the concurrency test pass for the wrong reason, and an effect left behind by an earlier
    test would make every count assertion in the suite meaningless.
    """
    async with AsyncSession(engine) as session, session.begin():
        await session.execute(delete(IrreversibleEffect))
        await session.execute(delete(AuditEvent))
        await session.execute(delete(Approval))
        await session.execute(delete(RateLimitCounter))
    yield Lab(engine, TestAuthority())


# ----------------------------------------------------------- the kill test must actually run

#: The file whose tests ADR-001 predeclared. Named once.
KILL_TEST_FILE = "test_kill_criteria.py"


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Refuse the whole session if a predeclared kill test has been disabled by a mark.

    `tests/test_predeclaration.py` guards the same property by reading the file as **text**, and a
    review showed that is not enough: it bans the literal string ``importorskip`` and nothing else,
    so adding ``pytestmark = pytest.mark.skip`` to the kill test left all three of its assertions
    green while zero kill tests ran. A guard that inspects source text is guessing at what pytest
    will do; this one asks pytest what it is actually about to do.

    ``tryfirst`` so this sees the collected items **before** ``-m`` deselection removes them —
    deselection is not disablement, and the offline lane legitimately deselects every kill test.

    ``UsageError`` rather than a failing test, because a failing test can be deselected too.
    """
    if importlib.util.find_spec("agent_authz_broker.authz") is None:
        return  # Still genuinely predeclared: the package does not exist yet.

    kill = [item for item in items if Path(str(item.fspath)).name == KILL_TEST_FILE]
    if not kill:
        return  # This run did not collect that file at all, which is not this hook's business.

    disabled = sorted(
        item.nodeid
        for item in kill
        if item.get_closest_marker("skip") is not None
        or item.get_closest_marker("skipif") is not None
    )
    if disabled:
        raise pytest.UsageError(
            "the predeclared kill test has been disabled by a mark, which means the suite that "
            "proves the central security claim is not running: " + ", ".join(disabled)
        )
