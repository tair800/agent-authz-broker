"""Four tables. Each one exists because something in the threat model has to be durable.

The load-bearing schema decisions are both on :class:`IrreversibleEffect`, and both are constraints
rather than code:

* ``approval_id`` is **UNIQUE**. That is what makes "one approval, one effect" a property of the
  database instead of a property of the Python that happens to run above it. Two racing requests can
  both believe they won; only one row can exist.
* ``approval_id`` is **NOT NULL**. There is no code path that writes an effect without naming the
  approval that authorised it, because the column will not permit one.

A test can be deleted. A constraint has to be migrated away, which is a thing somebody notices.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = ["Approval", "AuditEvent", "Base", "IrreversibleEffect", "RateLimitCounter", "new_id"]


def new_id(prefix: str) -> str:
    """A readable, prefixed id, so a value in a log says what kind of thing it is."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class Base(DeclarativeBase):
    pass


class Approval(Base):
    """A human's recorded decision to permit one irreversible action, once.

    Every binding column is here because ADR-001's table says removing it authorises something
    nobody agreed to: the subject, the tool, the target account and the amount together are the
    *thing* that was approved, and an approval that omits any of them approves a category rather
    than an act.

    ``consumed_at`` is the one-time property. It is NULL until exactly one request wins it.
    """

    __tablename__ = "approval"

    approval_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    account: Mapped[str] = mapped_column(String(64), nullable=False)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    __table_args__ = (
        # A negative or zero credit is not an approval anybody meant to give.
        CheckConstraint("amount > 0", name="ck_approval_amount_positive"),
        Index("ix_approval_lookup", "subject", "tool", "account"),
    )


class IrreversibleEffect(Base):
    """The synthetic thing that cannot be undone. **The row every test counts.**

    ADR-001: *"a component that grades itself is not evidence."* Nothing in this system reports how
    many effects happened; the suite asks the table.
    """

    __tablename__ = "irreversible_effect"

    effect_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    approval_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("approval.approval_id"), nullable=False, unique=True
    )
    """UNIQUE and NOT NULL. This is the 'one approval, one effect' guarantee, and it holds under
    any number of concurrent workers, processes or hosts — which an in-process lock does not."""

    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    account: Mapped[str] = mapped_column(String(64), nullable=False)
    amount: Mapped[int] = mapped_column(Integer, nullable=False)
    token_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class AuditEvent(Base):
    """Append-only. Every decision, allowed or refused, with what it was decided from.

    Refusals are recorded as carefully as grants. An audit trail that only holds successes cannot
    answer the question somebody actually asks after an incident, which is *what was tried*.
    """

    __tablename__ = "audit_event"

    audit_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    subject: Mapped[str | None] = mapped_column(String(200))
    token_id: Mapped[str | None] = mapped_column(String(64))
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    policy: Mapped[str] = mapped_column(String(16), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(64))
    required_scope: Mapped[str | None] = mapped_column(String(64))
    effective_scopes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    approval_id: Mapped[str | None] = mapped_column(String(40))
    effect_id: Mapped[str | None] = mapped_column(String(40))

    __table_args__ = (Index("ix_audit_at", "at"),)


class RateLimitCounter(Base):
    """How many times one subject has called one tool inside one fixed window.

    **In the database and not in the process, for the same reason the approval is.** An in-memory
    counter states a bound per worker, so "30 per minute" silently becomes 30 x N behind N of them —
    and on a free plan that reads as correct right up to the day somebody scales it. The counter is
    a row, incremented by ``INSERT … ON CONFLICT DO UPDATE … RETURNING``, so the number a caller
    gets back is its position in a single global sequence however many processes are serving.

    The primary key **is** the bucket: (subject, tool, window_start). Two subjects cannot share one,
    and neither can two tools, because there is no row for them to share.

    Windows are fixed rather than sliding. That is a deliberate, stated weakness: a caller can spend
    its whole allowance at the end of one window and again at the start of the next, so the true
    worst case over an arbitrary 60 seconds is **twice** the limit. Sliding windows cost a row per
    request; this costs one row per bucket. `docs/threat-model.md` states the burst rather than
    rounding it away.
    """

    __tablename__ = "rate_limit_counter"

    subject: Mapped[str] = mapped_column(String(200), primary_key=True)
    tool: Mapped[str] = mapped_column(String(64), primary_key=True)
    window_start: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
