"""The deployed service: the MCP resource server, a read-only console API, and the demo reset.

Three surfaces, and the separation between them is the point rather than an artefact of routing.

* **`/mcp`** — the MCP Streamable HTTP transport. Everything an agent can reach is here, and
  everything here goes through the token verifier and `effects.call_tool`.
* **`/api/v1/*`** — what the console renders. Reads only. It has no bearer token, no tool, and no
  way to cause an effect; the worst a reader can do with it is see the audit trail.
* **`/admin/reset`** — demo infrastructure, behind a separate bearer token that is not an MCP
  credential and is not minted by the test authority. **It is not an MCP tool and never appears in
  the tool list**, because a reset an agent can call is an undo button on the irreversible action
  this whole project exists to protect.

The approval-granting endpoint lives on the console API deliberately. A human grants approvals; the
agent can ask for one through `request_approval` and cannot create one, and there is no route from
the MCP surface to this one.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hmac
import json
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import delete, desc, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from agent_authz_broker.approvals import create_approval, list_approvals
from agent_authz_broker.config import Settings
from agent_authz_broker.db.engine import build_engine
from agent_authz_broker.db.models import (
    Approval,
    AuditEvent,
    IrreversibleEffect,
    RateLimitCounter,
)
from agent_authz_broker.mcp_server import create_server
from agent_authz_broker.testauthority import TestAuthority

__all__ = ["create_app"]

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "artifacts" / "matrix.json"
CHAINS = ROOT / "artifacts" / "chains.json"


class GrantApproval(BaseModel):
    """What a human supplies to approve one act, once."""

    subject: str
    account: str
    amount: int = Field(gt=0)
    approved_by: str = "console@demo.invalid"
    ttl_seconds: int = Field(default=900, ge=1, le=86_400)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI app.

    A factory so a test can point it at a scratch database without touching the environment of the
    process running it.
    """
    resolved = settings or Settings()
    engine: AsyncEngine = build_engine(resolved)
    authority = TestAuthority()
    mcp = create_server(resolved, engine, {authority.issuer: authority.jwks()})

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # The SDK's session manager has to be running for Streamable HTTP to accept a connection.
        async with mcp.session_manager.run():
            yield
        await engine.dispose()

    app = FastAPI(
        title="agent-authz-broker",
        version="0.1.0",
        summary=(
            "An MCP resource server that computes authority rather than accepting it: audience, "
            "delegation attenuation, and a human approval spent exactly once."
        ),
        docs_url=None if resolved.environment == "production" else "/docs",
        lifespan=lifespan,
    )

    if resolved.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=resolved.cors_allow_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

    # ------------------------------------------------------------------------------- health

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness. Touches nothing external, so it cannot fail for an unrelated reason."""
        return {"status": "alive", "service": "agent-authz-broker", "version": "0.1.0"}

    @app.get("/readyz")
    async def readyz() -> dict[str, str]:
        """Readiness. Reaches PostgreSQL, which is the thing `/healthz` deliberately does not.

        Worth the separation: `AAB_POSTGRES_DSN` has a localhost default, so a deployment with a
        misspelled variable name would answer `/healthz` perfectly while every query failed. Only
        this route tells the two apart.
        """
        try:
            async with AsyncSession(engine) as session:
                await session.execute(select(1))
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"status": "not_ready", "postgres": "unreachable"},
            ) from None
        return {"status": "ready", "postgres": "healthy"}

    @app.get("/api/v1/meta")
    async def meta() -> dict[str, Any]:
        for name in ("RENDER_GIT_COMMIT", "GIT_COMMIT_SHA"):
            revision = os.environ.get(name)
            if revision:
                break
        else:
            revision = ""
        return {
            "version": "0.1.0",
            "revision": revision,
            "resource_server_url": resolved.resource_server_url,
            "mcp_endpoint": "/mcp",
            "environment": resolved.environment,
        }

    # ------------------------------------------------------------------------- the console API

    @app.get("/api/v1/matrix")
    async def matrix() -> dict[str, Any]:
        """The measured security matrix, as `python -m agent_authz_broker.demo` wrote it.

        Served from the committed artifact rather than recomputed per request. Recomputing would
        mean clearing the demo database on a GET, which is a reset reachable without the reset
        token — the exact thing `/admin/reset` is gated for.
        """
        if not ARTIFACT.is_file():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "status": "no_matrix",
                    "hint": "run: python -m agent_authz_broker.demo",
                },
            )
        loaded: dict[str, Any] = json.loads(ARTIFACT.read_text(encoding="utf-8"))
        return loaded

    @app.get("/api/v1/chain/{scenario_id}")
    async def chain(scenario_id: str) -> dict[str, Any]:
        """The delegation chain for one scenario, and where authority was lost.

        Served from `artifacts/chains.json`, which the measurement run decodes out of the token each
        scenario actually minted. This route used to hold its own copy of the chains, written by
        hand from reading the scenarios. It was wrong: it named *alice* as the subject of the four
        tokens minted directly for *agent-7*, and nothing could have told anyone, because the copy
        was the only thing the screen consulted. The copy is gone.
        """
        if not CHAINS.is_file():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"status": "no_chains", "hint": "run: python -m agent_authz_broker.demo"},
            )
        loaded: dict[str, Any] = json.loads(CHAINS.read_text(encoding="utf-8"))
        found = loaded.get(scenario_id)
        if not isinstance(found, dict):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=scenario_id)
        return found

    @app.get("/api/v1/approvals")
    async def approvals() -> list[dict[str, Any]]:
        now = dt.datetime.now(tz=dt.UTC)
        async with AsyncSession(engine) as session:
            rows = await list_approvals(session)
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

    async def _require_approver_token(
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        """Gate approval-granting on a credential the test authority does not mint.

        **This route used to be open in every environment, and that falsified the headline claim.**
        The reasoning behind leaving it open was that the MCP surface cannot reach it — an agent can
        `request_approval` and cannot create one. But the agent is a process, not a tool list: it
        makes an ordinary HTTP POST to the same origin. A reviewer drove it end to end against the
        deployed configuration — mint a token, POST an approval naming its own subject, call
        `issue_credit` over real MCP — and read one row out of `irreversible_effect`. The confused
        deputy that `docs/threat-model.md` §6 called mitigated was reachable in one request.

        "No MCP route to it" is not the boundary that matters when both surfaces share one origin.
        The boundary that matters is whether the credential that grants an approval is one the agent
        can hold, so that is what this checks.

        Unset disables the route rather than leaving it open, exactly as the reset does: a demo
        whose approvals anyone can mint is a demo whose irreversible-effect count means nothing.
        The measurement (`make matrix`) creates approvals in-process and is unaffected.
        """
        expected = resolved.approver_token
        if expected is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        presented = (authorization or "").removeprefix("Bearer ").strip()
        if not presented or not hmac.compare_digest(presented, expected.get_secret_value()):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    @app.post(
        "/api/v1/approvals",
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(_require_approver_token)],
    )
    async def grant(body: GrantApproval) -> dict[str, Any]:
        """A human grants one approval, with a credential no agent token can stand in for.

        On the console API and not on MCP — the agent may ask for an approval and cannot create one
        — and now behind `AAB_APPROVER_TOKEN`, which the test authority does not mint and which no
        bearer token accepted by the MCP transport will satisfy. Still not an approver *identity*:
        one shared secret stands in for whatever authenticates staff in a real deployment, and the
        README says so rather than implying a story this build does not have.
        """
        async with AsyncSession(engine) as session, session.begin():
            approval = await create_approval(
                session,
                subject=body.subject,
                tool="issue_credit",
                account=body.account,
                amount=body.amount,
                approved_by=body.approved_by,
                ttl_seconds=body.ttl_seconds,
            )
            return {
                "approval_id": approval.approval_id,
                "expires_at": approval.expires_at.isoformat(),
            }

    @app.get("/api/v1/audit")
    async def audit(limit: int = 50) -> list[dict[str, Any]]:
        async with AsyncSession(engine) as session:
            rows = (
                await session.execute(
                    select(AuditEvent).order_by(desc(AuditEvent.at)).limit(min(limit, 200))
                )
            ).scalars()
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
                    "effective_scopes": row.effective_scopes.split()
                    if row.effective_scopes
                    else [],
                    "approval_id": row.approval_id,
                    "effect_id": row.effect_id,
                }
                for row in rows
            ]

    @app.get("/api/v1/effects")
    async def effects() -> dict[str, Any]:
        """The irreversible effects, counted from the table rather than reported by anything."""
        async with AsyncSession(engine) as session:
            rows = (
                await session.execute(
                    select(IrreversibleEffect).order_by(desc(IrreversibleEffect.created_at))
                )
            ).scalars()
            items = [
                {
                    "effect_id": row.effect_id,
                    "approval_id": row.approval_id,
                    "subject": row.subject,
                    "account": row.account,
                    "amount": row.amount,
                    "at": row.created_at.isoformat(),
                }
                for row in rows
            ]
        return {"count": len(items), "effects": items}

    @app.get("/api/v1/demo/tokens")
    async def demo_tokens() -> dict[str, Any]:
        """Mint one bearer token per scenario, **server-side**.

        The lab needs a way to hand a caller a token that is genuinely signed and genuinely wrong in
        one declared way. Signing happens here so the private key never leaves the process: the
        caller receives a bearer string, never key material, and the key is an in-memory Ed25519 key
        regenerated on every boot rather than a credential.

        **What this endpoint is, stated plainly:** an open token mint for a synthetic authority over
        a synthetic database. It would be indefensible in front of real data and it is exactly right
        in front of none. Every account, balance and approval this authority can reach is invented,
        and the only thing a token from here can cause is a row in a demonstration table.

        Refused in `production`, because a deployment that ever carried real data must not inherit
        a public token mint from the demo.
        """
        if resolved.environment == "production":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"status": "demo_tokens_disabled_in_production"},
            )
        read, flag, credit = "account:read", "account:flag", "credit:issue"
        here = resolved.resource_server_url
        return {
            "issuer": authority.issuer,
            "resource_server_url": here,
            "note": (
                "Synthetic authority, in-memory key, regenerated every boot. Nothing here is a "
                "credential for anything real."
            ),
            "tokens": {
                "valid_request": authority.mint_delegated(
                    chain=[("alice", [read, flag, credit])],
                    subject="agent-7",
                    audience=here,
                    scopes=[read, credit],
                ),
                "wrong_audience": authority.mint_delegated(
                    chain=[("alice", [read, flag, credit])],
                    subject="agent-7",
                    audience="https://other-service.example/mcp",
                    scopes=[read, credit],
                ),
                "scope_amplification": authority.mint_delegated(
                    chain=[("alice", [read, flag])],
                    subject="agent-7",
                    audience=here,
                    scopes=[read, flag, credit],
                ),
                "expired": authority.mint_flawed(
                    "expired", subject="agent-7", audience=here, scopes=[read, credit]
                ),
                "bad_signature": authority.mint_flawed(
                    "bad_signature", subject="agent-7", audience=here, scopes=[read, credit]
                ),
            },
        }

    # ------------------------------------------------------------------------------ demo reset

    async def _require_reset_token(
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        """Gate the reset on a token that is not an MCP credential.

        Unset disables the route entirely rather than leaving it open: a demo whose reset is
        reachable by anyone is a demo whose irreversible-effect count means nothing.
        """
        expected = resolved.admin_reset_token
        if expected is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        presented = (authorization or "").removeprefix("Bearer ").strip()
        # Constant-time comparison: a timing oracle on a demo reset is not a serious risk, but
        # writing the unsafe version here and the safe one elsewhere is how the unsafe one spreads.
        if not presented or not hmac.compare_digest(presented, expected.get_secret_value()):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    @app.post("/admin/reset", dependencies=[Depends(_require_reset_token)])
    async def reset() -> dict[str, Any]:
        """Clear the synthetic state so the demonstration can be run again.

        Not an MCP tool. Not in the tool list. Not reachable with any token the test authority
        mints. `tests/test_mcp_surface.py` fails the build if a tool named anything like this ever
        appears on the MCP surface.
        """
        async with AsyncSession(engine) as session, session.begin():
            await session.execute(delete(IrreversibleEffect))
            await session.execute(delete(AuditEvent))
            await session.execute(delete(Approval))
            await session.execute(delete(RateLimitCounter))
        return {"status": "reset"}

    # --------------------------------------------------------------------------- the MCP surface

    # Mounted at the ROOT, and mounted last.
    #
    # The SDK's app already serves `/mcp` and `/.well-known/oauth-protected-resource/mcp` at those
    # absolute paths. Mounting it under `/mcp` produced `/mcp/mcp` — which answered 404 to a real
    # client — and would have buried the RFC 9728 protected-resource metadata where no client looks
    # for it. Starlette matches in declaration order, so every route above wins first and only what
    # they do not claim reaches the MCP app.
    app.mount("/", mcp.streamable_http_app())
    return app
