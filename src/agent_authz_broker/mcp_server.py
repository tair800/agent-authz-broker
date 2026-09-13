"""The MCP surface: six tools, and not one of them decides anything.

This is deliberately the thinnest layer in the repository. The three tools that can be refused —
``read_account``, ``flag_account`` and ``issue_credit`` — hand the question to
:func:`agent_authz_broker.effects.call_tool` and render the answer; not one of them re-derives a
scope, re-reads an audience, or goes looking for an approval itself. That is not tidiness for its
own sake — an authorization check written in two places is a check that will eventually disagree
with itself, and the half that disagrees is the half an attacker uses.

The other three cause no effect and so have no decision to delegate: ``ping`` and
``request_approval`` reach no state at all, and ``read_approval`` reads approval state scoped to
the caller's own verified subject, which is data scoping rather than an authorization decision.

Three things here are load-bearing.

**The verifier reports attenuated scope.** :class:`BrokerTokenVerifier` puts the *effective* scope
set on the SDK's ``AccessToken``, never the leaf token's ``scope`` claim. Anything downstream that
reads ``AccessToken.scopes`` — the SDK's own ``required_scopes`` gate, a log line, a middleware
somebody adds next year — would otherwise be reading the claim this whole project exists to
disbelieve.

**``issue_credit`` takes two fields and there is nowhere to put a third.** No ``approval_id``, no
``approved``, no ``justification``. The server finds the approval in its own database from the
verified subject and the arguments, so a caller cannot assert one — not because the assertion is
rejected, but because the schema gives it no place to live.

**There is no admin reset tool.** Reset is HTTP admin infrastructure with its own bearer token, and
it is not advertised here. ``tests/test_mcp_surface.py`` asserts against the server's *advertised*
tool list rather than a constant, so a reset tool added later fails the build rather than the
threat model.
"""

from __future__ import annotations

import contextlib
import datetime as dt
from typing import Annotated, Literal

from jwt import PyJWKSet
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import AnyHttpUrl, BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from agent_authz_broker import __version__
from agent_authz_broker.approvals import get_approval
from agent_authz_broker.authz import HARDENED, Decision, effective_scopes
from agent_authz_broker.config import Settings
from agent_authz_broker.domain import DenialReason
from agent_authz_broker.effects import ToolOutcome, call_tool, record_transport_refusal
from agent_authz_broker.tokens import verify_token

__all__ = ["TOOL_NAMES", "BrokerTokenVerifier", "create_server"]

#: The complete advertised surface, for a reader. The build is graded on what the server actually
#: advertises, not on this tuple — a constant that agrees with itself proves nothing.
TOOL_NAMES = (
    "ping",
    "read_account",
    "flag_account",
    "request_approval",
    "read_approval",
    "issue_credit",
)


class Outcome(BaseModel):
    """The authorization decision, rendered the same way by every tool that can be refused.

    ``effective_scopes`` is reported on denials too, because the question a caller actually has
    after a refusal is *what did you think I had* — and publishing the attenuated set is how the
    delegation rule is visible rather than merely asserted.
    """

    decision: str
    reason: str | None = None
    effective_scopes: list[str] = Field(default_factory=list)
    audit_id: str
    effect_id: str | None = None


class ServerIdentity(BaseModel):
    """Who this server is, and — the useful part — which audience value it will accept."""

    server: str
    version: str
    resource_server_url: str
    trusted_issuers: list[str]
    policy: str


class AccountView(BaseModel):
    """A synthetic account. Invented holder, invented balance, no ledger behind it."""

    account: str
    holder: str
    balance: int


class AccountResult(BaseModel):
    """The account when the call was allowed; the reason and nothing else when it was not."""

    outcome: Outcome
    account: AccountView | None = None


class FlagResult(BaseModel):
    """The record of a flag is the audit event, whose id is returned as ``review_ref``."""

    outcome: Outcome
    flagged: bool
    review_ref: str | None = None
    note: str


class ApprovalRequestResult(BaseModel):
    """What a human would have to approve, and the flat statement that nothing was approved.

    ``granted`` is typed ``Literal[False]``, so the field cannot carry any other value and the
    advertised output schema says ``const: false``. A tool that can only ever answer "no" is a
    clearer contract than one that answers "no" today.
    """

    granted: Literal[False] = False
    subject: str
    tool: str
    account: str
    amount: int
    note: str


class ApprovalState(BaseModel):
    """An approval's lifecycle position, read from the database rather than from the caller."""

    approval_id: str
    state: Literal["pending", "expired", "consumed", "not_found"]
    subject: str | None = None
    tool: str | None = None
    account: str | None = None
    amount: int | None = None
    expires_at: str | None = None


class CreditResult(BaseModel):
    """The irreversible tool's answer. ``issued`` is true only when a row exists to point at."""

    outcome: Outcome
    issued: bool
    account: str
    amount: int


#: The synthetic account directory. ADR-001 fixes the whole domain as fake — invented names,
#: invented balances, no payment rail — so that nothing here needs an argument about whether the
#: irreversible action "really" matters. It is a module constant rather than a table because it is
#: read-only demonstration data and a migration for it would imply it were more than that.
_ACCOUNTS: dict[str, AccountView] = {
    "ACC-1": AccountView(account="ACC-1", holder="Rowan Ashby", balance=1250),
    "ACC-2": AccountView(account="ACC-2", holder="Imogen Vale", balance=430),
    "ACC-3": AccountView(account="ACC-3", holder="Teodor Marek", balance=9075),
}


class BrokerTokenVerifier:
    """Adapts :func:`agent_authz_broker.tokens.verify_token` to the SDK's ``TokenVerifier``.

    Two fields on the returned ``AccessToken`` are deliberate, and both are about not lying to code
    that runs after this one.

    ``scopes`` is the **attenuated effective set**, computed by intersecting the whole delegation
    chain — never the leaf's ``scope`` claim. The SDK's own ``required_scopes`` gate reads this
    field, as would any middleware or log line downstream. Populating it from the leaf claim would
    hand every one of those readers the amplified set, which is exactly the bug class ADR-001 names
    second and exactly the reason this repository exists. The set is put here once, attenuated, so
    that nothing downstream has to remember to attenuate it again.

    ``resource`` is the token's own audience: this server's identifier when the token names it,
    and otherwise the first audience the token actually carries. Reporting it honestly — including
    when it is somebody else's — is what lets the SDK's ``validate_token_resource`` refuse a
    wrong-audience token at the transport. That check is defence in depth and nothing more: it
    depends on this method being honest, and a guard that depends on the thing it guards should
    never be the only one. The authoritative audience check is in ``authz.py``, on claims the
    decision function reads for itself.

    Verification failures return ``None`` rather than a reason — the SDK's contract has no place for
    one — **and are written to the audit trail here**, because this is the only place that sees
    them. A refusal at this layer never reaches ``effects.call_tool``: the SDK rejects the request
    first, so the audit row `call_tool` would have written is never written.

    That was a real hole, and it was invisible from inside the test suite. The adversarial suite and
    the matrix run both call ``call_tool`` directly, so in the harness the flagship attack — a valid
    token minted for another resource server — *was* audited, and `artifacts/audit.json` carries an
    ``audience_mismatch`` row. Over the real transport it produced **nothing**: no row for a wrong
    audience, a bad signature, an expired token or a forged one. Every probe this project exists to
    detect was the one kind of event the trail could not show, while the README said *"every
    decision, refusals included"*. A reviewer drove the real client and counted the rows.
    """

    def __init__(
        self,
        *,
        authority_jwks: dict[str, PyJWKSet],
        audience: str,
        engine: AsyncEngine | None = None,
    ) -> None:
        """Bind the verifier to a key set, to this server's own identity, and to the audit trail.

        Args:
            authority_jwks: Trusted issuer -> its key set. An issuer absent here is refused.
            audience: This server's identifier, for reporting ``resource`` truthfully.
            engine: Where refusals at this layer are recorded. Optional only so that a test can
                construct a verifier without a database; ``create_server`` always supplies one, and
                a verifier without it refuses exactly as before but silently.
        """
        self._jwks = authority_jwks
        self._audience = audience
        self._engine = engine

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a bearer token, or return ``None`` if it is not authentic.

        Args:
            token: The raw bearer string from the ``Authorization`` header.

        Returns:
            An ``AccessToken`` carrying the attenuated scopes, or ``None`` when the signature,
            issuer, expiry, delegation chain **or audience** does not check out.

        **The audience is refused here, not only reported here.** An earlier version set
        ``resource`` truthfully and left the decision to the SDK's ``validate_token_resource``. That
        is real enforcement, but it covered only the tools that go on to call
        ``effects.call_tool``: ``request_approval`` and ``read_approval`` never reach `authz.py`, so
        for them a setting in somebody else's middleware was the *only* thing standing between a
        token minted for another service and this server's approval state. A review found it. The
        check now runs before any tool does, and ``validate_token_resource`` stays on as the second
        line rather than the first.
        """
        claims = verify_token(token, jwks_by_issuer=self._jwks)
        if isinstance(claims, str):
            # No subject and no token id: the token did not authenticate, so every identifier in it
            # is an attacker's assertion. Recording them as though they were established is how an
            # audit trail starts lying under exactly the conditions it exists for.
            await self._audit(reason=claims, subject=None, token_id=None)
            return None

        if self._audience not in claims.audience:
            await self._audit(
                reason="audience_mismatch",
                subject=claims.subject,
                token_id=claims.token_id,
            )
            return None

        granted = effective_scopes(claims, attenuate=True)
        resource = self._audience

        return AccessToken(
            token=token,
            # This authority issues no client identity, so the subject stands in for one. Saying so
            # is better than inventing a client_id that no other system would recognise.
            client_id=claims.subject,
            scopes=sorted(granted),
            expires_at=claims.expires_at,
            resource=resource,
            subject=claims.subject,
            claims={
                "iss": claims.issuer,
                "jti": claims.token_id,
                "act": [link.subject for link in claims.chain],
            },
        )

    async def _audit(
        self, *, reason: DenialReason, subject: str | None, token_id: str | None
    ) -> None:
        """Record a refusal made at the transport, without letting it break the refusal.

        The tool is unknown at this layer — the SDK has not routed the request yet — so the row
        names the layer instead of guessing. ``effective_scopes`` is empty because no authority was
        established, which is the honest value rather than a convenient one.

        A failure to write the row is swallowed on purpose. A database that is down must not turn a
        *refusal* into a 500 that a caller could read as something other than "no": failing closed
        is the behaviour, and the audit row is the record of it, not the mechanism.
        """
        if self._engine is None:
            return
        with contextlib.suppress(Exception):
            await record_transport_refusal(
                self._engine, reason=reason, subject=subject, token_id=token_id
            )


def _caller() -> AccessToken:
    """The verified token behind the current call.

    The raw string is handed on to ``effects.call_tool`` unchanged rather than being summarised
    here. The decision is computed from the token, and a layer that passed along its own summary
    would be quietly deciding what the decision function gets to see.

    Raises:
        ToolError: When no authenticated token is in context, which the transport should already
            have prevented. Failing here rather than proceeding with an anonymous call is the
            difference between a bug and a hole.
    """
    access = get_access_token()
    if access is None:
        raise ToolError("this tool requires a verified bearer token")
    return access


def _outcome(result: ToolOutcome) -> Outcome:
    """Render a :class:`ToolOutcome` for the wire without adding to it or reinterpreting it."""
    return Outcome(
        decision=str(result.decision),
        reason=result.reason,
        effective_scopes=sorted(result.effective_scopes),
        audit_id=result.audit_id,
        effect_id=result.effect_id,
    )


def create_server(
    settings: Settings,
    engine: AsyncEngine,
    authority_jwks: dict[str, PyJWKSet],
) -> MCPServer:
    """Build the MCP resource server with its six tools and its auth configuration.

    Args:
        settings: Typed configuration; ``resource_server_url`` is the audience every token must
            name and is passed to the decision function on every call.
        engine: The database the approval and the effect live in. The tools hand it to
            ``effects.call_tool``; only ``read_approval`` opens a session of its own, to read.
        authority_jwks: Trusted issuer -> its key set, fetched by the caller rather than by a tool.

    Returns:
        A configured ``MCPServer``. Serve it over Streamable HTTP with ``streamable_http_app()``.

    Raises:
        ValueError: If no trusted issuer was supplied. A resource server with an empty key set
            would refuse every token, which is safe but is a misconfiguration, not a policy.
    """
    issuers = sorted(authority_jwks)
    if not issuers:
        raise ValueError("create_server needs at least one trusted issuer's key set")

    audience = settings.resource_server_url
    verifier = BrokerTokenVerifier(authority_jwks=authority_jwks, audience=audience, engine=engine)

    auth = AuthSettings(
        # The authority that signs the tokens this server accepts. It is not run here: ADR-002
        # records that no authorization server is built, and a deterministic test authority with
        # real Ed25519 keys stands in.
        issuer_url=AnyHttpUrl(issuers[0]),
        resource_server_url=AnyHttpUrl(audience),
        # Defence in depth, and set explicitly because leaving it unset warns and behaves as False.
        # The authoritative audience check is ours, in authz.py, on claims the decision function
        # reads itself; this one only works because BrokerTokenVerifier populates `resource`
        # honestly, and a guard that depends on the thing it guards is not one to stand alone on.
        validate_token_resource=True,
        # No blanket scope gate. Authority here is per tool and is computed in authz.py from the
        # attenuated chain; a coarse gate at the transport would answer a different question and
        # invite somebody to believe it had answered this one.
        required_scopes=None,
    )

    server: MCPServer = MCPServer(
        name="agent-authz-broker",
        title="Agent Authorization Broker",
        version=__version__,
        instructions=(
            "An agent may request an action here; it cannot manufacture the authority to perform "
            "one. Scope comes from the delegation chain, not from the token's own claim, and the "
            "irreversible tool runs only against a human approval already recorded in this "
            "server's database. There is no argument, header or wording that substitutes for one."
        ),
        token_verifier=verifier,
        auth=auth,
    )

    @server.tool(title="Ping")
    def ping() -> ServerIdentity:
        """Server identity, and the audience value this server will accept.

        One of the three tools with no scope requirement — the others being ``request_approval``
        and ``read_approval`` — and so one of the three that does not consult ``effects.call_tool``:
        none of them can cause an effect, so there is no decision to delegate. It still needs an
        authentic token, because the transport authenticates every MCP request; "no scope" is not
        "no auth".

        Publishing ``resource_server_url`` is the point of it. A client that cannot see which
        audience a server enforces ends up discovering it by replaying a token, which is the
        failure this repository is about.
        """
        return ServerIdentity(
            server="agent-authz-broker",
            version=__version__,
            resource_server_url=audience,
            trusted_issuers=issuers,
            policy=HARDENED.name,
        )

    @server.tool(title="Read account")
    async def read_account(account: str) -> AccountResult:
        """Read a synthetic account. Requires ``account:read`` in the effective scope set.

        The decision is made by ``effects.call_tool`` and the account is rendered only after it
        comes back allowed. Reading the directory first and deciding afterwards would be the same
        code with the window an attacker wants in the middle of it.
        """
        result = await call_tool(
            engine,
            token=_caller().token,
            tool="read_account",
            arguments={"account": account},
            policy=HARDENED,
            authority_jwks=authority_jwks,
            audience=audience,
        )
        outcome = _outcome(result)
        if result.decision is not Decision.ALLOWED:
            return AccountResult(outcome=outcome)
        return AccountResult(outcome=outcome, account=_ACCOUNTS.get(account))

    @server.tool(title="Flag account for review")
    async def flag_account(account: str, reason: str) -> FlagResult:
        """Enqueue a human review of an account. Requires ``account:flag``.

        **Deliberately not irreversible, and deliberately not a block.** It creates work for a
        person and changes nothing else, so it needs no approval and has none. A fraud-adjacent
        tool that could freeze an account by itself would be an agent with an irreversible effect
        nobody signed off, which is the shape of the problem rather than a demonstration of it.

        The durable record of the flag is the audit event ``effects.call_tool`` writes, and its id
        is returned as ``review_ref``. This build has no separate review queue table, and rather
        than imply one, the note says so.
        """
        result = await call_tool(
            engine,
            token=_caller().token,
            tool="flag_account",
            arguments={"account": account, "reason": reason},
            policy=HARDENED,
            authority_jwks=authority_jwks,
            audience=audience,
        )
        outcome = _outcome(result)
        allowed = result.decision is Decision.ALLOWED
        return FlagResult(
            outcome=outcome,
            flagged=allowed,
            review_ref=result.audit_id if allowed else None,
            note=(
                "Recorded as an audit event for a human to pick up. Nothing was blocked, frozen "
                "or reversed, and this build has no separate review queue."
            ),
        )

    @server.tool(title="Request an approval")
    def request_approval(account: str, amount: int) -> ApprovalRequestResult:
        """State what the agent wants a human to approve. **It does not grant anything.**

        A human grants approvals out of band, through the console API, which is not reachable over
        MCP by any tool on this server. The distinction between asking for authority and minting it
        is the entire subject of ADR-001, so this tool is built to be incapable of the second:
        ``granted`` is ``Literal[False]``, and nothing here touches the approval table.

        ``subject`` is taken from the verified token, never from an argument, so an agent cannot
        ask for an approval in somebody else's name.

        **Limitation, stated rather than papered over:** this call persists nothing. There is no
        approval-request table in this build, so it echoes the request a human would have to grant
        and returns. The security property does not depend on it — an unrecorded request grants
        exactly as much as a recorded one, which is nothing.
        """
        access = _caller()
        return ApprovalRequestResult(
            subject=access.subject or access.client_id,
            tool="issue_credit",
            account=account,
            amount=amount,
            note=(
                "Nothing was approved and nothing was recorded. A human must create this approval "
                "out of band through the console API; this server cannot create one on an agent's "
                "behalf, and no tool here can reach the one that does."
            ),
        )

    @server.tool(title="Read an approval")
    async def read_approval(approval_id: str) -> ApprovalState:
        """Read an approval's state: pending, expired, consumed, or not found.

        Reads the approval table directly because there is no decision to delegate — this returns
        state, and it cannot cause an effect. The filter on the caller's own subject is data
        scoping rather than authorization: whether the agent can see an approval changes nothing
        about whether the approval authorises anything, which is settled in ``effects.call_tool``
        against the database on every irreversible call.

        An approval belonging to another subject reports ``not_found`` rather than a refusal, so
        the tool cannot be used to enumerate which approvals exist for whom.
        """
        access = _caller()
        subject = access.subject or access.client_id
        async with AsyncSession(engine, expire_on_commit=False) as session:
            approval = await get_approval(session, approval_id)
            if approval is None or approval.subject != subject:
                return ApprovalState(approval_id=approval_id, state="not_found")

            state: Literal["pending", "expired", "consumed"]
            if approval.consumed_at is not None:
                state = "consumed"
            elif approval.expires_at <= dt.datetime.now(tz=dt.UTC):
                state = "expired"
            else:
                state = "pending"
            return ApprovalState(
                approval_id=approval.approval_id,
                state=state,
                subject=approval.subject,
                tool=approval.tool,
                account=approval.account,
                amount=approval.amount,
                expires_at=approval.expires_at.isoformat(),
            )

    @server.tool(title="Issue a credit")
    async def issue_credit(
        account: Annotated[str, Field(description="The synthetic account to credit.")],
        amount: Annotated[
            int,
            Field(
                description=(
                    "Minor units. The server matches this against a recorded human approval; an "
                    "approval for one amount does not authorise another."
                )
            ),
        ],
    ) -> CreditResult:
        """Credit a synthetic account. **The irreversible tool.**

        Requires ``credit:issue`` in the effective scope set *and* a matching, unexpired,
        unconsumed human approval in this server's own database. The approval is consumed in the
        same transaction that writes the effect, so one approval authorises exactly one credit even
        when two calls arrive at once.

        **The input schema is exactly ``account`` and ``amount``, and that is a security property.**
        There is no ``approval_id``, no ``approved`` flag, no ``human_confirmed``, and no
        justification field that could be read as authority. The server looks the approval up
        itself, keyed on the subject from the verified token plus these two arguments. A caller
        therefore has no way to assert that a human agreed — not because the assertion would be
        rejected, but because the schema gives it nowhere to live, and a field that does not exist
        cannot be trusted by mistake in a later refactor.

        Args:
            account: The synthetic account to credit.
            amount: The amount in minor units; it must match the approval exactly.

        Returns:
            The decision, and ``issued`` true only when an effect row exists to point at.
        """
        result = await call_tool(
            engine,
            token=_caller().token,
            tool="issue_credit",
            arguments={"account": account, "amount": amount},
            policy=HARDENED,
            authority_jwks=authority_jwks,
            audience=audience,
        )
        outcome = _outcome(result)
        return CreditResult(
            outcome=outcome,
            issued=result.decision is Decision.ALLOWED and result.effect_id is not None,
            account=account,
            amount=amount,
        )

    return server
