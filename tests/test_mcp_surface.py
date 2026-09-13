"""What the server advertises, what it refuses to advertise, and what its verifier reports.

These are the checks that need no database. Everything here is read off the *live server object* —
the tool list it will actually serve, the input schema it will actually publish — rather than off a
constant this file also wrote. A test that compares a constant with itself is decoration; the point
is that adding a seventh tool, or a seventh field, breaks the build.

The behavioural half of ADR-001 (audience, attenuation, approval, the race) lives in
``test_kill_criteria.py`` against real PostgreSQL, and counts rows rather than trusting anything
reported here. This file covers the half that is structural: the shape of the surface an agent is
offered in the first place.
"""

from __future__ import annotations

import re

import pytest
from mcp.server.mcpserver import MCPServer
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from agent_authz_broker.config import Settings
from agent_authz_broker.domain import IRREVERSIBLE_TOOLS
from agent_authz_broker.mcp_server import BrokerTokenVerifier, create_server

# Imported under another name only because pytest tries to collect any module-level class whose
# name starts with "Test", and warns when it cannot. The class is a signer, not a test case.
from agent_authz_broker.testauthority import TestAuthority as Authority

pytestmark = pytest.mark.asyncio

RESOURCE = "https://broker.test/mcp"
ANOTHER_RESOURCE = "https://other-service.test/mcp"

READ = "account:read"
FLAG = "account:flag"
CREDIT = "credit:issue"

#: The surface an agent is allowed to see. Compared against what the server advertises.
EXPECTED_TOOLS = {
    "ping",
    "read_account",
    "flag_account",
    "request_approval",
    "read_approval",
    "issue_credit",
}

#: Reset is HTTP admin infrastructure behind its own bearer token. If any of these ever appears in
#: an advertised tool name, an agent can restore the demo state — and an agent that can reset the
#: record of what it did is an agent whose audit trail means nothing.
FORBIDDEN_NAME_PARTS = ("admin_reset", "reset", "restore")

#: Word parts by which a caller might try to assert that a human agreed. Parts rather than exact
#: names, so ``approval_id``, ``pre_approved``, ``consent_token`` and ``authorised_by`` are all
#: caught without anyone having to enumerate the spellings in advance.
ASSERTION_OF_AUTHORITY = re.compile(r"approv|consent|authori[sz]|permit|sanction", re.IGNORECASE)


@pytest.fixture
def authority() -> Authority:
    """A real Ed25519 signer, so "wrong audience" means a valid signature over a different aud."""
    return Authority()


@pytest.fixture
def settings() -> Settings:
    """Configuration supplied here rather than read from the environment.

    Every value this file depends on is passed explicitly, and init arguments outrank the
    environment and the dotenv file in pydantic-settings' precedence — so the audience under test
    is the one written above, not whatever a developer happens to have exported. A surface test
    whose expected audience comes from somebody's machine is not a test of the surface.
    """
    return Settings(
        environment="ci",
        postgres_dsn=SecretStr("postgresql+asyncpg://unused:unused@127.0.0.1:1/unused"),
        resource_server_url=RESOURCE,
    )


@pytest.fixture
def engine(settings: Settings) -> AsyncEngine:
    """An engine that is never connected.

    SQLAlchemy does not open a connection when the engine is constructed, and nothing in this file
    calls a tool that would need one. That is deliberate: the advertised surface must be inspectable
    without a database, or it cannot be checked in CI before the database exists.
    """
    return create_async_engine(settings.postgres_dsn.get_secret_value())


@pytest.fixture
def server(settings: Settings, engine: AsyncEngine, authority: Authority) -> MCPServer:
    return create_server(settings, engine, {authority.issuer: authority.jwks()})


@pytest.fixture
def verifier(authority: Authority) -> BrokerTokenVerifier:
    return BrokerTokenVerifier(
        authority_jwks={authority.issuer: authority.jwks()}, audience=RESOURCE
    )


# ------------------------------------------------------------------------------ the advertised set


async def test_the_advertised_tool_list_is_exactly_the_six(server: MCPServer) -> None:
    """The server offers these six and nothing else.

    Read from ``server.list_tools()``, which is what a client receives, so a tool registered by a
    later edit shows up here whether or not anybody updated a constant.
    """
    advertised = sorted(tool.name for tool in await server.list_tools())

    assert advertised == sorted(EXPECTED_TOOLS)


async def test_no_reset_shaped_tool_is_reachable_over_mcp(server: MCPServer) -> None:
    """The admin reset is not in the tool list, under any name that reads like one.

    ADR-001 lists "the admin reset being unreachable through MCP" among the results that must hold.
    The substring match is the guard against the plausible regression, which is not somebody adding
    ``admin_reset`` but somebody adding ``reset_demo`` in a hurry before a presentation.
    """
    advertised = [tool.name for tool in await server.list_tools()]

    for part in FORBIDDEN_NAME_PARTS:
        offenders = [name for name in advertised if part in name.lower()]
        assert offenders == [], f"an agent can reach {offenders} over MCP"


# --------------------------------------------------------------------- the structural AI boundary


async def test_issue_credit_takes_exactly_account_and_amount(server: MCPServer) -> None:
    """The irreversible tool's input schema has two fields, and both are facts about the act.

    This is the structural half of the AI boundary. The behavioural half — that an approval is
    looked up in the database and consumed exactly once — is in ``test_kill_criteria.py``, and it is
    the half that actually stops money moving. This half stops the *other* failure: a schema with
    somewhere to put ``approval_id`` invites a future handler to read it, and the day one does, the
    agent is back in charge of consent without anybody having decided that it should be.
    """
    tool = next(tool for tool in await server.list_tools() if tool.name == "issue_credit")

    assert set(tool.input_schema["properties"]) == {"account", "amount"}


async def test_issue_credit_has_no_field_by_which_a_caller_could_claim_approval(
    server: MCPServer,
) -> None:
    """No field name on the irreversible tool is a place to assert that a human agreed.

    Matched on word parts rather than exact names so that the check survives whatever somebody
    calls it: ``approval_id``, ``pre_approved``, ``consent``, ``authorized_by``, ``authorised_by``.
    """
    tool = next(tool for tool in await server.list_tools() if tool.name == "issue_credit")

    properties = tool.input_schema["properties"]
    offenders = [name for name in properties if ASSERTION_OF_AUTHORITY.search(name)]

    assert offenders == [], f"issue_credit lets a caller assert authority through {offenders}"


async def test_no_irreversible_tool_offers_a_field_that_asserts_authority(
    server: MCPServer,
) -> None:
    """The same guard, applied to every irreversible tool rather than to ``issue_credit`` by name.

    The set comes from ``domain.IRREVERSIBLE_TOOLS``, so a second irreversible tool added later is
    covered the moment it is declared as one — which is the way this guard would otherwise be
    defeated, by adding a tool nobody thought to point the first test at.

    It is deliberately *not* applied to every tool. ``read_approval`` takes an ``approval_id`` and
    should: it reads state and cannot cause an effect, and naming an approval to look one up is not
    the same act as claiming one was granted. A rule blunt enough to forbid both would be turned off
    the first time it was inconvenient, which is worse than a rule that draws the line correctly.
    """
    advertised = {tool.name: tool for tool in await server.list_tools()}

    assert set(advertised) >= IRREVERSIBLE_TOOLS, "the irreversible tool is not advertised at all"

    for name in IRREVERSIBLE_TOOLS:
        properties = advertised[name].input_schema.get("properties", {})
        offenders = [field for field in properties if ASSERTION_OF_AUTHORITY.search(field)]
        assert offenders == [], f"{name} lets a caller assert authority through {offenders}"


# ------------------------------------------------------------------------------- the auth wiring


async def test_the_server_enforces_its_configured_audience_at_the_transport(
    server: MCPServer, settings: Settings
) -> None:
    """``validate_token_resource`` is on, and set explicitly rather than left to a default.

    Defence in depth, not the primary control: the SDK's check works only because
    ``BrokerTokenVerifier`` reports ``AccessToken.resource`` honestly, and the authoritative
    audience decision is made in ``authz.py``. Asserting it here records that both exist, so that
    removing one later is a visible choice.
    """
    auth = server.settings.auth

    assert auth is not None
    assert auth.validate_token_resource is True
    assert str(auth.resource_server_url).removesuffix("/") == settings.resource_server_url


async def test_the_deployed_transport_is_streamable_http(server: MCPServer) -> None:
    """The ASGI app exists, because stdio is not a thing you put behind HTTPS."""
    assert server.streamable_http_app() is not None


# ------------------------------------------------------------------------------ the token verifier


async def test_the_verifier_refuses_a_token_signed_with_a_key_it_does_not_trust(
    verifier: BrokerTokenVerifier, authority: Authority
) -> None:
    """Impeccable Ed25519 cryptography, under the right ``kid``, with the wrong key."""
    forged = authority.mint_flawed(
        "bad_signature", subject="alice", audience=RESOURCE, scopes=[READ, CREDIT]
    )

    assert await verifier.verify_token(forged) is None


async def test_the_verifier_refuses_an_expired_token(
    verifier: BrokerTokenVerifier, authority: Authority
) -> None:
    expired = authority.mint_flawed(
        "expired", subject="alice", audience=RESOURCE, scopes=[READ, CREDIT]
    )

    assert await verifier.verify_token(expired) is None


async def test_the_verifier_accepts_a_valid_token_and_reports_its_subject_and_resource(
    verifier: BrokerTokenVerifier, authority: Authority
) -> None:
    token = authority.mint(subject="alice", audience=RESOURCE, scopes=[READ, CREDIT])

    access = await verifier.verify_token(token)

    assert access is not None
    assert access.subject == "alice"
    assert access.resource == RESOURCE
    assert set(access.scopes) == {READ, CREDIT}


async def test_the_verifier_reports_the_attenuated_set_not_the_leaf_claim(
    verifier: BrokerTokenVerifier, authority: Authority
) -> None:
    """The delegated token claims ``credit:issue``. Its delegator never had it.

    ``AccessToken.scopes`` is what the SDK's own ``required_scopes`` gate reads, and what any
    middleware or log line downstream reads. If the leaf's claim went there, every one of those
    readers would be checking against the amplified set — ADR-001's second bug class, reintroduced
    one layer below the code that refuses it. So the attenuated set is what goes on the wire object.
    """
    delegated = authority.mint_delegated(
        chain=[("alice", [READ, FLAG])],
        subject="agent-7",
        audience=RESOURCE,
        scopes=[READ, FLAG, CREDIT],
    )

    access = await verifier.verify_token(delegated)

    assert access is not None
    assert set(access.scopes) == {READ, FLAG}
    assert CREDIT not in access.scopes, "the leaf's scope claim reached AccessToken.scopes"


async def test_the_verifier_reports_a_foreign_audience_rather_than_hiding_it(
    verifier: BrokerTokenVerifier, authority: Authority
) -> None:
    """A token minted for another service reports *that* service as its resource.

    The verifier could quietly report this server's own URL and the token would sail through the
    SDK's transport check. Reporting the audience the token actually carries is what makes
    ``validate_token_resource`` worth having — and it is still not the control ADR-001 relies on,
    which is the audience comparison in ``authz.py``.
    """
    elsewhere = authority.mint(subject="alice", audience=ANOTHER_RESOURCE, scopes=[READ, CREDIT])

    access = await verifier.verify_token(elsewhere)

    assert access is not None, "this token is authentic; it is simply not addressed to us"
    assert access.resource == ANOTHER_RESOURCE
