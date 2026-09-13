"""The two boundaries a read-only security review found open, and the parsing it found brittle.

Each test here exists because something was **wrong**, not because a checklist said to cover it.
Delete the fix and the test goes red; that is the only property that makes a test evidence.

1. **An agent could manufacture the approval.** ``POST /api/v1/approvals`` was unauthenticated in
   every environment. The MCP surface cannot reach it -- but the agent is a process, not a tool
   list, and an ordinary HTTP POST to the same origin created an approval naming its own subject,
   which ``issue_credit`` then spent. One row in ``irreversible_effect``, against the repository's
   headline claim.
2. **The audit trail was blind to exactly the attacks this project is about.** A token refused at
   the transport never reaches ``effects.call_tool``, so a wrong audience, a forged signature and
   an expired token each produced *no* audit row on the deployed path. The suite could not see it,
   because the suite calls ``call_tool`` directly.
3. **The parse that runs before the signature check was reachable and fragile.** A deeply nested
   ``act`` raised an uncaught ``RecursionError`` before any key was consulted.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from agent_authz_broker.app import create_app
from agent_authz_broker.config import Settings
from agent_authz_broker.db.models import AuditEvent
from agent_authz_broker.mcp_server import BrokerTokenVerifier
from agent_authz_broker.testauthority import TestAuthority as Authority
from agent_authz_broker.tokens import MAX_TOKEN_BYTES, verify_token

RESOURCE = "https://broker.test/mcp"
ANOTHER_RESOURCE = "https://other-service.test/mcp"
APPROVER = "an-approver-secret-that-no-agent-holds"
CREDIT = "credit:issue"

GRANT = {"subject": "agent-7", "account": "ACC-1041", "amount": 500}


def _settings(**overrides: Any) -> Settings:
    return Settings(resource_server_url=RESOURCE, **overrides)


def _client(settings: Settings) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(settings)),
        base_url="http://broker.test",
    )


# ------------------------------------------------------ 1. the approval cannot be self-granted


@pytest.mark.asyncio
async def test_no_approval_can_be_granted_when_no_approver_credential_is_configured() -> None:
    """Unset closes the route rather than opening it.

    The reset endpoint already worked this way and this one did not, which was the whole finding: a
    demo whose approvals anyone can mint is a demo whose irreversible-effect count means nothing.
    """
    async with _client(_settings()) as client:
        response = await client.post("/api/v1/approvals", json=GRANT)

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_an_agents_own_bearer_token_cannot_grant_it_an_approval() -> None:
    """The credential that approves is not one the agent can hold.

    The token presented here is *valid*: real Ed25519 signature, this server's audience, unexpired,
    carrying the scope ``issue_credit`` requires. It is refused anyway, because authority to act and
    authority to approve are different authorities, and the confused deputy is what happens when one
    is allowed to stand in for the other.
    """
    authority = Authority()
    token = authority.mint(subject="agent-7", audience=RESOURCE, scopes=[CREDIT])

    async with _client(_settings(approver_token=SecretStr(APPROVER))) as client:
        response = await client.post(
            "/api/v1/approvals", json=GRANT, headers={"Authorization": "Bearer " + token}
        )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_the_configured_approver_credential_is_the_only_thing_that_grants() -> None:
    """That the refusals above are a gate, and not simply a broken route."""
    settings = _settings(approver_token=SecretStr(APPROVER))
    async with _client(settings) as client:
        wrong = await client.post(
            "/api/v1/approvals", json=GRANT, headers={"Authorization": "Bearer not-the-secret"}
        )
        missing = await client.post("/api/v1/approvals", json=GRANT)

    assert wrong.status_code == 401
    assert missing.status_code == 401


# ------------------------------------------- 3. the parse that runs before the signature check


def _deep_act_payload(depth: int) -> bytes:
    """A payload with ``depth`` nested ``act`` links, assembled as text.

    Not with ``json.dumps`` over nested dicts: the encoder recurses as well, so building the attack
    input crashes the test before the attack reaches the code under test. An attacker has no such
    problem -- they write the bytes.
    """
    link = '{"sub":"l","scope":"account:read","act":'
    head = '{"iss":"x","sub":"s","aud":"' + RESOURCE + '","act":'
    return (
        head + link * depth + '{"sub":"root","scope":"account:read"}' + "}" * (depth + 1)
    ).encode()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _token(payload: bytes) -> str:
    header = _b64(json.dumps({"alg": "EdDSA", "kid": "k"}).encode())
    return header + "." + _b64(payload) + ".sig"


def test_a_deeply_nested_delegation_chain_is_refused_on_size_before_it_is_parsed() -> None:
    """The finding, and the guard that actually closes it.

    A deeply nested ``act`` raised ``RecursionError`` inside the *unverified* decode --  not a
    ``PyJWTError``, so it escaped ``verify_token`` as a 500 with no audit row, and it needed no
    signing key because the crash happens before the issuer is read. The chain-depth cap of ten did
    not help: it bounds the intersection, and the parse runs first.

    The size cap is what closes it. Nesting deep enough to exhaust the stack needs roughly forty
    kilobytes of payload, and a real ten-link chain is a few.
    """
    deep = _deep_act_payload(5000)
    assert len(deep) > MAX_TOKEN_BYTES

    assert verify_token(_token(deep), jwks_by_issuer={}) == "token_malformed"


def test_the_parse_refuses_rather_than_raising_even_with_the_size_cap_lifted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second guard, tested where it can actually fire.

    Behind the size cap the ``except RecursionError`` cannot be reached, and a guard that cannot
    fail is not a guard -- this repository plants breaches precisely to avoid shipping one. So the
    cap is lifted here and the parse is made to crash on purpose. Remove ``RecursionError`` from the
    ``except`` clause in ``tokens.py`` and this test goes red with the raw ``RecursionError``, which
    is the behaviour the deployed server had.

    Both matter, in this order: the cap means the crash is unreachable, and this means that if the
    cap is ever raised -- for a legitimately longer chain, say -- the failure is still a refusal.
    """
    monkeypatch.setattr("agent_authz_broker.tokens.MAX_TOKEN_BYTES", 10_000_000)

    assert verify_token(_token(_deep_act_payload(20_000)), jwks_by_issuer={}) == "token_malformed"


def test_a_token_larger_than_the_cap_is_refused_whatever_it_contains() -> None:
    """The cap is on the bearer string, not on a claim inside it: nothing here is even a JWT."""
    oversized = "a." + ("A" * (MAX_TOKEN_BYTES + 10)) + ".c"

    assert verify_token(oversized, jwks_by_issuer={}) == "token_malformed"


@pytest.mark.parametrize(
    "audience", [{"https://broker.test/mcp": 1}, 7, True, None, [1, 2], ["ok", 3]]
)
def test_an_audience_that_is_not_a_string_or_a_list_of_strings_is_refused(audience: Any) -> None:
    """``tuple(anything iterable)`` accepted a JSON object by taking its keys.

    It also raised an uncaught ``TypeError`` on a number. Neither widened authority beyond what a
    multi-audience list already allows, and neither is a specification either -- the next claim read
    that way might be one where it matters.
    """
    authority = Authority()
    token = authority.mint_malformed(claims={"aud": audience})

    result = verify_token(token, jwks_by_issuer={authority.issuer: authority.jwks()})
    assert result == "token_malformed"


def test_a_well_formed_multi_audience_token_still_verifies() -> None:
    """The guard refuses shapes, not audiences. A list of strings is legitimate and stays so."""
    authority = Authority()
    token = authority.mint_malformed(claims={"aud": [ANOTHER_RESOURCE, RESOURCE]})

    claims = verify_token(token, jwks_by_issuer={authority.issuer: authority.jwks()})
    assert not isinstance(claims, str)
    assert RESOURCE in claims.audience


# ----------------------------------------- 2. refusals at the transport reach the audit trail


def _verifier(engine: AsyncEngine, authority: Authority) -> BrokerTokenVerifier:
    return BrokerTokenVerifier(
        authority_jwks={authority.issuer: authority.jwks()}, audience=RESOURCE, engine=engine
    )


async def _rows(engine: AsyncEngine) -> list[AuditEvent]:
    async with AsyncSession(engine) as session:
        return list((await session.execute(select(AuditEvent))).scalars())


async def _count(engine: AsyncEngine) -> int:
    async with AsyncSession(engine) as session:
        total = await session.execute(select(func.count()).select_from(AuditEvent))
        return int(total.scalar_one())


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_token_minted_for_another_resource_server_is_audited_at_the_transport(
    lab: Any, engine: AsyncEngine
) -> None:
    """Scenario A, over the path a real client takes.

    This is the flagship attack, and on the deployed transport it used to leave **no trace at all**:
    ``BrokerTokenVerifier`` returned ``None``, the SDK rejected the request, and ``call_tool`` --
    the only thing that wrote audit rows -- never ran. The matrix run and the kill tests both call
    ``call_tool`` directly, which is precisely why neither could see it.
    """
    authority = Authority()
    token = authority.mint(subject="agent-7", audience=ANOTHER_RESOURCE, scopes=[CREDIT])

    assert await _verifier(engine, authority).verify_token(token) is None

    rows = await _rows(engine)
    assert len(rows) == 1
    assert rows[0].decision == "denied"
    assert rows[0].reason == "audience_mismatch"
    assert rows[0].subject == "agent-7"


@pytest.mark.integration
@pytest.mark.parametrize("flaw", ["expired", "bad_signature", "unknown_issuer"])
@pytest.mark.asyncio
async def test_every_refusal_at_the_transport_is_audited(
    lab: Any, engine: AsyncEngine, flaw: Any
) -> None:
    """Not only the audience: a forged, expired or foreign-issuer token is a probe worth recording.

    Nothing here asserts a subject. A token that did not authenticate has no established identity,
    and writing down the one it claims would make the audit trail repeat the attacker's assertion as
    though the server had checked it.
    """
    authority = Authority()
    token = authority.mint_flawed(flaw, subject="agent-7", audience=RESOURCE, scopes=[CREDIT])

    assert await _verifier(engine, authority).verify_token(token) is None
    assert await _count(engine) == 1

    rows = await _rows(engine)
    assert rows[0].decision == "denied"
    assert rows[0].subject is None
    assert rows[0].token_id is None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_garbage_bearer_string_is_audited_rather_than_dropped(
    lab: Any, engine: AsyncEngine
) -> None:
    assert await _verifier(engine, Authority()).verify_token("not-a-token-at-all") is None
    assert await _count(engine) == 1


@pytest.mark.integration
@pytest.mark.asyncio
async def test_an_accepted_token_is_not_audited_here(lab: Any, engine: AsyncEngine) -> None:
    """The verifier records refusals, not admissions.

    A token that authenticates goes on to ``effects.call_tool``, which writes the row carrying the
    decision, the effective scopes and the effect. Writing one here as well would double-count every
    allowed call in a trail whose whole value is that it can be counted.
    """
    authority = Authority()
    token = authority.mint(subject="agent-7", audience=RESOURCE, scopes=[CREDIT])

    assert await _verifier(engine, authority).verify_token(token) is not None
    assert await _count(engine) == 0
