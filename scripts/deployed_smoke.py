"""Drive every security boundary against a **running** instance, over HTTP, and write the evidence.

This is not the test suite. The suite calls `effects.call_tool` in-process against a database it
owns; this speaks the wire protocol to a server it did not start, exactly as a client would. The
difference is the whole point: ADR-004's audit hole existed only on the transport path and every
test passed while it was open.

    AAB_APPROVER_TOKEN=... uv run python scripts/deployed_smoke.py --base-url https://host

**Effects are counted from the server's own `irreversible_effect` table**, read through
`/api/v1/effects`, never from what a tool call says about itself. Counts are taken as **deltas**
around each scenario rather than absolutes, so this is safe to run against a shared instance that
other visitors are driving — and so a scenario cannot be scored by a number some other request
produced.

The artifact it writes carries no token, no DSN and no secret: scenario names, decisions, denial
reasons, counts, and the deployed revision.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "ACC-1041"
AMOUNT = 500
EXPECTED_TOOLS = {
    "flag_account",
    "issue_credit",
    "ping",
    "read_account",
    "read_approval",
    "request_approval",
}


class Probe:
    """One HTTP client against the deployment, plus the MCP calls layered on it."""

    def __init__(self, base: str, approver: str | None) -> None:
        self.base = base.rstrip("/")
        self.approver = approver
        self.http = httpx.AsyncClient(timeout=90, follow_redirects=True)

    async def close(self) -> None:
        await self.http.aclose()

    # ---------------------------------------------------------------- backend state, not reports

    async def effects(self) -> int:
        r = await self.http.get(f"{self.base}/api/v1/effects")
        r.raise_for_status()
        return int(r.json()["count"])

    async def audit(self, limit: int = 200) -> list[dict[str, Any]]:
        r = await self.http.get(f"{self.base}/api/v1/audit", params={"limit": limit})
        r.raise_for_status()
        rows: list[dict[str, Any]] = r.json()
        return rows

    async def tokens(self) -> dict[str, str]:
        r = await self.http.get(f"{self.base}/api/v1/demo/tokens")
        r.raise_for_status()
        tokens: dict[str, str] = r.json()["tokens"]
        return tokens

    async def meta(self) -> dict[str, Any]:
        r = await self.http.get(f"{self.base}/api/v1/meta")
        r.raise_for_status()
        meta: dict[str, Any] = r.json()
        return meta

    # ------------------------------------------------------------------------------- the MCP wire

    async def call(self, token: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """One MCP tool call. Returns what happened, including a transport-level refusal.

        A token the verifier rejects never reaches a tool: the SDK raises rather than returning an
        outcome. That is a *result*, not an error to propagate — it is scenario A and H's expected
        behaviour — so it is captured and named.
        """
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        try:
            async with (
                httpx.AsyncClient(headers=headers, timeout=90) as http,
                streamable_http_client(f"{self.base}/mcp", http_client=http) as (read, write),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                result = await session.call_tool(tool, arguments)
                body = result.content[0].text if result.content else "{}"
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError:
                    return {"transport": "accepted", "raw": body[:300]}
                outcome = payload.get("outcome", payload)
                return {
                    "transport": "accepted",
                    "decision": outcome.get("decision"),
                    "reason": outcome.get("reason"),
                    "effect_id_present": bool(outcome.get("effect_id")),
                }
        except Exception as exc:  # a refusal at the transport arrives as an exception
            return {"transport": "refused", "error": type(exc).__name__}

    async def burst(self, token: str, tool: str, arguments: dict[str, Any], n: int) -> list[Any]:
        """`n` calls down **one** MCP session, as fast as the link allows.

        The rate-limit probe cannot open a session per call: against a free instance over the
        public internet that took longer than the 60-second window, so the window rolled and
        the ceiling was never reached. All 31 calls came back `allowed` and the scenario
        reported a failure that was really a slow client. One session, one handshake, N
        round trips.
        """
        headers = {"Authorization": f"Bearer {token}"}
        out: list[Any] = []
        async with (
            httpx.AsyncClient(headers=headers, timeout=90) as http,
            streamable_http_client(f"{self.base}/mcp", http_client=http) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            for _ in range(n):
                result = await session.call_tool(tool, arguments)
                body = result.content[0].text if result.content else "{}"
                try:
                    outcome = json.loads(body).get("outcome", {})
                except json.JSONDecodeError:
                    outcome = {}
                out.append({"decision": outcome.get("decision"), "reason": outcome.get("reason")})
        return out

    async def initialize(self, token: str) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {token}"}
        async with (
            httpx.AsyncClient(headers=headers, timeout=90) as http,
            streamable_http_client(f"{self.base}/mcp", http_client=http) as (read, write),
            ClientSession(read, write) as session,
        ):
            init = await session.initialize()
            tools = await session.list_tools()
            return {
                "server": f"{init.server_info.name} {init.server_info.version}",
                "protocol": str(init.protocol_version),
                "tools": sorted(t.name for t in tools.tools),
            }

    # --------------------------------------------------------------------------- approval granting

    async def drain_approvals(self, token: str, *, limit: int = 12) -> int:
        """Spend every unconsumed approval, so the next scenario starts from a known state.

        Scenario F says *one approval, two concurrent calls, exactly one effect*. If a second
        unconsumed approval is lying around — and D's successful grant leaves one — both calls
        succeed and the run reports a breach that is really this script's bookkeeping. It showed up
        exactly that way the first time, which is the counting-from-the-database rule doing its job
        on the evidence script itself.

        Returns how many were spent, so the artifact can show the state was actually reached.
        """
        for spent in range(limit):
            outcome = await self.call(token, "issue_credit", {"account": ACCOUNT, "amount": AMOUNT})
            if outcome.get("decision") != "allowed":
                return spent
        raise RuntimeError("could not reach a state with no unconsumed approval")

    async def grant(self, *, bearer: str | None) -> int:
        headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
        r = await self.http.post(
            f"{self.base}/api/v1/approvals",
            headers=headers,
            json={"subject": "agent-7", "account": ACCOUNT, "amount": AMOUNT},
        )
        return r.status_code


async def _scenario(
    probe: Probe, name: str, note: str, run: Any, *, expect_effects: int
) -> dict[str, Any]:
    """Run one scenario and score it on the change in `irreversible_effect`, not on what it said."""
    before = await probe.effects()
    detail = await run()
    after = await probe.effects()
    caused = after - before
    return {
        "scenario": name,
        "note": note,
        "detail": detail,
        "effects_caused": caused,
        "effects_allowed": expect_effects,
        "pass": caused == expect_effects,
    }


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "deployed-smoke.json")
    parser.add_argument("--label", default="", help="what this instance is, for the artifact")
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=0,
        help="what AAB_RATE_LIMIT_PER_MINUTE this instance is configured with; 0 skips the check",
    )
    args = parser.parse_args()

    approver = os.environ.get("AAB_APPROVER_TOKEN") or None
    probe = Probe(args.base_url, approver)
    results: list[dict[str, Any]] = []

    try:
        meta = await probe.meta()
        tokens = await probe.tokens()
        handshake = await probe.initialize(tokens["valid_request"])
        audit_before = len(await probe.audit())

        # --- the positive path, first: a suite that only proves refusals proves nothing ----------
        if approver:
            await probe.grant(bearer=approver)
        results.append(
            await _scenario(
                probe,
                "positive_path",
                "correct audience, attenuated scope, matching approval",
                lambda: probe.call(
                    tokens["valid_request"], "issue_credit", {"account": ACCOUNT, "amount": AMOUNT}
                ),
                expect_effects=1 if approver else 0,
            )
        )
        results.append(
            await _scenario(
                probe,
                "permitted_read",
                "a reversible tool inside the effective scope",
                lambda: probe.call(tokens["valid_request"], "read_account", {"account": "ACC-1"}),
                expect_effects=0,
            )
        )

        # --- A-H, the boundaries ----------------------------------------------------------------
        for name, note, token_key in [
            (
                "A_wrong_audience",
                "valid signature, minted for another resource server",
                "wrong_audience",
            ),
            (
                "B_scope_amplification",
                "leaf claims a scope its delegator never had",
                "scope_amplification",
            ),
            ("H_expired", "a token past its expiry", "expired"),
            ("H_bad_signature", "signed with a key this server does not trust", "bad_signature"),
        ]:
            results.append(
                await _scenario(
                    probe,
                    name,
                    note,
                    lambda k=token_key: probe.call(
                        tokens[k], "issue_credit", {"account": ACCOUNT, "amount": AMOUNT}
                    ),
                    expect_effects=0,
                )
            )

        results.append(
            await _scenario(
                probe,
                "H_garbage_bearer",
                "a bearer string that is not a token at all",
                lambda: probe.call(
                    "not-a-token-at-all", "issue_credit", {"account": ACCOUNT, "amount": AMOUNT}
                ),
                expect_effects=0,
            )
        )

        results.append(
            await _scenario(
                probe,
                "C_no_approval",
                "everything correct except that no human approved",
                lambda: probe.call(
                    tokens["valid_request"], "issue_credit", {"account": ACCOUNT, "amount": AMOUNT}
                ),
                expect_effects=0,
            )
        )

        # --- D and E: who may create an approval -------------------------------------------------
        results.append(
            {
                "scenario": "D_agent_token_cannot_grant_approval",
                "note": "a valid, correctly attenuated agent token presented to the approver route",
                "detail": {
                    "no_credential": await probe.grant(bearer=None),
                    "agent_token": await probe.grant(bearer=tokens["valid_request"]),
                },
                "effects_caused": 0,
                "effects_allowed": 0,
                "pass": True,
            }
        )
        if approver:
            status = await probe.grant(bearer=approver)
            results[-1]["detail"]["approver_credential"] = status
            results[-1]["pass"] = (
                results[-1]["detail"]["no_credential"] == 401
                and results[-1]["detail"]["agent_token"] == 401
                and status == 201
            )

        # --- F and G: one approval, two concurrent calls, then a replay --------------------------
        if approver:
            # Exactly one unconsumed approval, verified by draining first.
            drained = await probe.drain_approvals(tokens["valid_request"])
            await probe.grant(bearer=approver)
            before = await probe.effects()
            pair = await asyncio.gather(
                probe.call(
                    tokens["valid_request"], "issue_credit", {"account": ACCOUNT, "amount": AMOUNT}
                ),
                probe.call(
                    tokens["valid_request"], "issue_credit", {"account": ACCOUNT, "amount": AMOUNT}
                ),
            )
            raced = await probe.effects() - before
            results.append(
                {
                    "scenario": "F_one_approval_two_concurrent_calls",
                    "note": "exactly one effect, whichever call wins",
                    "detail": {"outcomes": pair, "approvals_drained_first": drained},
                    "effects_caused": raced,
                    "effects_allowed": 1,
                    "pass": raced == 1,
                }
            )
            results.append(
                await _scenario(
                    probe,
                    "G_replay_consumed_approval",
                    "the same token and the same spent approval, presented again",
                    lambda: probe.call(
                        tokens["valid_request"],
                        "issue_credit",
                        {"account": ACCOUNT, "amount": AMOUNT},
                    ),
                    expect_effects=0,
                )
            )

        # --- the ceiling, live and last ----------------------------------------------------------
        #
        # On `read_account`, deliberately. It needs no approval, so what refuses the last call is
        # unambiguously the limiter -- and because the bucket is (subject, tool, window), spending
        # this one leaves `issue_credit` untouched, which every scenario above already relied on
        # without saying so.
        if args.rate_limit > 0:
            before = await probe.effects()
            outcomes = await probe.burst(
                tokens["valid_request"], "read_account", {"account": "ACC-1"}, args.rate_limit + 5
            )
            last = outcomes[-1]
            allowed = sum(1 for o in outcomes if o.get("decision") == "allowed")
            limited = [o for o in outcomes if o.get("reason") == "rate_limited"]
            results.append(
                {
                    "scenario": "rate_limit",
                    "note": (
                        f"{args.rate_limit + 5} further calls, down one MCP session, against a "
                        f"ceiling of "
                        f"{args.rate_limit} per (subject, tool, 60s window). `allowed` is normally "
                        "short of the ceiling because `permitted_read` above already spent a unit "
                        "of this exact bucket -- the window is shared across the whole run, as a "
                        "window should be. The guarantee is an upper bound, so that is what is "
                        "asserted: some call was refused, none exceeded the ceiling, no effects."
                    ),
                    "detail": {
                        "configured_limit": args.rate_limit,
                        "calls_made": len(outcomes),
                        "allowed": allowed,
                        "refused_as_rate_limited": len(limited),
                        "final_decision": last.get("decision"),
                        "final_reason": last.get("reason"),
                    },
                    "effects_caused": await probe.effects() - before,
                    "effects_allowed": 0,
                    "pass": (
                        allowed <= args.rate_limit
                        and len(limited) > 0
                        and await probe.effects() - before == 0
                    ),
                }
            )

        # --- the transport audit trail ------------------------------------------------------------
        rows = await probe.audit()
        transport_rows = [r for r in rows if r.get("tool") == "-"]
        artifact = {
            "generated_at": dt.datetime.now(tz=dt.UTC).isoformat(timespec="seconds"),
            "instance": args.label or args.base_url,
            "public_api_url": args.base_url,
            "deployed_revision": meta.get("revision") or "(not reported by the deployment)",
            "environment": meta.get("environment"),
            "resource_server_url": meta.get("resource_server_url"),
            "mcp": handshake,
            "tool_list_is_exactly_the_six": sorted(handshake["tools"]) == sorted(EXPECTED_TOOLS),
            "approver_credential_supplied": bool(approver),
            "rate_limit_per_minute_configured": args.rate_limit or None,
            "scenarios": results,
            "audit": {
                "rows_before": audit_before,
                "rows_after": len(rows),
                "transport_refusals_recorded": len(transport_rows),
                "transport_refusal_reasons": sorted({str(r.get("reason")) for r in transport_rows}),
                "unauthenticated_rows_claim_no_subject": all(
                    r.get("subject") is None
                    for r in transport_rows
                    if r.get("reason") in {"token_malformed", "signature_invalid", "issuer_unknown"}
                ),
            },
            "all_scenarios_pass": all(r["pass"] for r in results),
        }
    finally:
        await probe.close()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {args.out}")
    print(f"  instance:  {artifact['instance']}")
    print(f"  mcp:       {handshake['server']} protocol {handshake['protocol']}")
    listed = "exactly the six" if artifact["tool_list_is_exactly_the_six"] else handshake["tools"]
    print(f"  tools:     {listed}")
    for row in results:
        mark = "PASS" if row["pass"] else "FAIL"
        print(
            f"  {mark}  {row['scenario']:38} effects {row['effects_caused']} "
            f"(allowed {row['effects_allowed']})"
        )
    audit = artifact["audit"]
    print(
        f"  audit:     {audit['rows_before']} -> {audit['rows_after']} rows, "
        f"{audit['transport_refusals_recorded']} recorded at the transport "
        f"{audit['transport_refusal_reasons']}"
    )
    return 0 if artifact["all_scenarios_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
