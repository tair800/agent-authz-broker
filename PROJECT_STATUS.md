# PROJECT_STATUS — agent-authz-broker

Resume point for every session. Read after `CLAUDE.md`, then `git status` and recent commits.

**Current status: FULLY COMPLETE AND FROZEN.** The predeclared kill test A–E passes against real
PostgreSQL. Two read-only adversarial reviews were run; the second one **broke the headline claim**
on the deployed path, the hole is closed, and both the hole and the fix are published rather than
absorbed.

---

## The measured result

Written by `python -m agent_authz_broker.demo` into `artifacts/`. Every effect count is
`SELECT count(*) FROM irreversible_effect` against a clean database.

| | Naive baseline | **Hardened** |
|---|---|---|
| Attacks permitted (of 5) | 2 | **0** |
| Irreversible effects (of 6 scenarios) | 4 | **2**, both required |

ADR-001 predicted the naive verifier would permit **3**. It permits 2 — approval is a layer below
both policies, so they differ only where the difference is a token check. The prediction is kept
beside the correction.

**51 tests green.** 28 offline, 23 against real PostgreSQL.

---

## What the two reviews found

**Review 1 (ADR-003)** — five controls removed one at a time, five caught. Verdict: each control is
load-bearing.

**Review 2 (ADR-004)** — attacked a copy rather than reading it. Two material holes, **neither in a
control review 1 had tested**:

1. **`POST /api/v1/approvals` was unauthenticated in every environment.** The agent could create the
   approval it then spent: mint a token, POST an approval naming its own subject, call
   `issue_credit` over real MCP, read 1 out of `irreversible_effect`. "It is not an MCP tool" was
   never the boundary — the agent is a process making ordinary HTTP requests to the same origin.
   Now gated on `AAB_APPROVER_TOKEN`, which the test authority does not mint.
2. **Refusals at the transport produced no audit row.** A token rejected by `BrokerTokenVerifier`
   never reaches `effects.call_tool`, which was the only thing writing audit rows. So a wrong
   audience, a forged signature and an expired token were all silent on the deployed server, while
   the README said *"every decision, refusals included"*. **No test could have caught this:** the
   suite calls `call_tool` directly, so in the harness the flagship attack *was* audited. The
   verifier writes the row itself now.

Plus two minor parser findings: an uncaught `RecursionError` on a deeply nested `act` before any
signature check, and `aud` read as `tuple(anything iterable)`.

`make breaches` replants **all eight** and requires each one's tests to fail. Verified: 8 of 8.

---

## Deployment state

| Layer | State |
|---|---|
| Console (Vercel Hobby) | **Live** — <https://agent-authz-broker.vercel.app>, serving the committed artifacts because `BROKER_API_BASE_URL` is unset there |
| Resource server (Render) | **Not deployed.** `agent-authz-broker.onrender.com` returns 404 |
| PostgreSQL (Neon) | **Not provisioned** |

`docs/deployment.md` §11 says exactly which claims were run and which were not.

---

## Known limits, stated rather than implied

- **`AAB_APPROVER_TOKEN` is a credential, not an approver identity.** One shared secret; anyone
  holding it approves as anyone, and `approved_by` is a string that holder supplied.
- **A stolen, still-valid token is not detected** within its attenuated scope for reversible reads.
- **Everything is synthetic.** Invented accounts, no payment rail, no external call. The
  "irreversible effect" is a row in a demonstration table.
- **Two reviews are two reviews.** Each found a hole the author had not thought of. That is evidence
  about the method, not about the remaining count.
- **Not built:** Keycloak gap analysis, Redis rate limiting, OpenTelemetry/Langfuse, step-up
  authorization, CIMD-vs-DCR, full RFC 9728/8707/9207 conformance suites. ADR-002 lists each, and
  records that **rate limiting is now delivered nowhere in the portfolio**.

---

## Commands

```bash
make gate        # lint, types, offline suite
make killtest    # the adversarial suite against real PostgreSQL
make breaches    # replant all eight breaches; each must turn its tests red
make matrix      # measure the security matrix and every console artifact
make api         # the MCP server + console API on :8000
uv run python scripts/mcp_smoke.py        # a real MCP client over Streamable HTTP

cd frontend && npm run dev                # the console on :3000
cd frontend && npm run screenshots        # retake docs/screenshots from a running console
```
