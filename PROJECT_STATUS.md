# PROJECT_STATUS — agent-authz-broker

Resume point for every session. Read after `CLAUDE.md`, then `git status` and recent commits.

**Current status: FULLY COMPLETE AND FROZEN.** The predeclared kill test A–E passes against real
PostgreSQL. **Three** read-only adversarial reviews were run. The second broke the headline claim on
the deployed path; the third found that the container could not have booted, and that the guard
protecting the kill test was itself a guard that could not fail. Every hole is closed, and every one
of them is published rather than absorbed.

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

**51 tests green.** 28 offline, 23 against real PostgreSQL. Five CI jobs, including one that
re-measures every published number and one that replants every breach.

---

## What the three reviews found

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

**Review 3 (ADR-005)** — asked *what did nobody look at?* and got: the shell.

1. **`deployment/entrypoint.sh` called `agent_authz_broker.demo.seed`, a module that has never
   existed in any commit.** Under `set -eu` with `render.yaml`'s `AAB_ENVIRONMENT=staging`, the
   container would have exited non-zero before `exec uvicorn` — **the published blueprint could not
   have booted** — and `make seed`/`make api` were broken the same way. Nothing needed seeding: no
   table holds an account. The step is removed, not implemented. It survived because §11 certified
   the entrypoint against a *stubbed* interpreter, which is a check that cannot fail.
2. **`tests/test_predeclaration.py` was itself the mistake it exists to prevent.** All three checks
   read the kill test as text; `pytest.mark.skip` left them reporting `3 passed` while zero of the
   seventeen kill tests ran. Replaced by a `pytest_collection_modifyitems` hook that asks pytest
   what it is about to run and refuses the session.

Plus: `read_approval` writes no audit row (now stated, and rule 6 scoped to *decisions*), the demo
token mint is open on non-production instances (now disclosed), and `make help` advertised five
breaches while the script plants ten.

`make breaches` replants **all eleven** and requires each one's tests to fail. Verified: 11 of 11 —
**and it now runs in CI**, alongside a gate that re-measures the matrix and fails if any published
number stops reproducing. Those were the two load-bearing claims with no independent execution.

---

## Deployment state

| Layer | State |
|---|---|
| Console (Vercel Hobby) | **Live** — <https://agent-authz-broker.vercel.app>, serving the committed artifacts because `BROKER_API_BASE_URL` is unset there |
| Resource server (Render) | **Not deployed** — needs an owner account login |
| PostgreSQL (Neon) | **Not provisioned** — needs an owner account login |
| The container itself | **Built, booted and attacked on every CI push.** The `container` job builds the image, runs it against PostgreSQL 16, and drives every boundary through it over HTTP |

`docs/deployment.md` §11 says exactly which claims were run and which were not.

---

## Known limits, stated rather than implied

- **`AAB_APPROVER_TOKEN` is a credential, not an approver identity.** One shared secret; anyone
  holding it approves as anyone, and `approved_by` is a string that holder supplied.
- **A stolen, still-valid token is not detected** within its attenuated scope for reversible reads.
- **Everything is synthetic.** Invented accounts, no payment rail, no external call. The
  "irreversible effect" is a row in a demonstration table.
- **Three reviews are three reviews.** Each found something the previous ones did not, and each
  found it by changing the *question* rather than looking harder. That is evidence about method, not
  about the remaining count.
- **`read_approval` leaves no audit row**, so an agent can probe it for approval ids untraced.
- **`GET /api/v1/demo/tokens` is open on any non-production instance.** Deliberate — it is the lab's
  front door — and harmless to the claim: approving needs `AAB_APPROVER_TOKEN`, which it does not
  mint.
- **Not built:** Keycloak gap analysis, OpenTelemetry/Langfuse, step-up authorization,
  CIMD-vs-DCR, full RFC 9728/8707/9207 conformance suites. ADR-002 lists each.
- **Rate limiting IS built** (ADR-006), in PostgreSQL rather than the blueprint's Redis:
  `(verified subject, tool, fixed 60-second window)`, default 30. Fixed windows, so the worst
  case across an arbitrary minute is twice the limit; **not DDoS protection**; and not part of
  the security claim — removing it admits no extra attack in the kill test.

---

## Commands

```bash
make gate         # lint, types, offline suite
make killtest     # the adversarial suite against real PostgreSQL
make breaches     # replant all eleven breaches; each must turn its own tests red
make matrix-gate  # prove every published number still reproduces from a fresh run
make matrix       # measure the security matrix and every console artifact
make api          # the MCP server + console API on :8000
uv run python scripts/mcp_smoke.py        # a real MCP client over Streamable HTTP

cd frontend && npm run dev                # the console on :3000
cd frontend && npm run screenshots        # retake docs/screenshots from a running console
```
