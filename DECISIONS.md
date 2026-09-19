# Decisions

Architecture decision records. ADR-001 is written **before any implementation** and fixes the claim,
the threat model and the kill tests. Nothing in it may be weakened after results are seen.

---

## ADR-001 — The claim, the threat model, and the kill test

**Status:** accepted, 2026-09-13, **before implementation**.

### The claim

> **An agent can request an action. It cannot manufacture the authority to perform one.**
>
> The MCP resource server decides, from the token and its own durable state, whether a call is
> authorized. It does not take the client's word for the audience, for the scope, or for whether a
> human approved. A structurally valid, correctly signed, unexpired token minted for a *different*
> resource server is refused. A delegated token never carries a scope its delegator lacked. An
> irreversible tool does not run without a recorded human approval, and one approval authorises
> exactly one irreversible effect even under concurrent calls.

### The failure this prevents

A SaaS company connects an assistant to back-office tooling. The agent is a non-deterministic caller
driven by attacker-influenceable content — retrieved documents, tool descriptions, user text. The
question is not whether the agent is well-behaved. It is what the server does when it is not.

**Three real bug classes, all of which a "the signature verified" check lets through:**

1. **Audience confusion.** A token the agent legitimately holds for service X is replayed at service
   Y. Signature valid, issuer valid, not expired, scopes present. If Y checks only the signature, the
   agent has just gained authority at Y that nobody granted.
2. **Scope amplification through delegation.** A delegation chain hands an agent a token whose `scope`
   claim lists more than the delegating principal ever had. A server that trusts the leaf token's
   scope claim grants it.
3. **Confused deputy on approval.** The agent asserts *"the human approved this"* in a prompt, a tool
   argument, or by presenting an approval issued for a different action, a different target, or one
   already spent. A server that accepts the assertion has put the agent in charge of consent.

### The trust boundary, stated once

**Everything the client sends is untrusted input, including the token's own claims about what it may
do.** The server independently computes the effective authority from:

- the token's cryptographic signature, against a key it fetches itself;
- the token's audience, compared to the server's own configured identity;
- the **full delegation chain**, attenuated — never the leaf's scope claim alone;
- its **own database**, for whether a matching, unexpired, unconsumed human approval exists.

No model output is in that path. No tool argument can substitute for any of it.

### The synthetic irreversible action

**`issue_credit`** — credit a synthetic customer account. Chosen because money movement is
unambiguously irreversible and needs no argument about whether it "really" matters. Everything is
fake: invented accounts, invented balances, no payment rail, no external call. The effect is a row in
`irreversible_effect`, and **the count that grades every test is read from that table**, never from
what a component reports about itself.

### The token model — the smallest set of claims the threat model needs

| Claim | Why it is present |
|---|---|
| `iss` | which authority signed it; pins the key set |
| `sub` | the principal the authority is for |
| `aud` | **the resource this token is for.** The audience check is the whole of bug class 1 |
| `exp`, `iat` | expiry |
| `jti` | token identity, for the audit trail |
| `scope` | what the leaf *claims*. Never trusted alone |
| `act` | the delegation chain (RFC 8693 actor), each link carrying its own `sub` and `scope` |

Anything not on this list is not added. Signing is real asymmetric cryptography (EdDSA/RS256 via a
mature JOSE library) verified against a JWKS the server reads; never string comparison.

### Effective authority — the attenuation rule, fixed now

> **effective = leaf.scope ∩ act[0].scope ∩ act[1].scope ∩ … ∩ root.scope**

Set intersection down the entire chain. A scope absent from **any** link is absent from the result,
whatever the leaf claims. Attenuation is monotone: adding a delegation hop can only remove authority.
There is no rule anywhere that adds a scope back.

### Human approval — what it is bound to, and why each field

An approval is a durable row, created out-of-band by a human, and it is bound to:

| Field | Without it |
|---|---|
| `subject` | an approval for one principal authorises another |
| `tool` | an approval to read authorises a credit |
| `resource` (account) | an approval for account A authorises account B |
| `amount` | an approval for 5 authorises 5,000 |
| `expires_at` | an approval is good forever |
| `consumed_at` | an approval is good repeatedly |

**Approval is checked in the resource server against the database.** There is no tool argument, no
header and no prompt that can assert approval. A guard test asserts the irreversible tool's input
schema has no field a caller could use to claim one.

### The kill test — predeclared, and not to be weakened

The core security claim **fails** if any of these produces an irreversible effect:

| | Scenario | Required hardened result |
|---|---|---|
| **A** | valid signature, unexpired, sufficient scopes, **audience names another resource server** | denied · **0 effects** |
| **B** | valid signature, valid audience, leaf `scope` claims `credit:issue`, **an ancestor in the chain never had it** | denied · **0 effects** |
| **C** | valid signature, valid audience, properly attenuated scope, **no matching approval** | denied · **0 effects** |
| **D** | one valid approval, **two concurrent calls** | exactly **1 effect** |
| **E** | valid signature, valid audience, attenuated scope, matching unexpired approval | allowed · exactly **1 effect** |

Plus the same required-zero result for: expired token, invalid signature, absent required scope,
expired approval, approval for another action, approval for another resource, approval already
consumed, and the admin reset being unreachable through MCP.

**Every effect count is `SELECT count(*) FROM irreversible_effect`.** A component that grades itself
is not evidence.

**D is a database property, not a Python one.** Atomic consumption is a conditional `UPDATE` guarded
by a unique constraint, run against real PostgreSQL with two genuinely concurrent connections. An
in-process lock would pass the test and fail in production behind two workers, so it is not used.

### The baseline, chosen before results

A **naive verifier** that does what a competent engineer writes when the brief is "check the token":
verify the signature against the JWKS, check `exp`, and read the leaf `scope` claim. It is not a straw
man — it is the check that most published guidance implies is sufficient. Both verifiers run the
same scenarios against the same database and the counts are compared.

> **Corrected by measurement, 2026-09-13.** This paragraph originally predicted the naive verifier
> would fail *"A, B and C"*. It fails **A and B**. Scenario C turns on approval, and approval is a
> layer *below* both policies — they differ only where the difference is a token check. The measured
> matrix says naive permits **2 of 5** attacks, not 3, and that is what the README publishes. The
> prediction is left here rather than edited away: a baseline overstated in the repository's own
> favour is exactly the thing a reader should be able to catch it doing.

**This repository does not claim MCP servers in general are insecure**, and it does not claim the
naive verifier is what any particular product ships.

### Where AI is allowed

The agent may read permitted synthetic resources, propose an action, explain why, and call tools with
authority it was granted. It may not mint authority, choose its audience, widen scope, assert
approval, consume an approval outside the server's transaction, write effect state directly, or reach
the admin reset. **No live model is required to prove anything here**, and none is in the security
path.

### What standard MCP conformance does and does not cover

Protocol conformance checks that this is a well-formed MCP server — initialize, tool listing, schemas,
transport. **It says nothing about audience validation, delegation attenuation or approval
semantics.** Those are this repository's own adversarial suite, and the README keeps the two apart.

---

## ADR-002 — What this build does not include, against the blueprint

**Status:** accepted, 2026-09-13, **before implementation**.

The portfolio blueprint (a private planning document, not published in this repository) specifies an XL build (~28 sessions): self-hosted Keycloak with an RFC
gap analysis, Redis rate limiting, OpenTelemetry GenAI semconv into self-hosted Langfuse, step-up
authorization, Client ID Metadata Documents versus DCR, RFC 9728/8707/9207 conformance suites, and
Cloud Run + Cloud SQL. The owner's instruction for this increment is a 1–2 day fast-track that
explicitly forbids an enterprise IAM platform, a general OAuth authorization server, and weeks of
standards work.

**Built:** the MCP resource server, strict audience validation, delegation-chain attenuation, durable
human approval with atomic one-time consumption, deterministic authorization, an audit trail, the
adversarial suite, and the naive-versus-hardened comparison — that is, the whole of ADR-001's claim.

**Not built, and not claimed anywhere:**

| Blueprint item | Status |
|---|---|
| Self-hosted Keycloak + RFC gap analysis | **Not built.** A deterministic test authority signs tokens with real keys. This repository is a **resource server**; it is not an authorization server and does not pretend to be one. |
| Redis rate limiting | **Superseded by ADR-006.** Rate limiting is built, in PostgreSQL rather than Redis. Adding a service for one integer is the habit that ADR worked against. |
| OpenTelemetry + Langfuse | **Not built.** |
| Step-up authorization on 403 | **Not built.** |
| CIMD vs DCR analysis | **Not built.** |
| Full RFC 9728 / 8707 / 9207 conformance suites | **Not built.** RFC 8707's resource indicator is *used* — it is how audience binding is expressed — but no conformance suite is claimed. |
| Cloud Run + Cloud SQL | **Not used.** Render Free + Neon Free, per the owner's zero-cost instruction. |

**The portfolio consequence, recorded rather than absorbed:** the portfolio's skill matrix (again a
private planning document) makes project 4 the **sole home** of *MCP server design*,
*OAuth 2.1 / authn / authz*, *rate limiting* and *API security*.
MCP and resource-server authorization are delivered. **Rate limiting was, when this ADR was
written, delivered nowhere in the portfolio.** ADR-006 closes it: it is built here, in PostgreSQL
rather than Redis, and proven by `tests/test_rate_limit.py` and breach 11.

---

## ADR-003 — The adversarial review: five breaches planted, five caught

**Status:** accepted, 2026-09-13, **after** the suite was green.

Project 3 shipped a guard that forbade importing a module which did not exist. It passed every run
and protected nothing until a reviewer planted the breach it was supposed to stop. A suite that has
never failed is not evidence that the system is safe; it is evidence that nothing has tested it.

So each control was deliberately removed, one at a time, and the suite was re-run. A control whose
removal changes nothing is not a control.

| # | Breach planted | Caught by | Result |
|---|---|---|---|
| 1 | `HARDENED` stops checking audience | `test_A_valid_token_for_another_resource_server_is_refused` | **FAILED** as required |
| 2 | `effective_scopes` returns the leaf's claim instead of the intersection | both `test_B_*` attenuation tests | **FAILED** as required |
| 3 | `consume_approval` drops `consumed_at IS NULL` from its `WHERE` | `test_D_two_concurrent_calls…` | **FAILED** — as an `IntegrityError` |
| 4 | the approval lookup stops filtering on the account | `test_C_an_approval_that_does_not_match…[other_account]` | **FAILED** as required |
| 5 | an `admin_reset` tool is registered on the MCP surface | `test_the_advertised_tool_list_is_exactly_the_six` and `test_no_reset_shaped_tool_is_reachable_over_mcp` | **FAILED** as required |

Every control was restored and the full suite was green: **32 tests** at that date. ADR-004 adds three more breaches and the suite is now 51.

**The removals are a script, not a memory of an afternoon.** A reviewer pointed out that this table
was exactly as checkable as the Project 3 guard it opens by warning about — a claim in a document.
So `scripts/plant_breaches.py` holds them, alongside the five that later reviews added. It refuses to start against a dirty tree, edits one
source file, runs **only** the tests named in the table above, requires them to fail, and restores
the file in a `finally`:

```
make breaches
```

A control whose removal changes nothing is reported as a hole and the script exits non-zero. That
is the difference between this section being a result and being a paragraph: re-run it against any
later commit and it either still holds or it tells you which control stopped being load-bearing.

**Breach 3 is the most informative of the five.** Removing the conditional from the `UPDATE` did not
produce a wrong answer — it produced a `psycopg`/asyncpg `IntegrityError` from the UNIQUE constraint
on `irreversible_effect.approval_id`. That is the backstop doing its job: even with the application
logic removed, the database refused to record a second effect against one approval. The two
mechanisms are genuinely independent, which is the only reason it is honest to call the second one a
backstop rather than a comment.

**What this review does not establish.** It shows that each control is load-bearing and that the
tests detect its removal. It does not enumerate every attack — no such review does, and five
breaches chosen by the author are five the author thought of. The threat model
in `docs/threat-model.md` states what is out of scope, and the largest item is unchanged: a stolen,
still-valid token used within its attenuated scope for reversible reads is not detected here.

---

## ADR-004 — The second review: the claim was false on the deployed path

**Status:** accepted, 2026-09-13, **after** ADR-003 and after the console was published.

ADR-003 planted five breaches and caught five, and concluded that each control was load-bearing.
That conclusion was correct and it was not the same as the system being sound. A second read-only
review — told to attack a copy rather than read it — found **two material holes**, and neither was
in a control ADR-003 had tested. They were in the space *between* the controls.

### 1. The agent could manufacture the approval

`POST /api/v1/approvals` was unauthenticated in every environment, including `production`.

The reasoning for leaving it open is written down in the original docstring, which is why it is
worth reading: *the MCP surface cannot reach it; an agent may `request_approval` and cannot create
one.* That is true and it is not the boundary. **The agent is a process, not a tool list.** It makes
ordinary HTTP requests, and the tools and the console API are served from one origin. The reviewer
minted a token, `POST`ed an approval naming its own subject, called `issue_credit` over a real MCP
client, and read `1` out of `SELECT count(*) FROM irreversible_effect`.

`docs/threat-model.md` §3 already granted the adversary *"write access to the resource server's
database … through the server's own API"*. §6 called the confused deputy mitigated anyway. The
threat model contained both halves of the contradiction and nobody had put them together.

**Closed by** `AAB_APPROVER_TOKEN`: unset disables the route, and a bearer token the test authority
mints — valid signature, correct audience, sufficient scope — is refused with 401. It is a
credential boundary and not an approver identity, and the README now says which of the two it is.

### 2. The audit trail was blind to exactly the attacks this project is about

A token refused by `BrokerTokenVerifier` never reaches `effects.call_tool`: the SDK rejects the
request at the transport. `call_tool` was the only thing that wrote audit rows. So on the deployed
server a wrong audience produced **no audit row**. Nor did a forged signature, an expired token, or
a garbage string. The README said *"every decision, refusals included"*, and the `AuditEvent`
docstring said *"every outcome, including every refusal"*.

**The suite could not have caught this, and that is the part worth keeping.** The kill tests and the
matrix run both call `call_tool` directly — deliberately, so they can count effects from a clean
database. In the harness scenario A *is* audited, and `artifacts/audit.json` carries an
`audience_mismatch` row that the deployed server would never have written. Every test passed. The
artifact was honest about the run that produced it and wrong about production.

This is the same shape as the Project 3 defect ADR-003 opens by citing, arrived at from the other
direction: there, a guard that could not fail; here, a claim no test was positioned to check.

**Closed by** the verifier writing the row itself, with no subject and no token id when the token
did not authenticate — recording the identity it *claimed* would make the trail repeat an attacker's
assertion as though the server had checked it.

### Two minor findings, both in the parse that runs before the signature check

A deeply nested `act` raised `RecursionError` inside the **unverified** decode — no signing key
needed — and `RecursionError` is not a `PyJWTError`, so it left `verify_token` as an uncaught 500
with no audit row. A 16 KB cap on the bearer string closes it; the `except` clause behind the cap
cannot fire, so it is tested with the cap lifted rather than shipped as a guard that cannot fail.
Separately, `aud` was read as `tuple(anything iterable)`, which accepted a JSON *object* by taking
its keys and raised an uncaught `TypeError` on a number. Neither widened authority. `aud` is now a
string or a list of strings and nothing else.

### What the review confirmed

Token forgery across an audience near-miss matrix (trailing slash, uppercased host, prefix,
`/x/../mcp`, fragment), `alg:none`, HS256 keyed on the Ed25519 public bytes, unknown `kid`,
wrong-key signatures, malformed `act` shapes, non-string `scope`; attenuation including the
multi-hop middle link; the approval race at 16/16 and 8-way concurrency on an isolated database;
`IrreversibleEffect` constructed in exactly one place; the `UNIQUE(approval_id)` backstop; the admin
reset absent from the tool list and gated by constant-time comparison. The reviewer also planted
four breaches of their own — accept `alg:none`, add HS256, drop expiry, drop `amount` from the
approval lookup — and each turned the suite red.

### The three new breaches

`scripts/plant_breaches.py` carries breaches **6, 7 and 8**: delete the approver gate, stop writing
transport refusals to the audit trail, stop catching `RecursionError`. Each requires its tests to
fail. The fixes are held to the standard ADR-003 set for the controls that were right the first
time — **eight planted, eight caught**, and the suite is green at **51 tests**.

### What this does not establish

Two reviews are two reviews. The first found a hole the author had not thought of, and so did the
second, which is evidence about the method rather than about the remaining count. The largest
unmitigated item is unchanged: a stolen, still-valid token used within its attenuated scope for
reversible reads is not detected here.

---

## ADR-005 — The third review: the container could not have booted

**Status:** accepted, 2026-09-17, **after** ADR-004 and after the project had been called complete.

ADR-004 closed two holes a security reviewer found by attacking a copy of the running system. This
one was found by asking a different question — *what did nobody look at?* — and the answer was: the
shell.

### 1. The entrypoint called a module that has never existed

`deployment/entrypoint.sh` ran `python -m agent_authz_broker.demo.seed` between the migration and
uvicorn. **There is no such module, and `git log --all --diff-filter=A -- "*seed*"` shows there
never was one in any commit.**

`entrypoint.sh` runs under `set -eu`, the seed branch fires whenever `AAB_ENVIRONMENT` is not
`production`, and `render.yaml` sets it to `staging`. The container would have exited non-zero
before `exec uvicorn`. **The deployment blueprint this repository publishes could not have booted.**
`make seed` and `make api` were broken the same way, and both are the documented local run path.

Nothing needed seeding, which is why the gap survived unnoticed: the schema has three tables —
`approval`, `irreversible_effect`, `audit_event` — and not one of them holds an account. The
synthetic accounts are a dict in `mcp_server.py`; the scenarios are code in `demo/matrix.py`.

**The step is removed rather than implemented.** Writing a seeder that seeds nothing, so that a
document describing it could stay true, is the wrong repair.

**Why nothing caught it, which is the part worth keeping.** `docs/deployment.md` §11 certified the
entrypoint as *"exercised against stubbed binaries in the image: it seeds when `AAB_ENVIRONMENT` is
unset."* The stub was a `python` that always succeeded. **Stubbing the interpreter makes the check
one that cannot fail** — the precise failure this repository plants breaches to avoid, in the one
file nobody thought to plant a breach in. Every guard was aimed at `src/`; the defect was in `sh`.
§11 now states the narrow thing that was actually proven.

### 2. The guard protecting the kill test was itself a guard that could not fail

`tests/test_predeclaration.py` exists because of Project 3's vacuous guard, and its own docstring
says *"a check that cannot fail is not a check."* All three of its assertions read
`test_kill_criteria.py` as **text**: seven names appear, the string `importorskip` does not, and
`await lab.effect_count()` occurs at least seven times.

A reviewer pointed out that this bans one spelling of one mechanism. Adding
`pytest.mark.skip(reason="flaky")` to the kill test's `pytestmark` leaves all three green. Verified
exactly: with the module skipped, `pytest tests/test_predeclaration.py` reports **3 passed** while
**zero of the seventeen kill tests run**. The count check had slack of its own — threshold seven
against a file containing eight, so one database read could be deleted unnoticed.

**Closed by asking pytest instead of reading source.** `pytest_collection_modifyitems` in
`tests/conftest.py`, `tryfirst` so it sees items before `-m` deselection removes them, refuses the
whole session with a `UsageError` if any collected kill test carries `skip` or `skipif`.
`UsageError` rather than a failing test, because a failing test can be deselected too. With the same
sabotage planted, it now names all seventeen and stops the run.

The text checks stay as a second line — they catch what collection cannot see, a `pytest.skip()`
inside a body — and were widened from `importorskip` to every spelling. The effect-count check is
now per scenario via `ast` rather than a count over the file.

### 3. Four smaller corrections

- **`read_approval` is outside the audit trail**, because it reaches no verdict and can cause no
  effect. True and defensible; but rule 6 said *"every refusal is audited"*, which implied
  otherwise. The rule is now scoped to *decisions*, and `docs/threat-model.md` §10 states that an
  agent can probe that tool without leaving a trace.
- **`GET /api/v1/demo/tokens` is open on any non-production instance**, and `render.yaml` deploys as
  `staging`. Deliberate — it is the lab's front door — and now disclosed in the threat model with
  the reason it is safe to say out loud: the approval gate needs `AAB_APPROVER_TOKEN`, which this
  endpoint does not mint, so an anonymous visitor holding every token here still cannot cause an
  irreversible effect.
- **`make help` advertised "ADR-003's five breaches"** while the script plants ten.
- **Four backticked paths pointed at private planning documents** absent from this public
  repository. Named as private rather than left dangling.

### What this review does not establish

Three reviews have now each found something the previous two did not, and each found it by changing
the *question* rather than by looking harder. That is evidence about method, not about a remaining
count. The largest item is still unchanged: a stolen, still-valid token used within its attenuated
scope for reversible reads is not detected here.

**Two load-bearing claims still have no independent execution**: `make breaches` and `make matrix`
run nowhere but on a developer's machine. Both now run in CI — `matrix` against a stable-field gate
rather than a byte diff, because every run mints fresh ids — which is what closes it.

---

## ADR-006 — Rate limiting: required, and what it is

**Status:** accepted, 2026-09-19.

### Was it required? The sources, not an opinion

| Source | What it says |
|---|---|
| `SKILL_MATRIX.md` legend | `●` load-bearing · **`○` present and real, but secondary** · blank = absent by design |
| `SKILL_MATRIX.md`, *Rate limiting* row | `○` in **project 4's column only**. No other project carries it |
| `SKILL_MATRIX.md`, gaps table | *"NOT delivered: rate limiting — project 4 shipped without it (ADR-002), so that row is now empty portfolio-wide and must be re-homed"* |
| `PORTFOLIO_BLUEPRINT.md`, project 4 **Major features** | *"…full audit trail · rate limiting"* |
| `PORTFOLIO_BLUEPRINT.md`, project 4 **Tests** | *"…durable-approval kill/resume test · **rate-limit tests**"* |

So: **required, and required to be proven by a test** — but `○`, which the legend defines as secondary
rather than load-bearing. Both halves matter. It had to exist; it must not be described as part of
the security claim. ADR-002 recorded it as not built and flagged the row as empty portfolio-wide,
which is an open gap rather than a decision. This closes it.

**It is not load-bearing and the README does not imply it is.** No rate limit stops a caller who
holds authority it should not have. That is the audience check, the attenuation rule and the approval
gate. Removing the limiter entirely would not admit a single extra attack in the kill test.

### What is limited

> **(verified subject, tool, fixed 60-second window)** — at most `AAB_RATE_LIMIT_PER_MINUTE` calls,
> default 30, `0` disables it.

- **The subject is the verified one**, never a value the caller supplied, so a caller cannot move
  itself into a fresh bucket by asking differently.
- **The bucket is the primary key** `(subject, tool, window_start)`. Two subjects cannot share one
  and neither can two tools, because there is no row for them to share.
- **Counted only for calls that were going to be allowed.** Counting refusals would let an attacker
  exhaust a *legitimate* subject's allowance by spraying its name at a tool it cannot use: the
  refusal is free to produce and the denial of service would land on the victim. Refusals are
  recorded in the audit trail, which is where a pattern of them belongs.
- **Claimed inside the transaction that writes the effect**, so a call that rolls back does not
  spend quota it never used.

### PostgreSQL, not Redis and not a dict

The blueprint said Redis. There is no Redis here, and adding one for a counter would be the habit the
owner's brief explicitly warned against — a whole service, on a free plan, for one integer.

An in-process counter was the other candidate and is worse than it looks. It states a bound *per
worker*: "30 per minute" behind N workers is 30 × N, and the deployment that exposes it is the one
nobody ran. That is the same reasoning as one-approval-one-effect, and it lands the same way — a
single `INSERT … ON CONFLICT DO UPDATE … RETURNING count`, atomic, so concurrent callers are
serialised by the row lock and each receives a distinct position. The entrypoint runs one worker
today; the bound does not depend on that staying true.

### The weaknesses, stated

- **Fixed window, not sliding.** A caller may spend a whole allowance at the end of one window and
  another at the start of the next, so the worst case across an arbitrary 60 seconds is **twice** the
  limit. A sliding window costs a row per request; this costs one row per bucket. The bound promised
  is *at most `limit` per fixed window*, and that is the bound the tests assert.
- **This is not DDoS protection and is not offered as any.** It bounds an *authenticated* caller.
  Volume that never presents a usable token is refused earlier by the verifier, and volume large
  enough to matter is a platform concern this application cannot address.
- **It is a ceiling, not fairness.** One subject inside its allowance can still crowd a free
  instance.

### Proven by

`tests/test_rate_limit.py`, against real PostgreSQL: below the limit succeeds · above it is denied
with **zero irreversible effects** · independent subjects do not share a bucket · the window recovers
· **ten concurrent calls against a ceiling of three produce exactly three effects** · `0` disables the
ceiling rather than refusing everything.

Breach **11** plants read-then-write — the plausible wrong implementation, which looks correct and
leaks under exactly the concurrency the bound is quoted for.

Live over HTTP against the container build, in `artifacts/deployed-smoke.json`: eleven calls against
a ceiling of ten, final call `rate_limited`, zero effects.
