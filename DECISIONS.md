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

`PORTFOLIO_BLUEPRINT.md` §4 specifies an XL build (~28 sessions): self-hosted Keycloak with an RFC
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
| Redis rate limiting | **Not built.** |
| OpenTelemetry + Langfuse | **Not built.** |
| Step-up authorization on 403 | **Not built.** |
| CIMD vs DCR analysis | **Not built.** |
| Full RFC 9728 / 8707 / 9207 conformance suites | **Not built.** RFC 8707's resource indicator is *used* — it is how audience binding is expressed — but no conformance suite is claimed. |
| Cloud Run + Cloud SQL | **Not used.** Render Free + Neon Free, per the owner's zero-cost instruction. |

**The portfolio consequence, recorded rather than absorbed:** `SKILL_MATRIX.md` makes project 4 the
**sole home** of *MCP server design*, *OAuth 2.1 / authn / authz*, *rate limiting* and *API security*.
MCP and resource-server authorization are delivered. **Rate limiting is now delivered nowhere in the
portfolio** and that row must be corrected or re-homed.

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

Every control was restored and the full suite is green: **32 tests**.

**Breach 3 is the most informative of the five.** Removing the conditional from the `UPDATE` did not
produce a wrong answer — it produced a `psycopg`/asyncpg `IntegrityError` from the UNIQUE constraint
on `irreversible_effect.approval_id`. That is the backstop doing its job: even with the application
logic removed, the database refused to record a second effect against one approval. The two
mechanisms are genuinely independent, which is the only reason it is honest to call the second one a
backstop rather than a comment.

**What this review does not establish.** It shows that each control is load-bearing and that the
tests detect its removal. It does not enumerate every attack — no such review does. The threat model
in `docs/threat-model.md` states what is out of scope, and the largest item is unchanged: a stolen,
still-valid token used within its attenuated scope for reversible reads is not detected here.
