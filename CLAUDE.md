# CLAUDE.md — agent-authz-broker

Operating contract for this repository. Read before any work here.

**Parent portfolio rules remain authoritative.** They live in a private planning workspace that
this repository is a child of and **are deliberately not published here**; they govern, this file
adds project rules, and nothing here relaxes one. Every rule a reader needs in order to judge this
repository is in this file or in `DECISIONS.md` — nothing below depends on a document you cannot
see.

---

## What this project is

An MCP resource server that computes authority rather than accepting it. See `DECISIONS.md` ADR-001
— the claim, the threat model and the kill test, all fixed **before implementation**.

---

## Non-negotiable rules

### 1. Everything the client sends is untrusted, including the token's claims about itself

The server independently computes authority from the signature, the audience, the **whole**
delegation chain, and its own database. The leaf's `scope` claim is never trusted alone.

### 2. No tool argument may assert authority

The irreversible tool's input schema carries no field a caller could use to claim an approval. This
is structural, and a guard test walks the advertised schema. Approval is found by the server.

### 3. One approval, one effect — in the database

A conditional `UPDATE` guarded by a `UNIQUE` constraint. **No in-process lock may be used for this**:
it would pass the test and fail behind two workers.

### 4. Effect counts come from the table

`SELECT count(*) FROM irreversible_effect`. Never from what a component reports about itself.

### 5. Granting an approval takes a credential no agent can hold

`POST /api/v1/approvals` is gated on `AAB_APPROVER_TOKEN`, which the test authority does not mint.
**"It is not an MCP tool" is not the boundary.** The agent is a process; it makes ordinary HTTP
requests to the same origin the tools are served from. This route was open in every environment
until a review used it to produce a real irreversible effect end to end — ADR-004.

### 6. Every authorization decision is audited, including the ones made before a tool is routed

A token the transport rejects never reaches `effects.call_tool`. `BrokerTokenVerifier` writes that
row itself, with no subject and no token id — an unauthenticated token's claims are assertions, and
an audit trail that repeats them has been written by the attacker.

**"Decision", not "refusal", and the difference is `read_approval`.** It is the one tool that does
not call `effects.call_tool`: it returns state, reaches no verdict, and cannot cause an effect, so
it writes no audit row. An agent can therefore probe it for approval ids without leaving a trace.
That is accepted — it answers `not_found` uniformly, so the probe learns nothing — and
`docs/threat-model.md` §10 states it rather than letting this rule imply otherwise.

### 7. The admin reset is not an MCP tool

It is HTTP infrastructure behind its own bearer token, and it must never appear in the tool list.

### 8. No model output is in the security path

Authorization is deterministic code. An agent may ask for anything; what it gets is computed.

### 9. A guard that cannot fail is not a guard

Every control must be shown to be load-bearing by removing it and watching a test go red. All twelve
are a script — `make breaches` — not a table in a document. See ADR-003 through ADR-007.

A guard that *cannot* fire is a subtler version of the same thing: the `RecursionError` catch in
`tokens.py` is unreachable behind the size cap, so it is tested with the cap lifted and labelled as
defence behind a guard rather than as a guard.

**This rule has been broken twice, in this repository, by the guards written to enforce it.**
`tests/test_predeclaration.py` checked the kill test as *text* and stayed green under
`pytest.mark.skip`; `docs/deployment.md` certified the container entrypoint against a *stubbed*
interpreter, which is how it shipped calling a module that has never existed. Both are ADR-005. A
guard written in a file nobody plants breaches in is a guard nobody has tested.

### 10. Secrets

Never commit keys, tokens or DSNs. Signing keys are in-memory and per-process. `.env.example` carries
names and placeholders only.

### 11. Attribution

Never add `Co-Authored-By`, `Generated with…`, or any similar marker anywhere.

### 12. Honesty

Never describe functionality that does not exist. Every number in the README comes from a committed
run and is reproducible with `make`.

---

## Key commands

```bash
make gate        # lint, types, offline suite
make matrix-gate # re-measure and prove every published number still reproduces
make killtest    # the adversarial suite against real PostgreSQL
make breaches    # replant all twelve breaches; each must turn its tests red
make matrix      # measure the security matrix and every console artifact
make api         # the MCP server + console API
make smoke BASE=<url>  # every boundary, over HTTP, against a running instance
uv run python -m agent_authz_broker.demo   # measure the security matrix
uv run python scripts/mcp_smoke.py         # real MCP client over Streamable HTTP
```
