# CLAUDE.md — agent-authz-broker

Operating contract for this repository. Read before any work here.

**Parent portfolio rules remain authoritative.** `../../CLAUDE.md` and
`../../PORTFOLIO_MASTER_SPEC.md` govern; this file adds project rules and never relaxes a parent one.

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

### 5. The admin reset is not an MCP tool

It is HTTP infrastructure behind its own bearer token, and it must never appear in the tool list.

### 6. No model output is in the security path

Authorization is deterministic code. An agent may ask for anything; what it gets is computed.

### 7. A guard that cannot fail is not a guard

Every control must be shown to be load-bearing by removing it and watching a test go red. See
ADR-003.

### 8. Secrets

Never commit keys, tokens or DSNs. Signing keys are in-memory and per-process. `.env.example` carries
names and placeholders only.

### 9. Attribution

Never add `Co-Authored-By`, `Generated with…`, or any similar marker anywhere.

### 10. Honesty

Never describe functionality that does not exist. Every number in the README comes from a committed
run and is reproducible with `make`.

---

## Key commands

```bash
make gate        # lint, types, offline suite, then the adversarial suite
make killtest    # the adversarial suite against real PostgreSQL
make api         # the MCP server + console API
uv run python -m agent_authz_broker.demo   # measure the security matrix
uv run python scripts/mcp_smoke.py         # real MCP client over Streamable HTTP
```
