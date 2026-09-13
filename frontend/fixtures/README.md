# fixtures

What this console renders when `BROKER_API_BASE_URL` is unset — which is the normal state of the
public demo, so these files are a shipped path and not a test scaffold.

**They are a measurement.** Every one of them is written by a single run of

```bash
python -m agent_authz_broker.demo
```

against real PostgreSQL, into `artifacts/`, and copied here by `scripts/copy-artifacts.mjs` at
build time. Do not edit them. An edit is overwritten by the next build, and — more to the point —
an edit is a number on a security console that nothing produced.

| File | What the run wrote it from |
|---|---|
| `matrix.json` | every scenario under both policies; each effect count is `SELECT count(*) FROM irreversible_effect` against a clean database |
| `audit.json` | the `audit_event` rows the authorization path wrote during that run, both policies, newest first |
| `approvals.json` | the `approval` rows the run left behind, with the state each ended in |
| `chains.json` | each scenario's delegation chain **decoded from the token it actually minted**, attenuated by the same `effective_scopes` the server uses |

## Why this file used to say something else

Three of these four were hand-written, and this README explained at length why
`totals.naive_effects` was 6. It was 4. The matrix fixture had been corrected when a reviewer
caught it before publication; the correction reached one file and stopped, because the other three
were only read by people, and not often.

So the audit screen went on showing the naive verifier minting six `eff-` ids — the prediction
[ADR-001](../../DECISIONS.md) had already retracted — under a banner reading *every number here was
measured; none was typed*. The chain screen named `alice` as the subject of the four tokens the
scenarios mint for `agent-7`, and disagreed with `GET /api/v1/chain/{id}`, which had its own
hand-written copy of the same chains and got that part right.

The fix is not a more careful editor. It is that there is nothing here left to edit: the API's
chain route now serves `artifacts/chains.json` too, so the second copy is gone as well.

## Two things worth knowing before quoting them

- **The approvals screen shows the hardened server's store, not both.** Under the naive policy the
  approvals for the audience and delegation scenarios are *consumed* rather than left pending —
  that consumption is the breach. `audit.json` carries both policies and records it. Showing two
  interleaved approval stores in one table with no column to tell them apart would be worse than
  choosing one and saying so here.
- **`role` on a chain link.** A token issued directly to its subject has one link and no
  delegation. It is written as a single `leaf`, and the chain screen names that case rather than
  drawing a one-node arrow.

`chains.json` is keyed by scenario id because the API serves one chain per id at
`/api/v1/chain/{scenarioId}`; the fixture store indexes it, the API reads the same key.
