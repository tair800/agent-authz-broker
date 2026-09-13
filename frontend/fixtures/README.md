# fixtures

What this console renders when `BROKER_API_BASE_URL` is unset — which is the normal state of the
public demo, so these files are a shipped path and not a test scaffold.

**They are not a measurement.** Every screen that reads them says so on its face. They reproduce
the matrix that `DECISIONS.md` ADR-001 fixed *before* any implementation existed; the live backend
recomputes the same screens from real signed tokens, and its effect counts come from
`SELECT count(*) FROM irreversible_effect` rather than from anything a component reports about
itself.

Two things in here are derived rather than observed, and are worth knowing before you quote them:

- **The naive column across the three approval scenarios.** ADR-001 states the naive baseline is
  signature and expiry only, and that it fails bug classes A, B *and* C — C being the confused
  deputy on approval. A verifier with no approval store allows `no_approval`, `expired_approval`
  and `approval_replay`, which is why `totals.naive_effects` is 6 rather than 3.
- **`role` on a chain link.** A token issued directly to its subject has one link and no
  delegation. It is written here as a single `leaf`, and the chain screen names that case rather
  than drawing a one-node arrow.

`chains.json` is keyed by scenario id because the API serves one chain per id at
`/api/v1/chain/{scenarioId}`; the fixture store indexes it, the API does not.
