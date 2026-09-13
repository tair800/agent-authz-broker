# The authorization lab console

Four screens over the broker's read-only API. The claim the console exists to make legible:

> An agent can request an action. It cannot manufacture the authority to perform one.

| Screen | What it answers |
|---|---|
| `/` | What did each verifier let through, and how many irreversible effects did that cost? |
| `/chain` | Where in the delegation chain did authority stop existing? |
| `/approvals` | What did a human actually agree to, and has it already been spent? |
| `/audit` | For each decision: how far did the request get before it was refused? |

## Running it

```
npm install
npm run dev        # http://localhost:3000
npm run build
npm test           # vitest
npm run typecheck  # tsc --noEmit
npm run lint
```

## Configuration

One variable, `BROKER_API_BASE_URL`, read on the server and only in `src/lib/server/source.ts`.
See `.env.example`.

**Unset is a supported, shipped state.** The console then renders the committed fixtures in
`frontend/fixtures/`, which is the normal path for the public demo. Every screen says on its face
which of the two it is showing, because the fixtures reproduce the matrix `DECISIONS.md` ADR-001
predeclared before any code existed, while the live backend recomputes it from real signed tokens
with its effect counts read from `select count(*) from irreversible_effect`. Those are different
kinds of claim and a reader is entitled to know which one is on screen.

A live read that fails is reported as a failure. It does **not** silently fall back to fixtures.

## What this console is not

- It is **not in the security path.** Nothing here authorizes anything; the decisions it renders
  were made by the resource server and are re-derivable from the audit table without it.
- It **holds no credential.** No token, no signing key, no private key is accepted, displayed or
  stored, and there is no variable for one. `src/test/boundary.test.ts` scans the source for the
  strings and fails the build if any appear.
- It **makes no browser request to the broker.** Every screen is a server component, there is no
  `"use client"` anywhere in the app, and the browser talks only to this app's own origin — so the
  broker needs no CORS entry for the console to work.

## Design notes worth knowing before reading the code

**Colour means "did authority hold", not "is this good news".** On five of six scenarios the
allowed answer is the failure, so `allowed` is never green and `denied` is never red. The naive
column is tinted as a breach exactly where it diverges from the hardened one.

**Open vocabularies are not policed.** Refusal reasons, policy names and approval states are typed
as `string`, not as closed unions, even though the broker's own `DenialReason` is a closed set. A
console that refuses to render a reason it was not recompiled for hides the one new refusal you
most want to see. Shape *is* validated — see `src/lib/parse.ts` — so a malformed payload becomes a
named failure rather than blank cells.

**Amounts are never parsed.** Whatever the broker sends is what is displayed. Re-deriving a
monetary value in a browser is how two systems come to disagree about one.

**Fixture provenance.** Two values in `fixtures/` are derived from ADR-001 rather than observed —
the naive column across the three approval scenarios, and the `role` of a single-link chain.
`fixtures/README.md` says which and why.

## Layout

```
fixtures/                  committed stand-ins; a shipped path, not a test scaffold
src/app/                   four screens, each with its own loading state
src/components/            presentational only; pure, synchronous, testable
src/lib/types.ts           the shapes, and the glosses for known refusal reasons
src/lib/parse.ts           shape validation for both paths
src/lib/server/source.ts   the only module that knows where the broker is
src/test/boundary.test.ts  the source scan that keeps the claims above honest
```
