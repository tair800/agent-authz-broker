# Deployment

How this runs, what it costs, and which properties are true only because of the plan it runs on.

**The console is deployed; the resource server is not.** `https://agent-authz-broker.vercel.app`
answers, and renders the committed artifacts because `BROKER_API_BASE_URL` is unset there. Render
and Neon have not been provisioned, so `https://agent-authz-broker.onrender.com/healthz` returns
404 and no MCP client has connected to a deployed instance. Section 11 says exactly which of the
claims below have been run and which have not.

---

## 1. Topology

```
  browser
     │
     ▼
  Vercel  (Hobby, fra1)  ── the read-only console ──┐
                                                    │  HTTPS
  MCP client / agent ─── Streamable HTTP /mcp ───────┤
                                                    ▼
                              Render Web Service (Docker, Free, Frankfurt)
                                 ├─ FastAPI: /mcp, /api/v1/*, /healthz
                                 └─ entrypoint: alembic upgrade head, then seed, then uvicorn
                                                    │  TLS
                                                    ▼
                              Neon PostgreSQL (Free, eu-central-1)
                                 ├─ approval          ← consumed by a conditional UPDATE
                                 ├─ irreversible_effect ← the table every test counts
                                 └─ audit
```

| Layer | Service | Plan | Region | Cost |
|---|---|---|---|---|
| Console | Vercel | Hobby | `fra1` | 0 |
| Resource server | Render Web Service (Docker) | Free | Frankfurt | 0 |
| PostgreSQL | Neon | Free | `eu-central-1` | 0 |

Total: **zero**, which was the constraint. Every limitation below follows from that and is recorded
rather than smoothed over.

**Render's own free PostgreSQL is deliberately not used.** It expires after 30 days, which would
take the demonstration down on a schedule with no warning. Neon's free tier does not expire.

The regions are chosen to sit together: Render Frankfurt, Neon `eu-central-1`, Vercel `fra1`. Every
authorization decision reads the database — the approval lookup and the consume are both in the
request path — so a transatlantic hop would be paid on every irreversible call.

## 2. The cold start, stated honestly

**Render's free plan spins the instance down after about 15 minutes of inactivity.** The next
request wakes it, and waking it means pulling the container, starting Python, running
`alembic upgrade head`, checking whether the database needs seeding, and binding the port. Neon's
free tier separately suspends an idle branch, so the first connection also pays a resume.

**Expect roughly 50 seconds for the first request after an idle period.** Subsequent requests are
normal. This figure is the documented behaviour of the free plan rather than a measurement taken
from this service, and it will be replaced with a measured one once the service is actually
deployed.

This matters more for an MCP server than for a web page, because **many MCP clients time out an
`initialize` well before 50 seconds** and will report the server as broken rather than as slow. The
practical advice for anyone connecting a client is to open `/healthz` in a browser first, wait for
it to answer, and then connect. That is a genuine wart of the free tier and not something the code
can fix.

## 3. Migrations run at container start, and that is a property of the plan

`deployment/entrypoint.sh` runs `alembic upgrade head` before uvicorn.

The usual objection is correct: a process that migrates on boot races every other replica for the
same DDL, and during a rolling deploy the old and new schema are both live. The clean answer is a
release command that runs once, before any instance starts.

**Render's free instance type has no release or pre-deploy hook — that is a paid feature.** So the
choice here is migrate-on-boot or migrate-by-hand, and migrate-on-boot is taken. The objection does
not apply for one specific reason: **the free plan runs exactly one instance**, with no horizontal
scaling and no rolling deploy. There is no second replica to race.

That is a property of the plan, not of the design. **Scale this to two instances and the race
returns immediately.** It is recorded as a limitation rather than resolved, because resolving it
means paying for a release hook.

A failed migration stops the container (`set -e`), the deploy stays unhealthy, and the server never
answers against a schema it does not expect. In this repository that matters more than usual: the
approval table's unique constraint is what makes one approval authorise exactly one irreversible
effect, so a half-migrated database is one whose central security property is unproven.

## 4. The demonstration data is seeded on boot, only into an empty database

`alembic upgrade head` creates the schema and leaves it empty, so a fresh Neon database would serve
a console with no accounts and no scenarios. The entrypoint therefore also runs
`python -m agent_authz_broker.demo.seed`, and it is guarded twice, in two different ways:

1. **Never when `AAB_ENVIRONMENT` is `production`.** Seeding writes invented accounts; an instance
   configured as production must never acquire them whatever else is true.
2. **Only into an empty database.** That check lives inside the seed module, not in the shell. Two
   emptiness checks in two languages drift, and the one that matters is the one inside the
   transaction that does the writing.

**There is deliberately no reset on this path.** A free container cold-starts often, and a
reset-on-boot would discard whatever approvals a visitor had just created, mid-demonstration. The
administrative reset is a separate, explicit operator route — see §7.

## 5. Configuration

Every value arrives through `AAB_*` environment variables. Nothing is baked into the image, which
is why the local image and the deployed image are the same image.

| Variable | Secret | What it is |
|---|---|---|
| `AAB_ENVIRONMENT` | no | Which deployment this is. `production` suppresses seeding. |
| `AAB_POSTGRES_DSN` | **yes** | The provider's connection string, as given. See §6. |
| `AAB_RESOURCE_SERVER_URL` | no | **This server's own identity**, and the whole audience check. |
| `AAB_CORS_ALLOW_ORIGINS` | no | JSON array of browser origins allowed to call the console API. |
| `AAB_ADMIN_RESET_TOKEN` | **yes** | Gates the operator reset route. Unset: unavailable. |
| `AAB_APPROVER_TOKEN` | **yes** | Gates approval-granting. **Not an MCP credential** — no token the agent holds satisfies it. Unset: unavailable. |
| `PORT` | no | Supplied by Render. The entrypoint binds it; 8000 locally. |

An empty value for either token is read as unset rather than arming the gate with the empty string:
a cleared dashboard field or a Makefile forwarding an unset variable would otherwise produce a route
that 401s at everything and looks configured.

The values `AAB_ENVIRONMENT` accepts are defined in `src/agent_authz_broker/config.py`.

The three secrets are `sync: false` in `render.yaml`: Render prompts for them on first apply and
stores them encrypted. No value enters the repository, the blueprint, or a build log.

The CI secret scan is a **backstop, and a narrow one**. Be precise about what it covers, because a
gate that is believed to cover more than it does is worse than no gate: it catches a private-key
block, an `AAB_ADMIN_RESET_TOKEN` or `AAB_APPROVER_TOKEN` assigned a value, and a JWT literal. **It does not recognise a
connection string**, so a committed `AAB_POSTGRES_DSN` pointing at a real provider would pass it.
The patterns are kept narrow deliberately — a broader DSN rule matches the local
`postgresql://aab:aab_local_dev@localhost:15434/aab` that appears legitimately in `.env.example`,
the `Makefile`, the CI service container and `config.py`'s default, and a gate that cries wolf is
one people learn to skip. What actually keeps the DSN out is `.gitignore` excluding `.env` and the
value living only in Render's dashboard; the scan is the second line, not the first.

### `AAB_RESOURCE_SERVER_URL` is the one value that will visibly break a deployment

It is the whole of the audience check. Set it wrong and **every call is denied with
`audience_mismatch`** — the server working correctly against a misconfiguration. It cannot be
derived from Render's `fromService`, which yields a bare hostname with no scheme and no path, so it
is set inline in `render.yaml` and must be corrected if Render assigns a hostname other than the
default for the service name.

If the demonstration denies everything, check this value first.

## 6. Paste the provider's DSN verbatim — the normaliser handles the rest

Neon's console hands out a connection string ending in
`?sslmode=require&channel_binding=require`. Those are **libpq** parameters. `asyncpg.connect`
parses a URL itself and understands `sslmode`; SQLAlchemy's asyncpg dialect instead splits the
query string into keyword arguments and calls a function with no place to put them. Pasted in
verbatim to a naive setup, that DSN produces a service that reports itself healthy and cannot
serve a request.

`async_dsn` in `src/agent_authz_broker/db/engine.py` normalises it before the engine is built, so
`AAB_POSTGRES_DSN` takes the provider's string unedited. Read that module for the authority on
this; in summary it:

- adds `+asyncpg` to the scheme when the scheme carries no driver, so a plain
  `postgresql://…` works and an explicit `postgresql+asyncpg://…` is left alone;
- rewrites `sslmode=require` (and `verify-ca` / `verify-full`) to asyncpg's `ssl=require`;
- drops `channel_binding`, which asyncpg negotiates itself and has no connect argument for —
  forwarding it is a guaranteed `TypeError`;
- sets `prepared_statement_cache_size=0` when the host looks like a pooled endpoint
  (`-pooler.`), because pgBouncer in transaction mode does not keep a prepared statement across
  checkouts and caching them there fails intermittently and nowhere else;
- **keeps** any parameter it does not recognise, rather than discarding it silently.

`build_engine` then sets `pool_pre_ping`, because a free-tier database that has suspended hands
back a connection that looks alive and is not — precisely the shape of the cold start in §2.

## 7. The administrative reset

The demonstration needs a way back to a clean state after visitors have spent approvals.

- It is an **operator route over HTTP**, gated on `AAB_ADMIN_RESET_TOKEN`.
- It is **not an MCP tool**, and ADR-001 predeclares that the agent must not be able to reach it
  through the protocol at all. An agent that can reset the database can erase the effects it
  caused, which makes the audit trail worthless.
- Leave `AAB_ADMIN_RESET_TOKEN` unset and the route is unavailable. That is the correct posture for
  any instance that is not a public demonstration.

## 8. The console

The console is a separate Vercel project with **root directory `frontend/`**. It is read-only: it
renders decisions, the delegation chain, the approval queue and the audit trail. It does not mint
tokens and it cannot call the irreversible tool.

Point its API base URL at the Render service, and put that same origin in
`AAB_CORS_ALLOW_ORIGINS`. CORS here is hygiene, not a security boundary — it constrains browsers
and constrains nothing that is not a browser. The audience, scope and approval checks are the
boundary; see `docs/threat-model.md`.

## 9. Reproducing it locally

Everything below runs against a throwaway PostgreSQL container with invented data. No cloud
account, no credential, nothing paid.

```bash
make install       # uv sync --frozen
make db-up         # the postgres:16 in docker-compose.yml, on localhost:15434
make migrate       # alembic upgrade head
make seed          # synthetic accounts and the ADR-001 scenarios
make api           # uvicorn on http://localhost:8000
```

Then the checks, in the order CI runs them:

```bash
make gate          # format, lint, mypy, the offline suite
make killtest      # the adversarial suite against the real database
```

To exercise the image the way Render does:

```bash
docker build -t agent-authz-broker .
docker run --rm -p 8000:8000 \
  -e AAB_ENVIRONMENT=local \
  -e AAB_POSTGRES_DSN=postgresql://aab:aab_local_dev@host.docker.internal:15434/aab \
  -e AAB_RESOURCE_SERVER_URL=http://localhost:8000/mcp \
  agent-authz-broker
```

`host.docker.internal` is how the container reaches a database running on the host; on Linux add
`--add-host=host.docker.internal:host-gateway`.

Note that `AAB_RESOURCE_SERVER_URL` must match the `aud` of whatever tokens you present, or the
server will refuse them — which is the mechanism working, and is worth seeing once deliberately.

## 10. Limitations, collected

Nothing here is a surprise; each is argued above. They are gathered so a reader does not have to
assemble the list themselves.

| Limitation | Cause | What removes it |
|---|---|---|
| ~50 s cold start after idle | Render free spins down; Neon suspends | A paid always-on plan |
| Migrate-on-boot, not a release hook | Free plan has no release hook | A paid plan |
| Safe only because one instance runs | Free plan does not scale out | A release hook |
| No rate limiting | Not built — ADR-002 records it | Out of scope for this increment |
| No token revocation or binding | Not built — see the threat model §8 | Out of scope here |
| Synthetic data only | By design | Nothing. It should stay that way. |
| Neon free branch limits | Free tier | A paid Neon plan |

## 11. Verified, and not

**Verified by running**, on the machine this was written on:

- The image builds, and the runtime layer contains no `uv` and no compiler. It runs as uid 10001,
  resolves `alembic` and `uvicorn` from `/app/.venv/bin`, and imports the package and every
  dependency.
- Removing `LICENSE` from the build context does fail the build with
  `OSError: License file does not exist: LICENSE`, which is why the Dockerfile copies it beside
  the manifest. That comment is a reproduced result, not folklore.
- The entrypoint is `sh`-compatible and was exercised against stubbed binaries in the image: it
  seeds when `AAB_ENVIRONMENT` is unset, does not seed when it is `production`, honours `PORT`,
  and — the one that matters — **stops with a non-zero exit before starting uvicorn when
  `alembic upgrade head` fails.**
- `render.yaml` and the CI workflow parse. The secret scan's four patterns catch a private-key
  block, a committed reset or approver token and a JWT literal, and match nothing in this
  repository including the workflow that defines them.
- `make db-up` brings `docker-compose.yml` up to a healthy PostgreSQL; every other target expands
  to the command it documents.
- **The approval gate, driven over HTTP against a running server.** `POST /api/v1/approvals`
  answered **401** with no credential, **401** with a valid agent bearer token minted by the test
  authority, and **201** with `AAB_APPROVER_TOKEN`. The approval that 201 created was then spent by
  `issue_credit` through a real MCP client — so the gate closes the hole without closing the demo.
- **Refusals at the transport, audited.** With the server running, `GET /api/v1/audit` went from 1
  row to 3 after replaying a token minted for another resource server and then a garbage bearer
  string over real MCP: `audience_mismatch` (subject `agent-7`) and `token_malformed` (no subject),
  both with `tool` recorded as `-` because the request was never routed. A reviewer measured **zero**
  rows for both of those before the fix.

**Verified by deploying**, after the above was written:

- The console is live on Vercel Hobby at `https://agent-authz-broker.vercel.app`. Every route
  answers 200, and each one states on its face that it is rendering committed artifacts rather than
  a live broker, because `BROKER_API_BASE_URL` is unset in that project.

**Not verified:** the resource server has **not** been deployed. Render and Neon were never
provisioned — `https://agent-authz-broker.onrender.com/healthz` returns 404 — so no MCP client has
connected to a deployed instance, the entrypoint's migrate-then-seed-then-serve sequence has run
only against local PostgreSQL, and the ~50 s cold start is the platform's documented behaviour
rather than a measurement of this service. The image build was exercised with a placeholder
`alembic.ini`, because the real migration environment had not landed when this was written.

This paragraph previously read *"nothing here has been deployed to Render, Neon or Vercel"* while
the README linked the live console. It was written before the console went up and nothing brought
it forward. It is corrected in place rather than deleted, because a repository whose whole subject
is refusing to take a claim on trust should show where it failed to check its own.
