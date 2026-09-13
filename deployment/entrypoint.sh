#!/bin/sh
# Container entrypoint: bring the schema to head, seed the demonstration if this is one, then serve.
#
# `set -e` carries more weight here than usual. A failed migration must stop the container rather
# than let uvicorn come up against a schema the code does not expect — and in this repository the
# schema is not incidental. The approval table's unique constraint is what makes one approval
# authorise exactly one irreversible effect (ADR-001 scenario D). A server running against a
# half-migrated database is a server whose central security property is unproven. Render restarts
# it, the deploy stays unhealthy, and that is the correct outcome.
#
# `set -u` catches a mistyped variable name here instead of turning it into an empty default.
set -eu

# --------------------------------------------------------------------------------- schema
#
# **Why migrations run here rather than as a release hook.** A process that migrates on boot races
# every other replica for the same DDL, and during a rolling deploy the old and new schema are both
# live. The clean answer is a release command that runs once before any instance starts.
#
# Render's free instance type has no release or pre-deploy hook — that is a paid feature — so the
# choice on this plan is migrate-on-boot or migrate-by-hand. Migrate-on-boot is taken, and the
# usual objection does not apply for one specific, plan-dependent reason: **the free plan runs
# exactly one instance**, with no horizontal scaling and no rolling deploy. There is no second
# replica to race.
#
# That is a property of the plan and not of the design. Scale this to two instances and the race
# returns immediately. It is recorded as a limitation in docs/deployment.md rather than resolved,
# because resolving it means paying for a release hook.
echo "entrypoint: applying migrations"
alembic upgrade head

# ----------------------------------------------------------------------------------- demo data
#
# `alembic upgrade head` leaves the schema empty, so a fresh database would serve a console with
# no accounts and no scenarios to run. The seed module fills it with synthetic accounts and the
# ADR-001 scenarios.
#
# Two guards, and they are different in kind:
#
#   1. **Never in production.** Seeding writes invented accounts. An instance configured as
#      production must never acquire them, whatever else is true.
#   2. **Only into an empty database.** That check lives in the seed module, which seeds an empty
#      database and returns without writing otherwise. It is deliberately not duplicated here:
#      two emptiness checks in two languages drift, and the one that matters is the one inside the
#      transaction that does the writing.
#
# There is deliberately **no reset** on this path. A free container cold-starts often, and a
# reset-on-boot would discard whatever approvals a visitor had just created — mid-demonstration.
if [ "${AAB_ENVIRONMENT:-local}" != "production" ]; then
  echo "entrypoint: seeding the demonstration if the database is empty"
  python -m agent_authz_broker.demo.seed
else
  echo "entrypoint: AAB_ENVIRONMENT is production, not seeding"
fi

# ------------------------------------------------------------------------------------- serve
#
# `exec` so uvicorn replaces this shell and becomes the process the platform signals. Without it
# SIGTERM reaches /bin/sh, which does not forward it, and every shutdown becomes a kill after the
# grace period — the difference between draining in-flight requests and severing them.
#
# PORT is supplied by the platform. The default keeps `docker run -p 8000:8000` working unchanged
# on a laptop.
#
# One worker, and that is not a limitation being hidden. The one-approval-one-effect guarantee is
# enforced by a conditional UPDATE in PostgreSQL precisely so that it does not depend on how many
# workers there are; a second worker would not break it. The free plan has one CPU, so a second
# worker would buy contention rather than throughput.
echo "entrypoint: starting uvicorn on ${PORT:-8000}"
exec uvicorn "agent_authz_broker.app:create_app" \
  --factory \
  --host 0.0.0.0 \
  --port "${PORT:-8000}"
