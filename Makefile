# Everything a reader needs to run this repository. `make help` lists it.
#
# Two suites, and the split is the point. `test` needs nothing — no database, no network, no
# credential — because the token verifier and the attenuation rule are pure functions. `killtest`
# needs real PostgreSQL, because one-approval-one-effect under concurrency is a property of the
# database and cannot be demonstrated against a stand-in.

SHELL := /bin/sh

# The database, its port and its password all come from docker-compose.yml. They are repeated
# here only to build the DSN; change them there.
PG_PORT := 15434
DSN := postgresql://aab:aab_local_dev@localhost:$(PG_PORT)/aab
AUD := http://localhost:8000/mcp

# For `make smoke`. RATE_LIMIT must match what the instance is configured with.
RATE_LIMIT ?= 30

.PHONY: help install fmt lint types test gate db-up migrate killtest breaches matrix matrix-gate smoke api clean

help: ## List the targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk -F':.*?## ' '{printf "  %-10s %s\n", $$1, $$2}'

install: ## Install exactly what uv.lock pins
	uv sync --frozen

fmt: ## Format
	uv run ruff format .

lint: ## Lint, and fail on unformatted source
	uv run ruff format --check .
	uv run ruff check .

types: ## Strict type check
	uv run mypy

test: ## The offline suite. No database, no network, no credential.
	uv run pytest -m "not integration"

gate: ## The offline gate, in the order CI runs it. Needs no database.
	uv sync --frozen
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy
	uv run pytest -m "not integration"

db-up: ## Start the local PostgreSQL from docker-compose.yml and wait for it
	docker compose up -d --wait

migrate: db-up ## Bring the schema to head
	AAB_POSTGRES_DSN=$(DSN) uv run alembic upgrade head

# There is no `seed` target. It ran `python -m agent_authz_broker.demo.seed`, a module that was
# never written -- nothing in the schema holds an account, so there was never anything to seed.
# `make api` therefore depends on `migrate`. See DECISIONS.md ADR-005.

killtest: migrate ## THE ADVERSARIAL SUITE. Every count comes from irreversible_effect.
	AAB_POSTGRES_DSN=$(DSN) AAB_ENVIRONMENT=local AAB_RESOURCE_SERVER_URL=$(AUD) \
	  uv run pytest -m integration

breaches: migrate ## Replant all eleven planted breaches; each must turn its own tests red
	AAB_POSTGRES_DSN=$(DSN) AAB_ENVIRONMENT=local AAB_RESOURCE_SERVER_URL=$(AUD) 	  uv run python scripts/plant_breaches.py

matrix-gate: migrate ## Re-measure and prove every committed number still reproduces
	AAB_POSTGRES_DSN=$(DSN) AAB_ENVIRONMENT=local AAB_RESOURCE_SERVER_URL=$(AUD) \
	  uv run python scripts/gate_matrix.py

matrix: migrate ## Measure the security matrix and write every console artifact
	AAB_POSTGRES_DSN=$(DSN) AAB_ENVIRONMENT=local AAB_RESOURCE_SERVER_URL=$(AUD) 	  uv run python -m agent_authz_broker.demo

# Forwarded, never defaulted. A value here would be a committed credential for granting
# approvals, and an empty one is read as unset (see config.py), so POST /api/v1/approvals
# is simply unavailable unless you export this yourself before running the target.
smoke: ## Drive every boundary against a RUNNING instance. BASE=<url> and AAB_APPROVER_TOKEN required.
	uv run python scripts/deployed_smoke.py --base-url $(BASE) --rate-limit $(RATE_LIMIT)

api: migrate ## Serve the MCP server and the console API
	AAB_POSTGRES_DSN=$(DSN) AAB_ENVIRONMENT=local AAB_RESOURCE_SERVER_URL=$(AUD) \
	  AAB_APPROVER_TOKEN="$(AAB_APPROVER_TOKEN)" \
	  uv run uvicorn "agent_authz_broker.app:create_app" --factory --port 8000

clean: ## Remove caches. The database is left alone: `docker compose down` stops it.
	rm -rf .pytest_cache .mypy_cache .ruff_cache
