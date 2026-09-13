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

.PHONY: help install fmt lint types test gate db-up migrate seed killtest api clean

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

seed: migrate ## Seed the synthetic accounts and the ADR-001 scenarios. Never deletes.
	AAB_POSTGRES_DSN=$(DSN) AAB_ENVIRONMENT=local \
	  uv run python -m agent_authz_broker.demo.seed

killtest: migrate ## THE ADVERSARIAL SUITE. Every count comes from irreversible_effect.
	AAB_POSTGRES_DSN=$(DSN) AAB_ENVIRONMENT=local AAB_RESOURCE_SERVER_URL=$(AUD) \
	  uv run pytest -m integration

api: seed ## Serve the MCP server and the console API against the seeded database
	AAB_POSTGRES_DSN=$(DSN) AAB_ENVIRONMENT=local AAB_RESOURCE_SERVER_URL=$(AUD) \
	  uv run uvicorn "agent_authz_broker.app:create_app" --factory --port 8000

clean: ## Remove caches. The database is left alone: `docker compose down` stops it.
	rm -rf .pytest_cache .mypy_cache .ruff_cache
