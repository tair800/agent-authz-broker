# syntax=docker/dockerfile:1
#
# The resource server image. Multi-stage, so the runtime layer carries a virtualenv and nothing
# that built it — no uv, no compiler, no package index cache. What ships is what runs.
#
# Nothing secret is baked in. Every value the server needs arrives through AAB_* environment
# variables at start, which is why the same image is the local image and the deployed one.

# ----------------------------------------------------------------------------- build
FROM python:3.12-slim AS build

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Pinned by digest-free tag on purpose: the version is the thing that must match the lockfile's
# producer, and it is the same version CI and the Makefile use.
COPY --from=ghcr.io/astral-sh/uv:0.11.15 /uv /bin/uv

WORKDIR /app

# Dependencies before source, so editing a module does not invalidate the dependency layer.
#
# LICENSE and README.md are copied alongside the manifest because hatchling reads both out of
# `pyproject.toml`'s metadata (`license = { file = "LICENSE" }`, `readme = "README.md"`). Omit
# them and the build fails with "License file does not exist" at the point the project itself is
# installed — a long way from the line that caused it. Learned by building the image, not by
# reading the manifest.
COPY pyproject.toml uv.lock LICENSE README.md ./
RUN uv sync --frozen --no-install-project --no-dev

COPY src ./src

# Alembic needs its config and its script directory inside the image, because migrations run in
# the container (see deployment/entrypoint.sh for why they cannot run anywhere else on this plan).
#
# `alembic.ini` is required and deliberately not optional: a missing one fails the *build*, which
# is a far better place to discover it than a deploy that comes up and cannot find
# `script_location`.
#
# `migrations*` is a wildcard, and that is not sloppiness. The migration scripts may live at the
# repository root (`migrations/`) or inside the package (`src/agent_authz_broker/db/migrations/`);
# the second is already covered by `COPY src`, and under BuildKit a wildcard that matches nothing
# is a no-op rather than an error. So one Dockerfile serves both layouts and neither silently
# ships without its migrations.
COPY alembic.ini ./
COPY migrations* ./migrations/

# Now install the project itself into the same virtualenv.
RUN uv sync --frozen --no-dev

# --------------------------------------------------------------------------- runtime
FROM python:3.12-slim AS runtime

# The unprivileged user is created before anything is copied, so the copies land owned by it and
# no recursive chown is needed. The server writes nothing to the filesystem; it writes rows.
RUN useradd --create-home --uid 10001 app

WORKDIR /app
COPY --from=build --chown=app:app /app /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# `--chmod` rather than trusting the checkout's mode bit: this repository is developed on Windows,
# which does not carry an executable bit, so a clone there produces a 0644 entrypoint and a
# container that exits with "permission denied" before it reaches its first line.
COPY --chmod=0755 deployment/entrypoint.sh /app/entrypoint.sh

USER app
EXPOSE 8000

# ENTRYPOINT, not CMD. `docker run <image> <something>` then cannot quietly replace the migration
# step with a bare command — the schema must be at head before the server answers a single MCP
# call, and that ordering should not be one argument away from being skipped.
ENTRYPOINT ["/app/entrypoint.sh"]
