"""Alembic environment.

The DSN comes from `Settings`, never from `alembic.ini`, so there is exactly one place a database
address is configured and no second copy to fall out of date. `alembic.ini` leaves it blank
deliberately — a value there would be a committed connection string.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import AsyncEngine

from agent_authz_broker.config import Settings
from agent_authz_broker.db.engine import build_engine
from agent_authz_broker.db.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _run(connection: object) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)  # type: ignore[arg-type]
    with context.begin_transaction():
        context.run_migrations()


async def _online() -> None:
    engine: AsyncEngine = build_engine(Settings())
    async with engine.connect() as connection:
        await connection.run_sync(_run)
        await connection.commit()
    await engine.dispose()


def run_offline() -> None:
    context.configure(
        url=Settings().postgres_dsn.get_secret_value(), target_metadata=target_metadata
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_offline()
else:
    asyncio.run(_online())
