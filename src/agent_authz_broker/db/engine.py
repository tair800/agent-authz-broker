"""Turning a configured DSN into one SQLAlchemy asyncpg can connect with.

The normalisation is not hypothetical tidiness: a managed provider issues a URL ending
``?sslmode=require&channel_binding=require``, and pasted in verbatim it produces a service that
reports itself healthy and cannot serve a request. `asyncpg.connect` parses a URL itself and
understands ``sslmode``; SQLAlchemy's asyncpg dialect splits the query string into keyword arguments
and calls a function whose signature has no place to put them.

Unrecognised parameters are kept, not dropped. Silently discarding a future provider's required
option would fail with no error at all, which is worse than the failure this fixes.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from agent_authz_broker.config import Settings

__all__ = ["async_dsn", "build_engine"]

_TLS_MODES: Final = frozenset({"require", "verify-ca", "verify-full"})

#: asyncpg negotiates SCRAM channel binding itself and has no connect argument for it, so
#: forwarding the parameter is a guaranteed TypeError.
_UNSUPPORTED: Final = frozenset({"channel_binding"})

#: A pooled endpoint runs pgBouncer in transaction mode, which does not keep a prepared statement
#: across checkouts. Caching them there produces intermittent errors under load and nowhere else.
_POOLED_MARKER: Final = "-pooler."


def async_dsn(settings: Settings) -> str:
    """The DSN with the asyncpg driver and a query string asyncpg can accept."""
    raw = settings.postgres_dsn.get_secret_value()
    parts = urlsplit(raw)
    scheme = "postgresql+asyncpg" if "+" not in parts.scheme else parts.scheme
    return urlunsplit(
        (scheme, parts.netloc, parts.path, _normalise(parts.query, host=parts.hostname or ""), "")
    )


def _normalise(query: str, *, host: str) -> str:
    out: list[tuple[str, str]] = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key in _UNSUPPORTED:
            continue
        if key == "sslmode":
            if value in _TLS_MODES:
                out.append(("ssl", "require"))
            continue
        out.append((key, value))
    if _POOLED_MARKER in host and not any(k == "prepared_statement_cache_size" for k, _ in out):
        out.append(("prepared_statement_cache_size", "0"))
    return urlencode(out)


def build_engine(settings: Settings) -> AsyncEngine:
    """One engine per process.

    ``pool_pre_ping`` because a free-tier database suspends when idle and hands back a connection
    that looks alive and is not.
    """
    return create_async_engine(async_dsn(settings), pool_pre_ping=True, future=True)
