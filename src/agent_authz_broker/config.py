"""Typed configuration. Every value arrives from the environment; none is invented here."""

from __future__ import annotations

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["Settings"]


class Settings(BaseSettings):
    """What the service needs to start.

    ``extra="forbid"`` so a misspelled variable fails at startup rather than being ignored — the
    failure mode where a setting looks configured and is not. That matters more here than usual:
    a mistyped ``AAB_RESOURCE_SERVER_URL`` would leave the server enforcing an audience nobody
    mints tokens for, which fails closed but looks like a broken deployment rather than a typo.
    """

    model_config = SettingsConfigDict(
        env_prefix="AAB_", env_file=".env", extra="forbid", case_sensitive=False
    )

    environment: str = Field(default="local", pattern="^(local|ci|staging|production)$")

    postgres_dsn: SecretStr = Field(
        default=SecretStr("postgresql://aab:aab_local_dev@localhost:15434/aab"),
        description="PostgreSQL DSN. A secret because it carries a password.",
    )

    resource_server_url: str = Field(
        default="http://localhost:8000/mcp",
        description=(
            "This server's own identity. THE audience value every token must name. It is "
            "configuration rather than a constant because the same code must refuse a token minted "
            "for the deployed URL when running locally, and vice versa."
        ),
    )

    #: Fail-closed. An empty list means no browser origin may call the API directly.
    cors_allow_origins: list[str] = Field(default_factory=list)

    admin_reset_token: SecretStr | None = Field(
        default=None,
        description=(
            "Bearer token for the demo reset endpoint. Unset disables reset entirely. This is "
            "admin infrastructure and is deliberately NOT an MCP tool: see ADR-001."
        ),
    )
