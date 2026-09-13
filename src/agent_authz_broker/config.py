"""Typed configuration. Every value arrives from the environment; none is invented here."""

from __future__ import annotations

from pydantic import Field, SecretStr, field_validator
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

    approver_token: SecretStr | None = Field(
        default=None,
        description=(
            "Bearer token a human presents to grant an approval. Unset disables POST "
            "/api/v1/approvals entirely. It is NOT an MCP credential and the test authority does "
            "not mint it: an agent holding a perfectly valid, correctly attenuated token must not "
            "be able to approve its own irreversible action."
        ),
    )

    @field_validator("admin_reset_token", "approver_token", mode="after")
    @classmethod
    def _blank_is_unset(cls, value: SecretStr | None) -> SecretStr | None:
        """An empty value disables the gate rather than arming it with the empty string.

        ``AAB_APPROVER_TOKEN=`` in a shell, a Makefile forwarding an unset variable, or a dashboard
        field somebody cleared all arrive here as ``""``. Armed with that, the route answers 401 to
        everything and looks configured. Unset is the honest reading and it is also the safe one:
        the route becomes unavailable, which is what both of these credentials mean by absent.
        """
        if value is None or not value.get_secret_value().strip():
            return None
        return value
