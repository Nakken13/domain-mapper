"""Runtime settings loaded from environment variables and an optional `.env` file.

API keys are stored as `SecretStr`: they never show up in `repr()`, logs or
`model_dump()`, and must be read explicitly with `get_secret_value()`.
"""

from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """domain-mapper settings. Every variable is prefixed with `DOMAIN_MAPPER_`."""

    model_config = SettingsConfigDict(
        env_prefix="DOMAIN_MAPPER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    shodan_api_key: SecretStr | None = None
    censys_api_id: SecretStr | None = None
    censys_api_secret: SecretStr | None = None
    cache_dir: Path = Path(".cache")

    @field_validator("shodan_api_key", "censys_api_id", "censys_api_secret", mode="before")
    @classmethod
    def _empty_means_unset(cls, value: object) -> object:
        """`KEY=` in `.env` (as shipped in `.env.example`) must disable the source."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @property
    def shodan_enabled(self) -> bool:
        return self.shodan_api_key is not None

    @property
    def censys_enabled(self) -> bool:
        return self.censys_api_id is not None and self.censys_api_secret is not None
