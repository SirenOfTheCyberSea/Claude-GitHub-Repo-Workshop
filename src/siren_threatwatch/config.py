"""Application configuration loaded from environment variables and an optional `.env` file.

Secrets are held as :class:`pydantic.SecretStr` so they are never printed by ``repr`` or logs.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Hosts that connectors are permitted to contact. Anything else is refused (SSRF protection).
DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset(
    {
        "www.cisa.gov",
        "raw.githubusercontent.com",  # CISA's official mirror: github.com/cisagov/kev-data
    }
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SIREN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Storage
    database_url: str = "sqlite:///data/siren.db"
    data_dir: Path = Path("data")

    # Logging
    log_level: str = "INFO"
    log_json: bool = False

    # HTTP safety limits
    http_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    http_max_retries: int = Field(default=3, ge=0, le=10)
    http_max_response_mb: int = Field(default=50, ge=1, le=500)
    http_max_concurrency: int = Field(default=4, ge=1, le=32)
    http_max_redirects: int = Field(default=3, ge=0, le=10)

    # CISA KEV
    kev_enabled: bool = True
    kev_feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_mirror_url: str = (
        "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
    )

    # Scheduling
    schedule_interval_minutes: int = Field(default=360, ge=15, le=10080)

    # Prioritization & alerts
    org_relevant_keywords: Annotated[list[str], NoDecode] = Field(default_factory=list)
    alert_min_score: int = Field(default=60, ge=0, le=100)

    # Credentials for later-phase connectors. Read from un-prefixed env vars.
    nvd_api_key: SecretStr | None = Field(default=None, validation_alias=AliasChoices("NVD_API_KEY"))
    otx_api_key: SecretStr | None = Field(default=None, validation_alias=AliasChoices("OTX_API_KEY"))
    abusech_auth_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("ABUSECH_AUTH_KEY")
    )

    @field_validator("org_relevant_keywords", mode="before")
    @classmethod
    def _split_keywords(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip().lower() for part in value.split(",") if part.strip()]
        return value

    @field_validator("nvd_api_key", "otx_api_key", "abusech_auth_key", mode="before")
    @classmethod
    def _blank_is_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("kev_feed_url", "kev_mirror_url")
    @classmethod
    def _url_must_be_allowlisted(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https" or (parts.hostname or "") not in DEFAULT_ALLOWED_HOSTS:
            raise ValueError(f"URL host must be HTTPS and one of {sorted(DEFAULT_ALLOWED_HOSTS)}")
        return value

    @field_validator("log_level")
    @classmethod
    def _upper(cls, value: str) -> str:
        return value.upper()

    # Convenience paths -------------------------------------------------
    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def export_dir(self) -> Path:
        return self.data_dir / "exports"

    @property
    def max_response_bytes(self) -> int:
        return self.http_max_response_mb * 1024 * 1024

    def secret_values(self) -> list[str]:
        """Return configured secret values (used only by the log redaction filter)."""
        return [
            s.get_secret_value() for s in (self.nvd_api_key, self.otx_api_key, self.abusech_auth_key) if s
        ]

    def credential_status(self) -> dict[str, bool]:
        """Whether each credential is configured — never the value itself."""
        return {
            "NVD_API_KEY": self.nvd_api_key is not None,
            "OTX_API_KEY": self.otx_api_key is not None,
            "ABUSECH_AUTH_KEY": self.abusech_auth_key is not None,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
