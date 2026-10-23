"""Application settings loaded from environment variables and an optional .env file.

All settings use the ``KG_`` prefix, e.g. ``KG_PORT=8000``.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

SERVER_ROOT = Path(__file__).resolve().parents[2]

LOOPBACK_HOSTNAMES = {"localhost"}


def _is_loopback(host: str) -> bool:
    if host.lower() in LOOPBACK_HOSTNAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="KG_",
        env_file=SERVER_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"

    # Network binding. Remote binding is refused unless explicitly allowed,
    # because the API has no authentication yet (see docs/security.md).
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    allow_remote_bind: bool = False

    # Comma-separated in the environment: KG_CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
    # NoDecode: skip pydantic-settings' JSON parsing so _split_csv sees the raw string.
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    database_url: str = f"sqlite:///{(SERVER_ROOT / 'data' / 'kernelguard.db').as_posix()}"

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_json: bool = True

    # Collector
    # Stable host identifier; defaults to the Windows MachineGuid (see app.collectors.host).
    host_id: str | None = None
    collector_interval_seconds: int = Field(default=10, ge=1, le=3600)
    collector_batch_size: int = Field(default=200, ge=1, le=1000)
    # Upper bound per channel per cycle so one busy channel cannot starve others.
    collector_max_batches_per_cycle: int = Field(default=10, ge=1, le=1000)
    # On first run: read the channel's retained history (True) or start at its newest record.
    collector_read_history: bool = True
    # Comma-separated sensor names to run; see app.collectors.registry.
    collector_sensors: Annotated[list[str], NoDecode] = ["sysmon", "system", "security"]

    # Limits protecting the pipeline against oversized or hostile records.
    max_event_xml_bytes: int = Field(default=256 * 1024, ge=4096)
    max_field_chars: int = Field(default=8192, ge=256)
    store_raw_xml: bool = True

    # Detection: optional JSON with rule overrides and allowlists.
    detection_config: Path | None = SERVER_ROOT / "config" / "detection" / "detection.json"
    detection_enabled: bool = True

    # Retention: events older than this, or beyond the row cap, are purged.
    # Measured ~4.7 KB/event including raw XML, so 500k rows is roughly 2.3 GB.
    event_retention_days: int = Field(default=30, ge=1)
    event_max_rows: int = Field(default=500_000, ge=1000)

    @field_validator("cors_origins", "collector_sensors", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip().startswith("["):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("cors_origins")
    @classmethod
    def _reject_wildcard_origin(cls, value: list[str]) -> list[str]:
        if "*" in value:
            raise ValueError("Wildcard CORS origin is not permitted; list approved origins explicitly")
        return value

    @model_validator(mode="after")
    def _enforce_local_binding(self) -> Settings:
        if not _is_loopback(self.host) and not self.allow_remote_bind:
            raise ValueError(
                f"Refusing to bind to non-loopback host {self.host!r}. The API has no authentication "
                "yet; set KG_ALLOW_REMOTE_BIND=true only after adding auth and TLS."
            )
        return self

    @property
    def sqlite_path(self) -> Path | None:
        prefix = "sqlite:///"
        if self.database_url.startswith(prefix) and ":memory:" not in self.database_url:
            return Path(self.database_url[len(prefix):])
        return None


@lru_cache
def get_settings() -> Settings:
    return Settings()
