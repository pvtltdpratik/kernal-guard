from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def make(**overrides: object) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def test_defaults_bind_to_loopback() -> None:
    settings = make()
    assert settings.host == "127.0.0.1"
    assert settings.allow_remote_bind is False


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_hosts_accepted(host: str) -> None:
    assert make(host=host).host == host


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "kernelguard.example"])
def test_non_loopback_host_rejected_without_opt_in(host: str) -> None:
    with pytest.raises(ValidationError, match="non-loopback"):
        make(host=host)


def test_non_loopback_host_allowed_with_explicit_opt_in() -> None:
    assert make(host="0.0.0.0", allow_remote_bind=True).host == "0.0.0.0"


def test_cors_origins_parsed_from_comma_separated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KG_CORS_ORIGINS", "http://localhost:3000, http://127.0.0.1:5173")
    assert make().cors_origins == ["http://localhost:3000", "http://127.0.0.1:5173"]


def test_wildcard_cors_origin_rejected() -> None:
    with pytest.raises(ValidationError, match="Wildcard"):
        make(cors_origins=["*"])


def test_sqlite_path_derived_from_url(tmp_path) -> None:  # type: ignore[no-untyped-def]
    db = tmp_path / "kg.db"
    assert make(database_url=f"sqlite:///{db.as_posix()}").sqlite_path == db
    assert make(database_url="sqlite:///:memory:").sqlite_path is None
