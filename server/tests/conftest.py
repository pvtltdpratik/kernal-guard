from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.db.migrate import upgrade_to_head
from app.db.session import build_engine, get_db
from app.main import create_app


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]  # isolate tests from a developer's .env
        environment="test",
        database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
        log_json=False,
        log_level="WARNING",
    )


@pytest.fixture
def engine(settings: Settings) -> Iterator[Engine]:
    """A temporary database built by the real Alembic migrations."""
    engine = build_engine(settings.database_url)
    upgrade_to_head(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@pytest.fixture
def client(settings: Settings, session_factory: sessionmaker[Session]) -> Iterator[TestClient]:
    def _get_db() -> Iterator[Session]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app = create_app(settings)
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_db] = _get_db
    with TestClient(app) as test_client:
        yield test_client
