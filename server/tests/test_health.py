from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app import __version__
from app.core.config import Settings, get_settings
from app.db.migrate import head_revision
from app.db.session import build_engine, get_db
from app.main import create_app


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__
    assert body["environment"] == "test"
    assert body["components"]["database"] == {"status": "ok", "detail": None}
    assert body["components"]["schema"] == {"status": "ok", "detail": head_revision()}
    assert datetime.fromisoformat(body["timestamp"].replace("Z", "+00:00")).tzinfo is not None


def test_health_degraded_when_schema_not_migrated(settings: Settings) -> None:
    engine = build_engine(settings.database_url.replace("test.db", "unmigrated.db"))
    factory = sessionmaker(bind=engine)

    def _db() -> Iterator[Session]:
        with factory() as session:
            yield session

    app = create_app(settings)
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app) as client:
        response = client.get("/health")
    engine.dispose()

    assert response.status_code == 503
    schema = response.json()["components"]["schema"]
    assert schema["status"] == "error"
    assert "app.db.migrate" in schema["detail"]


def test_health_reports_degraded_when_database_fails(client: TestClient) -> None:
    class BrokenSession:
        def execute(self, *_args: object, **_kwargs: object) -> None:
            raise OperationalError("SELECT 1", {}, Exception("disk I/O error"))

    def _broken_db() -> Iterator[BrokenSession]:
        yield BrokenSession()

    client.app.dependency_overrides[get_db] = _broken_db  # type: ignore[attr-defined]
    response = client.get("/health")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["components"]["database"]["status"] == "error"
    # Internal exception text must not leak to clients.
    assert "disk I/O" not in response.text


def test_request_id_is_generated_and_echoed(client: TestClient) -> None:
    generated = client.get("/health").headers["X-Request-ID"]
    assert len(generated) == 32

    echoed = client.get("/health", headers={"X-Request-ID": "trace-123"}).headers["X-Request-ID"]
    assert echoed == "trace-123"


def test_unsafe_request_id_is_replaced(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "bad\nvalue" + "x" * 100})
    assert response.headers["X-Request-ID"] != "bad\nvalue" + "x" * 100
