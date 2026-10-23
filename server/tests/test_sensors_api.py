from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.base import ChannelAccessDeniedError, ChannelUnavailableError
from app.collectors.registry import SENSORS
from app.collectors.sysmon import SYSMON_CHANNEL
from app.services.ingestion import IngestionService
from tests.helpers import FakeEventLogReader, load_fixture


def by_name(client: TestClient) -> dict[str, dict]:  # type: ignore[type-arg]
    body = client.get("/api/v1/sensors/status").json()
    return {s["sensor"]: s for s in body["sensors"]}


def test_never_run_sensors_are_stale(client: TestClient) -> None:
    response = client.get("/api/v1/sensors/status")
    assert response.status_code == 200
    body = response.json()
    assert body["collector_stale"] is True
    assert {s["sensor"] for s in body["sensors"]} == set(SENSORS)
    assert all(s["state"] == "never_run" and s["stale"] for s in body["sensors"])


def test_reports_mixed_sensor_states(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader(
        errors={
            SYSMON_CHANNEL: ChannelUnavailableError(SYSMON_CHANNEL),
            "Security": ChannelAccessDeniedError("Security"),
        }
    )
    reader.add("System", load_fixture("system_7045_service_install.xml"), 1)
    service = IngestionService(reader, session_factory, host_id="host-1")
    for spec in SENSORS.values():
        service.ingest(spec)

    sensors = by_name(client)
    assert sensors["system"]["state"] == "ok"
    assert sensors["system"]["events_ingested"] == 1
    assert sensors["system"]["stale"] is False
    assert sensors["sysmon"]["state"] == "unavailable"
    assert "Sysmon" in sensors["sysmon"]["detail"]
    assert sensors["security"]["state"] == "access_denied"
    assert sensors["security"]["consecutive_failures"] == 1
    assert client.get("/api/v1/sensors/status").json()["collector_stale"] is False
