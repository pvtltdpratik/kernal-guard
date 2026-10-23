from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.registry import SENSORS
from app.collectors.sysmon import SYSMON_CHANNEL
from app.services.ingestion import IngestionService
from tests.helpers import BASE_TIME, FakeEventLogReader, load_fixture

SYSMON_FIXTURES = [
    "sysmon_1_process_create.xml",
    "sysmon_3_network.xml",
    "sysmon_6_driver_load.xml",
    "sysmon_7_image_load_unsigned.xml",
    "sysmon_8_remote_thread.xml",
    "sysmon_10_process_access.xml",
    "sysmon_11_file_create.xml",
    "sysmon_13_registry_set.xml",
]


@pytest.fixture
def seeded(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    for offset, name in enumerate(SYSMON_FIXTURES, start=1):
        reader.add(SYSMON_CHANNEL, load_fixture(name), offset)
    reader.add("System", load_fixture("system_7045_service_install.xml"), 500, BASE_TIME + timedelta(hours=2))
    service = IngestionService(reader, session_factory, host_id="host-1")
    service.ingest(SENSORS["sysmon"])
    service.ingest(SENSORS["system"])


def items(response) -> list[dict]:  # type: ignore[no-untyped-def,type-arg]
    assert response.status_code == 200, response.text
    return response.json()["items"]


def test_list_defaults_newest_first(client: TestClient, seeded: None) -> None:
    body = client.get("/api/v1/events").json()
    assert body["total"] == 9
    assert (body["page"], body["page_size"]) == (1, 50)
    timestamps = [item["timestamp"] for item in body["items"]]
    assert timestamps == sorted(timestamps, reverse=True)
    assert "raw_xml" not in body["items"][0]  # summaries never carry raw XML


def test_pagination_is_stable_and_complete(client: TestClient, seeded: None) -> None:
    seen: list[str] = []
    for page in (1, 2, 3, 4, 5):
        seen += [i["id"] for i in items(client.get("/api/v1/events", params={"page": page, "page_size": 2}))]
    assert len(seen) == 9 == len(set(seen))
    assert items(client.get("/api/v1/events", params={"page": 99})) == []


def test_sort_ascending(client: TestClient, seeded: None) -> None:
    timestamps = [i["timestamp"] for i in items(client.get("/api/v1/events", params={"sort": "timestamp"}))]
    assert timestamps == sorted(timestamps)


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        ({"category": "process_creation"}, 1),
        ({"category": ["network_connection", "image_load"]}, 2),
        ({"source": "windows_eventlog"}, 1),
        ({"channel": "System"}, 1),
        ({"source_event_id": 10}, 1),
        ({"process_guid": "{3f1b2c4d-1a2b-6716-0b04-000000002b00}"}, 7),
        ({"process_id": 7432}, 7),
        ({"image": "UPDATER.EXE"}, 7),
        ({"image": "%"}, 0),  # LIKE wildcards are matched literally
        ({"host_id": "someone-else"}, 0),
        ({"since": "2026-10-20T09:15:05Z"}, 6),
        ({"since": "2026-10-20T09:15:05Z", "until": "2026-10-20T09:15:08Z"}, 3),  # until is exclusive
    ],
)
def test_filters(client: TestClient, seeded: None, params: dict, expected: int) -> None:  # type: ignore[type-arg]
    response = client.get("/api/v1/events", params=params)
    assert response.status_code == 200, response.text
    assert response.json()["total"] == expected


@pytest.mark.parametrize(
    "params",
    [
        {"page_size": 501},
        {"page": 0},
        {"sort": "image"},
        {"category": "keystrokes"},
        {"since": "2026-10-20T09:15:05"},  # naive datetime rejected
        {"process_id": -1},
        {"image": "x" * 261},
    ],
)
def test_invalid_query_returns_validation_error(client: TestClient, params: dict) -> None:  # type: ignore[type-arg]
    response = client.get("/api/v1/events", params=params)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_since_after_until_rejected(client: TestClient) -> None:
    response = client.get(
        "/api/v1/events", params={"since": "2026-10-21T00:00:00Z", "until": "2026-10-20T00:00:00Z"}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "bad_request"


def test_event_detail_and_raw_opt_in(client: TestClient, seeded: None) -> None:
    event_id = items(client.get("/api/v1/events", params={"source_event_id": 1}))[0]["id"]

    detail = client.get(f"/api/v1/events/{event_id}").json()
    assert detail["sha256"].startswith("3b4c5d6e")
    assert detail["data"]["CommandLine"].endswith("/silent")
    assert detail["parent_process_guid"] == "{3f1b2c4d-0e11-6716-5a03-000000002b00}"
    assert detail["raw_xml"] is None

    raw = client.get(f"/api/v1/events/{event_id}", params={"include_raw": "true"}).json()
    assert raw["raw_xml"].startswith("<Event")


def test_event_not_found(client: TestClient) -> None:
    response = client.get("/api/v1/events/" + "0" * 32)
    assert response.status_code == 404
    assert response.json()["error"] == {
        "code": "not_found",
        "message": "Event not found",
        "details": None,
        "request_id": response.headers["X-Request-ID"],
    }


@pytest.mark.parametrize("bad_id", ["not-an-id", "A" * 32, "1;DROP TABLE events"])
def test_event_id_validated(client: TestClient, bad_id: str) -> None:
    assert client.get(f"/api/v1/events/{bad_id}").status_code in (404, 422)
    assert client.get(f"/api/v1/events/{bad_id}").json()["error"]["code"] in ("validation_error", "not_found")
