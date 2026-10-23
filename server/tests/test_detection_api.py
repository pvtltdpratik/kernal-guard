"""API tests for alerts, incidents, processes, metrics and the detection catalog."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.base import ChannelUnavailableError
from app.collectors.registry import SENSORS
from app.collectors.sysmon import SYSMON_CHANNEL
from app.services.ingestion import IngestionService
from tests.detection_harness import Harness, at
from tests.helpers import (
    GUID_A,
    GUID_PARENT,
    TEMP_EXE,
    FakeEventLogReader,
    load_fixture,
    network,
    proc_create,
    registry_set,
)

RUN_KEY = r"HKU\S-1-5-21-1000\Software\Microsoft\Windows\CurrentVersion\Run\X"


@pytest.fixture
def seeded(session_factory: sessionmaker[Session]) -> Harness:
    h = Harness(session_factory)
    h.run(
        (proc_create(), at(0)),
        (registry_set(RUN_KEY, TEMP_EXE), at(5)),
        (network(), at(10)),
    )
    return h


def ok(response):  # type: ignore[no-untyped-def]
    assert response.status_code == 200, response.text
    return response.json()


# ------------------------------------------------------------------- alerts


def test_list_alerts_default_sort_and_filters(client: TestClient, seeded: Harness) -> None:
    body = ok(client.get("/api/v1/alerts"))
    assert body["total"] == 4  # EXEC-001, PERSIST-001, NET-001, SPY-002
    last_seen = [a["last_seen"] for a in body["items"]]
    assert last_seen == sorted(last_seen, reverse=True)

    assert ok(client.get("/api/v1/alerts", params={"severity": "high"}))["total"] == 2
    assert ok(client.get("/api/v1/alerts", params={"rule_id": "KG-NET-001"}))["total"] == 1
    assert ok(client.get("/api/v1/alerts", params={"q": "RUN KEY"}))["total"] == 1
    assert ok(client.get("/api/v1/alerts", params={"min_score": 70}))["total"] == 1
    assert ok(client.get("/api/v1/alerts", params={"status": ["reviewed", "false_positive"]}))["total"] == 0

    by_score = [a["risk_score"] for a in ok(client.get("/api/v1/alerts", params={"sort": "-risk_score"}))["items"]]
    assert by_score == sorted(by_score, reverse=True)


@pytest.mark.parametrize(
    "params",
    [{"status": "deleted"}, {"severity": "extreme"}, {"page_size": 201}, {"sort": "title"},
     {"min_score": 101}, {"incident_id": "nope"}, {"since": "2026-10-20T00:00:00"}],
)
def test_list_alerts_validation(client: TestClient, params: dict) -> None:  # type: ignore[type-arg]
    response = client.get("/api/v1/alerts", params=params)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_alert_detail_explains_itself(client: TestClient, seeded: Harness) -> None:
    alert_id = ok(client.get("/api/v1/alerts", params={"rule_id": "KG-PERSIST-001"}))["items"][0]["id"]
    detail = ok(client.get(f"/api/v1/alerts/{alert_id}"))

    assert detail["rule"]["rule_id"] == "KG-PERSIST-001"
    assert detail["rule"]["false_positives"] and detail["rule"]["rationale"]
    assert detail["mitre"][0] == {"technique_id": "T1547.001", "name": "Registry Run Keys / Startup Folder",
                                  "tactic": "Persistence", "relationship": "observed"}
    observed = [o for o in detail["observations"] if o["kind"] == "observed"]
    assert observed and observed[0]["event_id"] == detail["evidence"][0]["id"]
    assert detail["score_breakdown"][-1]["factor"] == "total"
    assert detail["evidence_missing"] == 0
    assert detail["history"] == []


def test_patch_alert_false_positive_rescores_incident(client: TestClient, seeded: Harness) -> None:
    alerts = ok(client.get("/api/v1/alerts", params={"sort": "-risk_score"}))["items"]
    top = alerts[0]
    incident_before = ok(client.get(f"/api/v1/incidents/{top['incident_id']}"))

    detail = ok(client.patch(f"/api/v1/alerts/{top['id']}", json={"status": "false_positive", "note": "Known updater"}))
    assert detail["status"] == "false_positive"
    assert [h["action"] for h in detail["history"]] == ["status_change", "note"]
    assert detail["history"][0] == {**detail["history"][0], "from_status": "new", "to_status": "false_positive", "actor": "local"}

    incident_after = ok(client.get(f"/api/v1/incidents/{top['incident_id']}"))
    assert incident_after["risk_score"] < incident_before["risk_score"]
    assert any("false positive" in u for u in incident_after["uncertainty"])
    excluded = [b for b in incident_after["score_breakdown"] if b["alert_id"] == top["id"]]
    assert excluded[0]["contribution"] == 0


@pytest.mark.parametrize(
    "body", [{}, {"status": "deleted"}, {"note": ""}, {"status": "reviewed", "assignee": "x"}, {"note": "x" * 4001}]
)
def test_patch_alert_validation(client: TestClient, seeded: Harness, body: dict) -> None:  # type: ignore[type-arg]
    alert_id = ok(client.get("/api/v1/alerts"))["items"][0]["id"]
    response = client.patch(f"/api/v1/alerts/{alert_id}", json=body)
    assert response.status_code == 422, response.text


def test_alert_not_found(client: TestClient) -> None:
    assert client.get("/api/v1/alerts/" + "0" * 32).status_code == 404
    assert client.patch("/api/v1/alerts/" + "0" * 32, json={"status": "reviewed"}).status_code == 404


# ---------------------------------------------------------------- incidents


def test_incident_detail_timeline(client: TestClient, seeded: Harness) -> None:
    [incident] = ok(client.get("/api/v1/incidents"))["items"]
    assert incident["alert_count"] == 4
    detail = ok(client.get(f"/api/v1/incidents/{incident['id']}"))

    stamps = [t["timestamp"] for t in detail["timeline"]]
    assert stamps == sorted(stamps)
    assert {t["kind"] for t in detail["timeline"]} == {"event", "alert"}
    assert {r["rule_id"] for r in detail["rules_fired"]} == {"KG-EXEC-001", "KG-PERSIST-001", "KG-NET-001", "KG-SPY-002"}
    assert any("not proof of malware" in u for u in detail["uncertainty"])
    assert detail["score_breakdown"][0]["reason"] == "highest-scoring rule"


def test_patch_incident_status_and_note(client: TestClient, seeded: Harness) -> None:
    incident_id = ok(client.get("/api/v1/incidents"))["items"][0]["id"]
    detail = ok(client.patch(f"/api/v1/incidents/{incident_id}", json={"status": "investigating", "note": "Looking"}))
    assert detail["status"] == "investigating"
    assert [h["action"] for h in detail["history"]] == ["status_change", "note"]
    assert ok(client.get("/api/v1/incidents", params={"status": "open"}))["total"] == 0
    assert client.patch(f"/api/v1/incidents/{incident_id}", json={"status": "resolved"}).status_code == 422


# ---------------------------------------------------------------- processes


def test_process_investigation(client: TestClient, seeded: Harness) -> None:
    [summary] = ok(client.get("/api/v1/processes", params={"process_guid": GUID_A}))["items"]
    detail = ok(client.get(f"/api/v1/processes/{summary['id']}"))

    assert detail["image"] == TEMP_EXE and detail["creation_observed"] is True
    assert detail["parent"]["process_guid"] == GUID_PARENT
    assert detail["event_counts"] == {"process_creation": 1, "registry_value_set": 1, "network_connection": 1}
    assert detail["network"][0]["destination_ip"] == "93.184.215.14" and detail["network"][0]["connections"] == 1
    assert {a["rule_id"] for a in detail["alerts"]} >= {"KG-EXEC-001", "KG-PERSIST-001", "KG-NET-001"}

    parent = ok(client.get(f"/api/v1/processes/{detail['parent']['id']}"))
    assert [c["process_guid"] for c in parent["children"]] == [GUID_A]


def test_process_list_filters(client: TestClient, seeded: Harness) -> None:
    assert ok(client.get("/api/v1/processes", params={"image": "UPDATER"}))["total"] == 1
    assert client.get("/api/v1/processes", params={"process_id": -5}).status_code == 422
    assert client.get("/api/v1/processes/" + "f" * 32).status_code == 404


# -------------------------------------------------------- metrics & catalog


def test_metrics_overview(client: TestClient, seeded: Harness) -> None:
    body = ok(client.get("/api/v1/metrics/overview", params={"window": "7d"}))
    assert body["total_events"] == 3
    assert body["active_alerts"] == 4
    severities = {s["severity"]: s["count"] for s in body["alerts_by_severity"]}
    assert sum(severities.values()) == 4 and severities["high"] == 2
    assert body["open_incidents"] == 1 and body["recent_incidents"][0]["alert_count"] == 4
    assert body["event_volume_bucket"] == "day" and len(body["event_volume"]) in (7, 8)
    assert {s["sensor"] for s in body["sensors"]} == set(SENSORS)
    assert client.get("/api/v1/metrics/overview", params={"window": "1y"}).status_code == 422


def test_rules_catalog(client: TestClient) -> None:
    rules = ok(client.get("/api/v1/detection/rules"))
    assert len(rules) == 16
    spy = next(r for r in rules if r["rule_id"] == "KG-SPY-002")
    assert spy["kind"] == "correlation" and spy["thresholds"] == {"min_categories": 3}


def test_capabilities_reflect_sensor_health(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader(errors={SYSMON_CHANNEL: ChannelUnavailableError(SYSMON_CHANNEL)})
    reader.add("System", load_fixture("system_7045_service_install.xml"), 1)
    service = IngestionService(reader, session_factory, host_id="host-1")
    service.ingest(SENSORS["sysmon"])
    service.ingest(SENSORS["system"])

    caps = ok(client.get("/api/v1/detection/capabilities"))
    by_name = {c["technique"]: c for c in caps}
    lsass = by_name["LSASS memory access"]
    assert (lsass["design_visibility"], lsass["effective_visibility"]) == ("observable", "not_observable")
    assert lsass["effective_note"] == "No telemetry on this host (sysmon: unavailable)."
    service_cap = by_name["Windows service creation"]
    assert service_cap["effective_visibility"] == "observable"
    log_clear = by_name["Clear Windows event logs"]  # system OK, security never polled
    assert log_clear["effective_visibility"] == "observable"
    assert log_clear["effective_note"] == "Reduced coverage (security: never run)."
    assert by_name["Keylogging via GetAsyncKeyState / GetKeyboardState polling"]["effective_visibility"] == "not_observable"
