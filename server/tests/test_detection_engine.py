"""Engine behaviour: process tracking, dedup, correlation, scoring, failure isolation."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.registry import SENSORS
from app.collectors.sysmon import SYSMON_CHANNEL
from app.db.models import Alert, AlertEvidence, Event, Incident
from app.detection.config import Allowlist, DetectionConfig
from app.detection.engine import DetectionEngine
from app.detection.scoring import score_alert, score_incident
from app.detection.types import Confidence, Severity
from app.services.ingestion import IngestionService
from tests.detection_harness import Harness, at
from tests.helpers import (
    GUID_A,
    GUID_B,
    GUID_PARENT,
    TEMP_EXE,
    FakeEventLogReader,
    build_event,
    load_fixture,
    network,
    proc_create,
    registry_set,
)

RUN_KEY = r"HKU\S-1-5-21-1000\Software\Microsoft\Windows\CurrentVersion\Run\X"


@pytest.fixture
def h(session_factory: sessionmaker[Session]) -> Harness:
    return Harness(session_factory)


# --------------------------------------------------------- process tracking


def test_creation_event_builds_process_and_parent(h: Harness) -> None:
    h.run(proc_create(sha="ignored"))
    processes = {p.process_guid: p for p in h.processes()}
    child, parent = processes[GUID_A], processes[GUID_PARENT]
    assert child.creation_observed and child.start_time is not None
    assert child.parent_process_guid == GUID_PARENT
    assert child.command_line == f'"{TEMP_EXE}"'
    assert parent.image == r"C:\Windows\explorer.exe"
    assert parent.creation_observed is False and parent.start_time is None  # never guessed


def test_pid_reuse_creates_distinct_processes(h: Harness) -> None:
    h.run(
        (proc_create(guid=GUID_A, pid=4242, image=r"C:\Windows\a.exe"), at(0)),
        (build_event(5, {"ProcessGuid": GUID_A, "ProcessId": "4242", "Image": r"C:\Windows\a.exe"}), at(5)),
        (proc_create(guid=GUID_B, pid=4242, image=r"C:\Windows\b.exe"), at(10)),
    )
    reused = [p for p in h.processes() if p.process_id == 4242]
    assert len(reused) == 2
    first = next(p for p in reused if p.process_guid == GUID_A)
    assert first.end_time == at(5)


def test_out_of_order_network_before_creation(h: Harness) -> None:
    h.run((network(), at(10)))
    [early] = [p for p in h.processes() if p.process_guid == GUID_A]
    assert early.creation_observed is False and early.start_time is None

    h.run((proc_create(), at(1)))
    [process] = [p for p in h.processes() if p.process_guid == GUID_A]
    assert process.creation_observed is True
    assert process.start_time == at(1)
    assert process.first_seen == at(1) and process.last_seen == at(10)


def test_conflicting_image_is_recorded_not_overwritten(h: Harness) -> None:
    h.run((proc_create(image=TEMP_EXE), at(0)), (network(image=r"C:\Other\renamed.exe"), at(5)))
    [process] = [p for p in h.processes() if p.process_guid == GUID_A]
    assert process.image == TEMP_EXE
    assert process.conflicts[0]["field"] == "image"
    assert process.conflicts[0]["observed"] == r"C:\Other\renamed.exe"


def test_security_4688_process_keyed_by_pid_and_time(h: Harness) -> None:
    h.run(load_fixture("security_4688_process_create.xml"), channel="Security")
    [process] = [p for p in h.processes() if p.key.startswith("pid:")]
    assert process.process_id == 0x1D08 and process.process_guid is None


# ------------------------------------------------------- dedup & idempotence


def test_repeat_events_increment_occurrences_not_alerts(h: Harness) -> None:
    h.run((registry_set(RUN_KEY, TEMP_EXE), at(0)))
    h.run((registry_set(RUN_KEY, TEMP_EXE), at(30)))
    [alert] = h.alerts("KG-PERSIST-001")
    assert alert.occurrence_count == 2
    assert alert.first_seen == at(0) and alert.last_seen == at(30)


def test_rescan_is_idempotent(h: Harness, session_factory: sessionmaker[Session]) -> None:
    h.run((proc_create(), at(0)), (registry_set(RUN_KEY, TEMP_EXE), at(5)), (network(), at(10)))
    before = {(a.rule_id, a.occurrence_count, a.risk_score) for a in h.alerts()}
    incidents_before = [(i.id, i.risk_score) for i in h.incidents()]

    with session_factory() as session, session.begin():
        events = list(session.scalars(select(Event).order_by(Event.timestamp)))
        result = DetectionEngine().process(session, events)

    assert result.alerts_created == 0 and result.alerts_updated == 0
    assert {(a.rule_id, a.occurrence_count, a.risk_score) for a in h.alerts()} == before
    assert [(i.id, i.risk_score) for i in h.incidents()] == incidents_before


def test_evidence_links_are_capped(session_factory: sessionmaker[Session]) -> None:
    h = Harness(session_factory, config=DetectionConfig(max_evidence_per_alert=3))
    h.run(*[(registry_set(RUN_KEY, TEMP_EXE), at(i)) for i in range(6)])
    [alert] = h.alerts("KG-PERSIST-001")
    with session_factory() as session:
        links = session.scalars(select(AlertEvidence).where(AlertEvidence.alert_id == alert.id)).all()
    assert len(links) == 3
    assert alert.occurrence_count == 6


def test_allowlisted_image_is_suppressed(session_factory: sessionmaker[Session]) -> None:
    h = Harness(session_factory, config=DetectionConfig(allowlist=Allowlist(images=[TEMP_EXE.upper()])))
    h.run(proc_create(), network())
    assert h.alerts() == []


# --------------------------------------------------------------- correlation


def test_related_alerts_share_one_incident(h: Harness) -> None:
    h.run((proc_create(), at(0)), (registry_set(RUN_KEY, TEMP_EXE), at(5)))
    [incident] = h.incidents()
    assert all(a.incident_id == incident.id for a in h.alerts())
    assert f"process:guid:host-1:{GUID_A.lower()}" in incident.entities


def test_child_alert_joins_parent_incident_via_parent_entity(h: Harness) -> None:
    h.run((proc_create(guid=GUID_A), at(0)))
    h.run((proc_create(guid=GUID_B, parent_guid=GUID_A, image=r"C:\Users\Public\child.exe"), at(5)))
    assert len(h.incidents()) == 1


def test_unrelated_processes_get_separate_incidents(h: Harness) -> None:
    h.run((proc_create(guid=GUID_A, parent_guid="{11111111-0000-0000-0000-000000000001}"), at(0)),
          (proc_create(guid=GUID_B, parent_guid="{22222222-0000-0000-0000-000000000002}",
                       image=r"C:\Users\Public\other.exe"), at(5)))
    assert len(h.incidents()) == 2


def test_alerts_outside_window_start_new_incident(h: Harness) -> None:
    h.run((proc_create(), at(0)))
    h.run((registry_set(RUN_KEY, TEMP_EXE), at(0) + timedelta(hours=3)))
    assert len(h.incidents()) == 2


def test_closed_incident_is_not_reused(h: Harness, session_factory: sessionmaker[Session]) -> None:
    h.run((proc_create(), at(0)))
    with session_factory() as session, session.begin():
        session.scalars(select(Incident)).one().status = "closed"
    h.run((registry_set(RUN_KEY, TEMP_EXE), at(10)))
    assert len(h.incidents()) == 2


# ------------------------------------------------------------------- scoring


def test_alert_score_breakdown() -> None:
    score, breakdown = score_alert(Severity.HIGH, Confidence.MEDIUM, [("reason", 20)])
    assert score == round((75 + 20) * 0.8) == 76
    assert [b["factor"] for b in breakdown] == ["severity", "adjustment", "confidence", "total"]


def test_alert_score_is_capped() -> None:
    score, breakdown = score_alert(Severity.CRITICAL, Confidence.HIGH, [("a", 25), ("b", 25)])
    assert score == 100 and breakdown[-1]["capped"] is True


def _alert(rule: str, score: int, severity: str = "medium", status: str = "new") -> Alert:
    return Alert(id=f"{rule}-{score}", rule_id=rule, risk_score=score, severity=severity, status=status)


def test_incident_counts_each_rule_once_and_excludes_false_positives() -> None:
    score, severity, breakdown = score_incident([
        _alert("R1", 60, "high"),
        _alert("R1", 40),             # same rule: not independent evidence
        _alert("R2", 50),
        _alert("R3", 90, "critical", status="false_positive"),
    ])
    assert score == round(60 + 0.2 * 50) == 70
    assert severity == Severity.HIGH
    reasons = {b["alert_id"]: b["reason"] for b in breakdown}
    assert reasons["R1-40"].startswith("same rule")
    assert reasons["R3-90"].startswith("excluded")


def test_incident_with_only_false_positives_scores_zero() -> None:
    score, severity, _ = score_incident([_alert("R1", 80, "high", status="false_positive")])
    assert (score, severity) == (0, Severity.INFORMATIONAL)


# --------------------------------------------------------- failure isolation


def test_detection_failure_keeps_events_and_is_reported(session_factory: sessionmaker[Session]) -> None:
    class Exploding:
        def process_event_ids(self, session, event_ids):  # type: ignore[no-untyped-def]
            session.add(Alert(id="x"))  # partial write that must be rolled back
            raise RuntimeError("engine bug")

    reader = FakeEventLogReader()
    reader.add(SYSMON_CHANNEL, load_fixture("sysmon_1_process_create.xml"), 1)
    service = IngestionService(reader, session_factory, host_id="host-1", processor=Exploding())
    result = service.ingest(SENSORS["sysmon"])

    assert (result.state, result.inserted, result.detection_failures) == ("ok", 1, 1)
    with session_factory() as session:
        assert session.scalar(select(Event.id)) is not None
        assert session.scalar(select(Alert.id)) is None
        from app.db.models import SensorHealth

        health = session.get(SensorHealth, "sysmon")
        assert health is not None and health.detection_failures == 1
        assert "rescan" in (health.detail or "")


def test_rule_exception_is_contained(h: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.detection.rules.executable import ProcessFromUserWritablePath

    def boom(self, event, ctx):  # type: ignore[no-untyped-def]
        raise ValueError("rule bug")

    monkeypatch.setattr(ProcessFromUserWritablePath, "evaluate", boom)
    h.run(proc_create(), network())
    assert h.rule_ids() == {"KG-NET-001"}  # other rules still ran
