"""ORM models.

Telemetry (Phase 2): events, per-channel bookmarks, sensor health.
Detection (Phase 3): processes, rule catalog, alerts + evidence links,
incidents and investigation history.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UTCDateTime


def _uuid() -> str:
    return uuid.uuid4().hex


class Event(Base):
    """One normalised telemetry record. Optional fields stay NULL when the
    source did not provide them; nothing is inferred or filled in."""

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)

    # Provenance
    source: Mapped[str] = mapped_column(String(32))  # sysmon | windows_eventlog
    channel: Mapped[str] = mapped_column(String(128))
    provider: Mapped[str | None] = mapped_column(String(128))
    source_event_id: Mapped[int] = mapped_column(Integer)
    record_id: Mapped[int] = mapped_column(BigInteger)
    dedup_key: Mapped[str] = mapped_column(String(64), unique=True)

    # Time: when the activity happened (Sysmon UtcTime, else TimeCreated),
    # when Windows logged it, and when KernelGuard stored it.
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime())
    logged_at: Mapped[datetime] = mapped_column(UTCDateTime())
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime())

    # Host
    host_id: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str | None] = mapped_column(String(255))

    # Process identity. Sysmon ProcessGuid survives PID reuse; PID alone does not.
    process_guid: Mapped[str | None] = mapped_column(String(64))
    process_id: Mapped[int | None] = mapped_column(Integer)
    image: Mapped[str | None] = mapped_column(Text)
    parent_process_guid: Mapped[str | None] = mapped_column(String(64))
    parent_process_id: Mapped[int | None] = mapped_column(Integer)
    parent_image: Mapped[str | None] = mapped_column(Text)
    user: Mapped[str | None] = mapped_column(String(255))

    # File identity, only when the sensor reported it
    sha256: Mapped[str | None] = mapped_column(String(64))
    sha1: Mapped[str | None] = mapped_column(String(40))
    md5: Mapped[str | None] = mapped_column(String(32))
    imphash: Mapped[str | None] = mapped_column(String(32))
    signed: Mapped[bool | None] = mapped_column(Boolean)
    signature: Mapped[str | None] = mapped_column(String(255))
    signature_status: Mapped[str | None] = mapped_column(String(64))

    category: Mapped[str] = mapped_column(String(48))
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    # complete | partial (required fields missing) | truncated (values capped)
    collection_status: Mapped[str] = mapped_column(String(16))
    missing_fields: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Original event XML, size-capped. May contain sensitive command lines.
    raw_xml: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_category_timestamp", "category", "timestamp"),
        Index("ix_events_process_guid", "process_guid"),
        Index("ix_events_process_id", "process_id"),
        Index("ix_events_source_event_id", "source", "source_event_id"),
        Index("ix_events_ingested_at", "ingested_at"),
    )


class CollectorBookmark(Base):
    """Last EventRecordID durably stored for a channel."""

    __tablename__ = "collector_bookmarks"

    channel: Mapped[str] = mapped_column(String(128), primary_key=True)
    last_record_id: Mapped[int] = mapped_column(BigInteger, default=0)
    # TimeCreated of that record; used to detect a cleared log whose IDs restarted.
    last_logged_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())


class SensorHealth(Base):
    """Collector state per sensor/channel, written by the collector process
    and read by the API."""

    __tablename__ = "sensor_health"

    sensor: Mapped[str] = mapped_column(String(64), primary_key=True)
    channel: Mapped[str] = mapped_column(String(128))
    # ok | unavailable | access_denied | error | never_run
    state: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str | None] = mapped_column(Text)

    last_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_error_at: Mapped[datetime | None] = mapped_column(UTCDateTime())

    events_ingested: Mapped[int] = mapped_column(BigInteger, default=0)
    duplicates_skipped: Mapped[int] = mapped_column(BigInteger, default=0)
    parse_failures: Mapped[int] = mapped_column(BigInteger, default=0)
    records_ignored: Mapped[int] = mapped_column(BigInteger, default=0)
    # Records overwritten by log rotation before they could be read.
    records_missed: Mapped[int] = mapped_column(BigInteger, default=0)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    # Stored events the detection engine failed to evaluate (rescan needed).
    detection_failures: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")


class Process(Base):
    """One process instance, assembled from every event that mentions it.

    Identity (``key``):
    - ``guid:{host}:{ProcessGuid}`` when Sysmon supplied a GUID (PID-reuse safe);
    - ``pid:{host}:{pid}:{start}`` for Security 4688, where PID plus creation
      time distinguishes reused PIDs.

    Fields are filled from the first event that carries them and are never
    overwritten; disagreeing later values are recorded in ``conflicts``.
    """

    __tablename__ = "processes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    key: Mapped[str] = mapped_column(String(160), unique=True)
    host_id: Mapped[str] = mapped_column(String(64))
    process_guid: Mapped[str | None] = mapped_column(String(64))
    process_id: Mapped[int | None] = mapped_column(Integer)
    image: Mapped[str | None] = mapped_column(Text)
    command_line: Mapped[str | None] = mapped_column(Text)
    user: Mapped[str | None] = mapped_column(String(255))
    integrity_level: Mapped[str | None] = mapped_column(String(32))
    parent_process_guid: Mapped[str | None] = mapped_column(String(64))
    parent_process_id: Mapped[int | None] = mapped_column(Integer)
    parent_image: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64))
    sha1: Mapped[str | None] = mapped_column(String(40))
    md5: Mapped[str | None] = mapped_column(String(32))
    imphash: Mapped[str | None] = mapped_column(String(32))
    # NULL start_time means the creation event was not observed.
    start_time: Mapped[datetime | None] = mapped_column(UTCDateTime())
    end_time: Mapped[datetime | None] = mapped_column(UTCDateTime())
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    creation_observed: Mapped[bool] = mapped_column(Boolean, default=False)
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    conflicts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    __table_args__ = (
        Index("ix_processes_host_guid", "host_id", "process_guid"),
        Index("ix_processes_host_pid", "host_id", "process_id"),
        Index("ix_processes_parent_guid", "parent_process_guid"),
        Index("ix_processes_image", "image"),
        Index("ix_processes_last_seen", "last_seen"),
    )


class DetectionRuleRecord(Base):
    """Catalog of rules known to the engine (definitions live in code)."""

    __tablename__ = "detection_rules"

    rule_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    version: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())


class Incident(Base):
    """A group of alerts that share an entity (process, parent, file) in time."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    host_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    # open | investigating | closed
    status: Mapped[str] = mapped_column(String(16), default="open")
    severity: Mapped[str] = mapped_column(String(16))
    severity_rank: Mapped[int] = mapped_column(Integer)
    risk_score: Mapped[int] = mapped_column(Integer)
    score_breakdown: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    entities: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())

    __table_args__ = (
        Index("ix_incidents_status_last_seen", "status", "last_seen"),
        Index("ix_incidents_host_last_seen", "host_id", "last_seen"),
    )


class Alert(Base):
    """A rule finding about one subject. Repeat findings for the same subject
    increment ``occurrence_count`` rather than creating new alerts, so
    duplicate events are not counted as independent evidence."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    dedup_key: Mapped[str] = mapped_column(String(64), unique=True)
    rule_id: Mapped[str] = mapped_column(String(32))
    rule_version: Mapped[int] = mapped_column(Integer)
    host_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    severity_rank: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[int] = mapped_column(Integer)
    score_breakdown: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    # new | acknowledged | reviewed | false_positive
    status: Mapped[str] = mapped_column(String(16), default="new")
    observations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    uncertainty: Mapped[list[str]] = mapped_column(JSON, default=list)
    entities: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitre: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    process_guid: Mapped[str | None] = mapped_column(String(64))
    process_id: Mapped[int | None] = mapped_column(Integer)
    image: Mapped[str | None] = mapped_column(Text)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))

    __table_args__ = (
        Index("ix_alerts_status_last_seen", "status", "last_seen"),
        Index("ix_alerts_severity_rank", "severity_rank"),
        Index("ix_alerts_rule_id", "rule_id"),
        Index("ix_alerts_process_guid", "process_guid"),
        Index("ix_alerts_incident_id", "incident_id"),
        Index("ix_alerts_last_seen", "last_seen"),
    )


class AlertEvidence(Base):
    """Link from an alert to a supporting event. No FK to events: retention
    may purge an event while the alert (with its observations) is kept."""

    __tablename__ = "alert_evidence"

    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    linked_at: Mapped[datetime] = mapped_column(UTCDateTime())

    __table_args__ = (Index("ix_alert_evidence_event_id", "event_id"),)


class InvestigationAction(Base):
    """Append-only history of analyst actions on alerts and incidents."""

    __tablename__ = "investigation_actions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    target_type: Mapped[str] = mapped_column(String(16))  # alert | incident
    target_id: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(32))  # status_change | note
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str | None] = mapped_column(String(16))
    note: Mapped[str | None] = mapped_column(Text)
    # No authentication yet: actor is "local". Replace with the authenticated principal.
    actor: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())

    __table_args__ = (Index("ix_investigation_actions_target", "target_type", "target_id", "created_at"),)
