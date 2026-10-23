"""Schemas for alerts, incidents, processes, metrics and the detection catalog."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.detection.types import Confidence, Severity
from app.schemas.events import EventSummary

AlertStatus = Literal["new", "acknowledged", "reviewed", "false_positive"]
IncidentStatus = Literal["open", "investigating", "closed"]


class MitreOut(BaseModel):
    technique_id: str
    name: str
    tactic: str
    relationship: Literal["observed", "consistent_with"]


class ObservationOut(BaseModel):
    kind: Literal["observed", "inferred"]
    text: str
    event_id: str | None = None


class RuleOut(BaseModel):
    rule_id: str
    name: str
    description: str
    category: str
    kind: Literal["event", "correlation"]
    severity: Severity
    confidence: Confidence
    rationale: str
    required_evidence: list[str]
    false_positives: list[str]
    mitre: list[MitreOut]
    thresholds: dict[str, float | int]
    version: int
    enabled: bool


class AlertSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    risk_score: int
    status: AlertStatus
    host_id: str
    process_guid: str | None
    process_id: int | None
    image: str | None
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime
    incident_id: str | None


class InvestigationActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    action: str
    from_status: str | None
    to_status: str | None
    note: str | None
    actor: str
    created_at: datetime


class AlertDetail(AlertSummary):
    rule: RuleOut | None
    observations: list[ObservationOut]
    uncertainty: list[str]
    entities: list[str]
    mitre: list[MitreOut]
    score_breakdown: list[dict[str, Any]]
    evidence: list[EventSummary]
    evidence_missing: int = Field(description="Linked events no longer stored (purged by retention)")
    history: list[InvestigationActionOut]
    created_at: datetime
    updated_at: datetime


class _StatusNotePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, min_length=1, max_length=4000)

    @model_validator(mode="after")
    def _require_change(self) -> _StatusNotePatch:
        if getattr(self, "status", None) is None and self.note is None:
            raise ValueError("Provide 'status' and/or 'note'")
        return self


class AlertPatch(_StatusNotePatch):
    status: AlertStatus | None = None


class IncidentPatch(_StatusNotePatch):
    status: IncidentStatus | None = None


class IncidentSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    status: IncidentStatus
    severity: Severity
    risk_score: int
    host_id: str
    first_seen: datetime
    last_seen: datetime
    alert_count: int = 0


class TimelineEntry(BaseModel):
    timestamp: datetime
    kind: Literal["event", "alert"]
    event: EventSummary | None = None
    alert_id: str | None = None
    rule_id: str | None = None
    title: str
    observations: list[ObservationOut] = Field(default_factory=list)


class IncidentDetail(IncidentSummary):
    entities: list[str]
    score_breakdown: list[dict[str, Any]]
    alerts: list[AlertSummary]
    rules_fired: list[RuleOut]
    timeline: list[TimelineEntry]
    uncertainty: list[str]
    history: list[InvestigationActionOut]
    created_at: datetime
    updated_at: datetime


class ProcessSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    key: str
    host_id: str
    process_guid: str | None
    process_id: int | None
    image: str | None
    user: str | None
    start_time: datetime | None
    end_time: datetime | None
    first_seen: datetime
    last_seen: datetime
    creation_observed: bool


class NetworkSummary(BaseModel):
    destination_ip: str | None
    destination_port: str | None
    destination_hostname: str | None
    protocol: str | None
    connections: int
    first_seen: datetime
    last_seen: datetime


class ProcessDetail(ProcessSummary):
    command_line: str | None
    integrity_level: str | None
    parent_process_guid: str | None
    parent_process_id: int | None
    parent_image: str | None
    sha256: str | None
    sha1: str | None
    md5: str | None
    imphash: str | None
    sources: list[str]
    conflicts: list[dict[str, Any]]
    signature: dict[str, Any] | None = Field(description="From image-load events of this image, if any")
    parent: ProcessSummary | None
    children: list[ProcessSummary]
    event_counts: dict[str, int]
    network: list[NetworkSummary]
    alerts: list[AlertSummary]


class CapabilityOut(BaseModel):
    technique_id: str
    technique: str
    design_visibility: str
    effective_visibility: str
    effective_note: str | None
    sensors: list[str]
    evidence: str
    gaps: str
    rules: list[str]


class SeverityCount(BaseModel):
    severity: Severity
    count: int


class VolumePoint(BaseModel):
    bucket_start: datetime
    count: int


class SensorHealthSummary(BaseModel):
    sensor: str
    state: str
    stale: bool


class MetricsOverview(BaseModel):
    generated_at: datetime
    total_events: int
    events_last_24h: int
    active_alerts: int
    alerts_by_severity: list[SeverityCount]
    open_incidents: int
    recent_incidents: list[IncidentSummary]
    sensors: list[SensorHealthSummary]
    event_volume: list[VolumePoint]
    event_volume_bucket: Literal["hour", "day"]
    top_rules: list[dict[str, Any]]
