"""Read/write services for alerts and incidents (API side)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.db.models import Alert, AlertEvidence, Event, Incident, InvestigationAction
from app.detection.config import DetectionConfig
from app.detection.correlation import IncidentCorrelator
from app.detection.rules import CORRELATION_RULES, RULES_BY_ID
from app.detection.types import Severity
from app.schemas.detection import (
    AlertDetail,
    AlertSummary,
    IncidentDetail,
    IncidentSummary,
    InvestigationActionOut,
    ObservationOut,
    RuleOut,
    TimelineEntry,
)
from app.schemas.events import EventSummary

ACTIVE_ALERT_STATUSES = ("new", "acknowledged")
ACTOR = "local"  # no authentication yet; see docs/security.md
MAX_TIMELINE_EVENTS = 500

AlertSort = Literal[
    "last_seen", "-last_seen", "first_seen", "-first_seen", "risk_score", "-risk_score", "severity", "-severity"
]
IncidentSort = Literal["last_seen", "-last_seen", "risk_score", "-risk_score", "severity", "-severity"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------- rules


def rule_out(rule_id: str, config: DetectionConfig) -> RuleOut | None:
    rule = RULES_BY_ID.get(rule_id)
    if rule is None:
        return None
    meta = rule.meta
    return RuleOut(
        rule_id=meta.rule_id,
        name=meta.name,
        description=meta.description,
        category=meta.category,
        kind="correlation" if rule in CORRELATION_RULES else "event",
        severity=meta.severity,
        confidence=meta.confidence,
        rationale=meta.rationale,
        required_evidence=list(meta.required_evidence),
        false_positives=list(meta.false_positives),
        mitre=[vars(m) for m in meta.mitre],  # type: ignore[misc]
        thresholds={k: config.threshold(rule_id, k, v) for k, v in meta.thresholds.items()},
        version=meta.version,
        enabled=config.is_enabled(rule_id),
    )


def all_rules(config: DetectionConfig) -> list[RuleOut]:
    return [r for rule_id in RULES_BY_ID if (r := rule_out(rule_id, config)) is not None]


# ------------------------------------------------------------------ alerts


@dataclass(frozen=True)
class AlertFilters:
    statuses: list[str] | None = None
    severities: list[Severity] | None = None
    rule_id: str | None = None
    host_id: str | None = None
    process_guid: str | None = None
    incident_id: str | None = None
    q: str | None = None
    min_score: int | None = None
    since: datetime | None = None
    until: datetime | None = None


def _alert_filters(statement: Select, f: AlertFilters) -> Select:  # type: ignore[type-arg]
    if f.statuses:
        statement = statement.where(Alert.status.in_(f.statuses))
    if f.severities:
        statement = statement.where(Alert.severity.in_([s.value for s in f.severities]))
    if f.rule_id:
        statement = statement.where(Alert.rule_id == f.rule_id)
    if f.host_id:
        statement = statement.where(Alert.host_id == f.host_id)
    if f.process_guid:
        statement = statement.where(Alert.process_guid == f.process_guid)
    if f.incident_id:
        statement = statement.where(Alert.incident_id == f.incident_id)
    if f.q:
        needle = f.q.lower()
        statement = statement.where(
            func.lower(Alert.title).contains(needle, autoescape=True)
            | func.lower(func.coalesce(Alert.image, "")).contains(needle, autoescape=True)
        )
    if f.min_score is not None:
        statement = statement.where(Alert.risk_score >= f.min_score)
    if f.since:
        statement = statement.where(Alert.last_seen >= f.since)
    if f.until:
        statement = statement.where(Alert.last_seen < f.until)
    return statement


_ALERT_SORT = {"last_seen": Alert.last_seen, "first_seen": Alert.first_seen, "risk_score": Alert.risk_score, "severity": Alert.severity_rank}


def list_alerts(db: Session, f: AlertFilters, sort: AlertSort, page: int, page_size: int) -> tuple[list[Alert], int]:
    total = db.scalar(_alert_filters(select(func.count()).select_from(Alert), f)) or 0
    column = _ALERT_SORT[sort.lstrip("-")]
    primary = column.desc() if sort.startswith("-") else column.asc()
    statement = (
        _alert_filters(select(Alert), f)
        .order_by(primary, Alert.last_seen.desc(), Alert.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return list(db.scalars(statement)), total


def _history(db: Session, target_type: str, target_id: str) -> list[InvestigationActionOut]:
    actions = db.scalars(
        select(InvestigationAction)
        .where(InvestigationAction.target_type == target_type, InvestigationAction.target_id == target_id)
        .order_by(InvestigationAction.created_at)
    )
    return [InvestigationActionOut.model_validate(a) for a in actions]


def alert_detail(db: Session, alert: Alert, config: DetectionConfig) -> AlertDetail:
    linked = list(db.scalars(select(AlertEvidence.event_id).where(AlertEvidence.alert_id == alert.id)))
    events = list(db.scalars(select(Event).where(Event.id.in_(linked)).order_by(Event.timestamp))) if linked else []
    return AlertDetail(
        **AlertSummary.model_validate(alert).model_dump(),
        rule=rule_out(alert.rule_id, config),
        observations=[ObservationOut(**o) for o in alert.observations],
        uncertainty=alert.uncertainty,
        entities=alert.entities,
        mitre=alert.mitre,  # type: ignore[arg-type]
        score_breakdown=alert.score_breakdown,
        evidence=[EventSummary.model_validate(e) for e in events],
        evidence_missing=len(linked) - len(events),
        history=_history(db, "alert", alert.id),
        created_at=alert.created_at,
        updated_at=alert.updated_at,
    )


def _record(db: Session, target_type: str, target_id: str, action: str, *, from_status: str | None = None,
            to_status: str | None = None, note: str | None = None) -> None:
    db.add(InvestigationAction(target_type=target_type, target_id=target_id, action=action,
                               from_status=from_status, to_status=to_status, note=note, actor=ACTOR,
                               created_at=utcnow()))


def update_alert(db: Session, alert: Alert, status: str | None, note: str | None, config: DetectionConfig) -> None:
    if status is not None and status != alert.status:
        _record(db, "alert", alert.id, "status_change", from_status=alert.status, to_status=status)
        alert.status = status
        alert.updated_at = utcnow()
        if alert.incident_id:
            # An analyst verdict changes the evidence: false positives stop
            # contributing to the incident score.
            incident = db.get(Incident, alert.incident_id)
            if incident is not None:
                db.flush()
                IncidentCorrelator(db, config.incident_window_minutes).rescore(incident)
    if note is not None:
        _record(db, "alert", alert.id, "note", note=note)


# --------------------------------------------------------------- incidents


@dataclass(frozen=True)
class IncidentFilters:
    statuses: list[str] | None = None
    severities: list[Severity] | None = None
    host_id: str | None = None
    q: str | None = None
    min_score: int | None = None
    since: datetime | None = None
    until: datetime | None = None


def _incident_filters(statement: Select, f: IncidentFilters) -> Select:  # type: ignore[type-arg]
    if f.statuses:
        statement = statement.where(Incident.status.in_(f.statuses))
    if f.severities:
        statement = statement.where(Incident.severity.in_([s.value for s in f.severities]))
    if f.host_id:
        statement = statement.where(Incident.host_id == f.host_id)
    if f.q:
        statement = statement.where(func.lower(Incident.title).contains(f.q.lower(), autoescape=True))
    if f.min_score is not None:
        statement = statement.where(Incident.risk_score >= f.min_score)
    if f.since:
        statement = statement.where(Incident.last_seen >= f.since)
    if f.until:
        statement = statement.where(Incident.last_seen < f.until)
    return statement


_INCIDENT_SORT = {"last_seen": Incident.last_seen, "risk_score": Incident.risk_score, "severity": Incident.severity_rank}


def _alert_counts(db: Session, incident_ids: list[str]) -> dict[str, int]:
    if not incident_ids:
        return {}
    rows = db.execute(
        select(Alert.incident_id, func.count()).where(Alert.incident_id.in_(incident_ids)).group_by(Alert.incident_id)
    )
    return {incident_id: count for incident_id, count in rows}


def incident_summaries(db: Session, incidents: list[Incident]) -> list[IncidentSummary]:
    counts = _alert_counts(db, [i.id for i in incidents])
    return [
        IncidentSummary.model_validate(i).model_copy(update={"alert_count": counts.get(i.id, 0)}) for i in incidents
    ]


def list_incidents(
    db: Session, f: IncidentFilters, sort: IncidentSort, page: int, page_size: int
) -> tuple[list[IncidentSummary], int]:
    total = db.scalar(_incident_filters(select(func.count()).select_from(Incident), f)) or 0
    column = _INCIDENT_SORT[sort.lstrip("-")]
    primary = column.desc() if sort.startswith("-") else column.asc()
    statement = (
        _incident_filters(select(Incident), f)
        .order_by(primary, Incident.last_seen.desc(), Incident.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    return incident_summaries(db, list(db.scalars(statement))), total


def incident_detail(db: Session, incident: Incident, config: DetectionConfig) -> IncidentDetail:
    alerts = list(db.scalars(select(Alert).where(Alert.incident_id == incident.id).order_by(Alert.first_seen)))
    alert_ids = [a.id for a in alerts]
    links = list(db.execute(select(AlertEvidence.event_id, AlertEvidence.alert_id).where(AlertEvidence.alert_id.in_(alert_ids)))) if alert_ids else []
    event_ids = list(dict.fromkeys(event_id for event_id, _ in links))
    events = (
        list(db.scalars(select(Event).where(Event.id.in_(event_ids)).order_by(Event.timestamp).limit(MAX_TIMELINE_EVENTS)))
        if event_ids else []
    )

    timeline = [
        TimelineEntry(timestamp=e.timestamp, kind="event", event=EventSummary.model_validate(e),
                      title=f"{e.category.replace('_', ' ')}: {e.image or e.channel}")
        for e in events
    ] + [
        TimelineEntry(timestamp=a.first_seen, kind="alert", alert_id=a.id, rule_id=a.rule_id, title=a.title,
                      observations=[ObservationOut(**o) for o in a.observations])
        for a in alerts
    ]
    # Alerts sort after the events that triggered them at the same instant.
    timeline.sort(key=lambda t: (t.timestamp, t.kind == "alert"))

    uncertainty = list(dict.fromkeys(u for a in alerts for u in a.uncertainty))
    false_positives = [a for a in alerts if a.status == "false_positive"]
    if false_positives:
        uncertainty.insert(0, f"{len(false_positives)} alert(s) marked false positive by an analyst; excluded from the score.")
    if len(event_ids) > len(events):
        uncertainty.append(f"{len(event_ids) - len(events)} evidence event(s) are no longer stored (retention) or exceed the timeline limit.")

    rules = [r for rule_id in dict.fromkeys(a.rule_id for a in alerts) if (r := rule_out(rule_id, config))]
    summary = incident_summaries(db, [incident])[0]
    return IncidentDetail(
        **summary.model_dump(),
        entities=incident.entities,
        score_breakdown=incident.score_breakdown,
        alerts=[AlertSummary.model_validate(a) for a in alerts],
        rules_fired=rules,
        timeline=timeline,
        uncertainty=uncertainty,
        history=_history(db, "incident", incident.id),
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )


def update_incident(db: Session, incident: Incident, status: str | None, note: str | None) -> None:
    if status is not None and status != incident.status:
        _record(db, "incident", incident.id, "status_change", from_status=incident.status, to_status=status)
        incident.status = status
        incident.updated_at = utcnow()
    if note is not None:
        _record(db, "incident", incident.id, "note", note=note)
