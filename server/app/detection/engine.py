"""Detection engine: tracker -> event rules -> alerts -> incidents -> correlation rules.

Runs inside the ingestion transaction for each batch of newly stored
events (via ``process``), and over historical events for rescans. All
writes are idempotent: re-evaluating an event links no new evidence and
does not increase occurrence counts.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Alert, AlertEvidence, DetectionRuleRecord, Event, Incident
from app.detection.config import DetectionConfig
from app.detection.context import DetectionContext
from app.detection.correlation import IncidentCorrelator
from app.detection.processes import ProcessTracker
from app.detection.rules import CORRELATION_RULES, EVENT_RULES, RULES_BY_ID
from app.detection.rules.base import CorrelationRule, EventRule
from app.detection.scoring import score_alert
from app.detection.types import Finding, RuleMeta

logger = logging.getLogger(__name__)

MAX_OBSERVATIONS = 50


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def alert_dedup_key(rule_id: str, host_id: str, subject: str) -> str:
    return hashlib.sha256(f"{rule_id}|{host_id}|{subject}".encode()).hexdigest()


@dataclass
class EngineResult:
    events: int = 0
    alerts_created: int = 0
    alerts_updated: int = 0
    suppressed: int = 0
    rule_errors: int = 0
    incidents_touched: set[str] = field(default_factory=set)


class DetectionEngine:
    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()
        self._rules_by_category: dict[str, list[EventRule]] = {}
        for rule in EVENT_RULES:
            if self.config.is_enabled(rule.meta.rule_id):
                for category in rule.categories:
                    self._rules_by_category.setdefault(category, []).append(rule)
        self._correlation_rules = [r for r in CORRELATION_RULES if self.config.is_enabled(r.meta.rule_id)]

    # ------------------------------------------------------------ catalog

    def sync_rule_catalog(self, session: Session) -> None:
        now = utcnow()
        for rule_id, rule in RULES_BY_ID.items():
            record = session.get(DetectionRuleRecord, rule_id) or DetectionRuleRecord(rule_id=rule_id)
            meta = rule.meta
            record.name, record.category = meta.name, meta.category
            record.severity, record.confidence = meta.severity.value, meta.confidence.value
            record.version, record.enabled = meta.version, self.config.is_enabled(rule_id)
            record.updated_at = now
            session.add(record)

    # ------------------------------------------------------------ process

    def process_event_ids(self, session: Session, event_ids: list[str]) -> EngineResult:
        if not event_ids:
            return EngineResult()
        events = list(
            session.scalars(select(Event).where(Event.id.in_(event_ids)).order_by(Event.timestamp, Event.id))
        )
        return self.process(session, events)

    def process(self, session: Session, events: list[Event]) -> EngineResult:
        result = EngineResult(events=len(events))
        tracker = ProcessTracker(session)
        for event in events:
            tracker.observe(event)
        session.flush()

        ctx = DetectionContext(session, self.config, tracker)
        touched: dict[str, Alert] = {}
        for event in events:
            for rule in self._rules_by_category.get(event.category, ()):
                for finding in self._run_rule(rule, event, ctx, result):
                    alert = self._apply_finding(session, rule.meta, finding, event.host_id, result)
                    if alert is not None:
                        touched[alert.id] = alert
        session.flush()

        self._correlate(session, ctx, list(touched.values()), result)
        return result

    def _run_rule(self, rule: EventRule, event: Event, ctx: DetectionContext, result: EngineResult) -> list[Finding]:
        try:
            return rule.evaluate(event, ctx)
        except Exception:
            result.rule_errors += 1
            logger.exception("Rule failed", extra={"rule_id": rule.meta.rule_id, "event_id": event.id})
            return []

    # ------------------------------------------------------------- alerts

    def _suppressed(self, finding: Finding, session: Session) -> bool:
        allow = self.config.allowlist
        if finding.image and finding.image.lower() in allow.images:
            return True
        if allow.sha256 and finding.event_ids:
            hashes = session.scalars(select(Event.sha256).where(Event.id.in_(finding.event_ids)))
            if any(h and h in allow.sha256 for h in hashes):
                return True
        return False

    def _apply_finding(
        self, session: Session, meta: RuleMeta, finding: Finding, host_id: str, result: EngineResult
    ) -> Alert | None:
        if self._suppressed(finding, session):
            result.suppressed += 1
            return None

        severity = finding.severity or meta.severity
        confidence = finding.confidence or meta.confidence
        score, breakdown = score_alert(severity, confidence, finding.adjustments)
        mitre = [vars(m) for m in (finding.mitre if finding.mitre is not None else meta.mitre)]
        observations = [vars(o) for o in finding.observations]

        times = list(session.scalars(select(Event.timestamp).where(Event.id.in_(finding.event_ids)))) or [utcnow()]
        first, last = min(times), max(times)
        key = alert_dedup_key(meta.rule_id, host_id, finding.subject)
        alert = session.scalar(select(Alert).where(Alert.dedup_key == key))
        now = utcnow()

        if alert is None:
            alert = Alert(
                dedup_key=key, rule_id=meta.rule_id, rule_version=meta.version, host_id=host_id,
                title=finding.title[:255], severity=severity.value, severity_rank=severity.rank,
                confidence=confidence.value, risk_score=score, score_breakdown=breakdown, status="new",
                observations=observations[:MAX_OBSERVATIONS], uncertainty=list(finding.uncertainty),
                entities=sorted(set(finding.entities)), mitre=mitre,
                process_guid=finding.process_guid, process_id=finding.process_id, image=finding.image,
                occurrence_count=1, first_seen=first, last_seen=last, created_at=now, updated_at=now,
            )
            session.add(alert)
            session.flush()
            self._link_evidence(session, alert, finding.event_ids)
            result.alerts_created += 1
            return alert

        new_links = self._link_evidence(session, alert, finding.event_ids)
        if new_links == 0:
            return None  # same evidence re-evaluated (rescan/duplicate): not new evidence
        alert.occurrence_count += 1
        alert.first_seen, alert.last_seen = min(alert.first_seen, first), max(alert.last_seen, last)
        known = {o["text"] for o in alert.observations}
        alert.observations = (alert.observations + [o for o in observations if o["text"] not in known])[:MAX_OBSERVATIONS]
        alert.uncertainty = list(dict.fromkeys([*alert.uncertainty, *finding.uncertainty]))
        alert.entities = sorted(set(alert.entities) | set(finding.entities))
        if severity.rank > alert.severity_rank or score > alert.risk_score:
            alert.severity, alert.severity_rank = severity.value, severity.rank
            alert.confidence, alert.risk_score, alert.score_breakdown = confidence.value, score, breakdown
        alert.updated_at = now
        result.alerts_updated += 1
        return alert

    def _link_evidence(self, session: Session, alert: Alert, event_ids: list[str]) -> int:
        existing = set(session.scalars(select(AlertEvidence.event_id).where(AlertEvidence.alert_id == alert.id)))
        room = self.config.max_evidence_per_alert - len(existing)
        new_ids = [e for e in dict.fromkeys(event_ids) if e not in existing]
        now = utcnow()
        for event_id in new_ids[: max(room, 0)]:
            session.add(AlertEvidence(alert_id=alert.id, event_id=event_id, linked_at=now))
        # Flush so a later finding for the same alert in this batch sees these
        # links (sessions use autoflush=False).
        session.flush()
        # Evidence beyond the cap still counts as new (occurrence) but is not linked.
        return len(new_ids)

    # -------------------------------------------------------- correlation

    def _correlate(self, session: Session, ctx: DetectionContext, alerts: list[Alert], result: EngineResult) -> None:
        correlator = IncidentCorrelator(session, self.config.incident_window_minutes)
        incidents: dict[str, Incident] = {}
        for alert in sorted(alerts, key=lambda a: a.first_seen):
            incident = correlator.assign(alert)
            incidents[incident.id] = incident
        session.flush()

        for incident in incidents.values():
            members = list(session.scalars(select(Alert).where(Alert.incident_id == incident.id)))
            active = [a for a in members if a.status != "false_positive"]
            for rule in self._correlation_rules:
                for finding in self._run_correlation(rule, incident, active, ctx, result):
                    alert = self._apply_finding(session, rule.meta, finding, incident.host_id, result)
                    if alert is not None:
                        alert.incident_id = incident.id
            session.flush()
            correlator.rescore(incident)
            result.incidents_touched.add(incident.id)

    def _run_correlation(
        self, rule: CorrelationRule, incident: Incident, alerts: list[Alert], ctx: DetectionContext, result: EngineResult
    ) -> list[Finding]:
        try:
            return rule.evaluate(incident, alerts, ctx)
        except Exception:
            result.rule_errors += 1
            logger.exception("Correlation rule failed", extra={"rule_id": rule.meta.rule_id, "incident_id": incident.id})
            return []

    def rescore_incident(self, session: Session, incident: Incident) -> None:
        IncidentCorrelator(session, self.config.incident_window_minutes).rescore(incident)
