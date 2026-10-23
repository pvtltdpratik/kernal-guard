"""Incident correlation.

An alert joins an existing non-closed incident on the same host when:
- they share at least one entity (process key, parent process key, file path), and
- the incident's activity window [first_seen - W, last_seen + W] overlaps the alert.

Entities use ProcessGuid or PID+start time keys (never bare PIDs), so PID
reuse cannot merge unrelated processes. If an alert matches several
incidents, it joins the most recently active one; the others are reported
in its correlation notes rather than merged automatically.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Alert, Incident
from app.detection.scoring import score_incident


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IncidentCorrelator:
    def __init__(self, session: Session, window_minutes: int) -> None:
        self.session = session
        self.window = timedelta(minutes=window_minutes)

    def assign(self, alert: Alert) -> Incident:
        if alert.incident_id:
            incident = self.session.get(Incident, alert.incident_id)
            if incident is not None:
                self._absorb(incident, alert)
                return incident

        entities = set(alert.entities)
        candidates = list(
            self.session.scalars(
                select(Incident)
                .where(
                    Incident.host_id == alert.host_id,
                    Incident.status != "closed",
                    Incident.last_seen >= alert.first_seen - self.window,
                    Incident.first_seen <= alert.last_seen + self.window,
                )
                .order_by(Incident.last_seen.desc())
            )
        )
        matches = [i for i in candidates if entities & set(i.entities)] if entities else []
        if matches:
            incident = matches[0]
            if len(matches) > 1:
                others = ", ".join(i.id for i in matches[1:])
                note = f"Also shares entities with incident(s) {others}; not merged automatically."
                if note not in alert.uncertainty:
                    alert.uncertainty = [*alert.uncertainty, note]
        else:
            now = utcnow()
            incident = Incident(
                host_id=alert.host_id,
                title=alert.title,
                status="open",
                severity=alert.severity,
                severity_rank=alert.severity_rank,
                risk_score=alert.risk_score,
                score_breakdown=[],
                entities=[],
                first_seen=alert.first_seen,
                last_seen=alert.last_seen,
                created_at=now,
                updated_at=now,
            )
            self.session.add(incident)
            self.session.flush()
        alert.incident_id = incident.id
        self._absorb(incident, alert)
        return incident

    @staticmethod
    def _absorb(incident: Incident, alert: Alert) -> None:
        incident.entities = sorted(set(incident.entities) | set(alert.entities))
        incident.first_seen = min(incident.first_seen, alert.first_seen)
        incident.last_seen = max(incident.last_seen, alert.last_seen)

    def rescore(self, incident: Incident) -> None:
        alerts = list(self.session.scalars(select(Alert).where(Alert.incident_id == incident.id)))
        score, severity, breakdown = score_incident(alerts)
        incident.risk_score = score
        incident.severity = severity.value
        incident.severity_rank = severity.rank
        incident.score_breakdown = breakdown
        active = [a for a in alerts if a.status != "false_positive"]
        lead = max(active or alerts, key=lambda a: (a.risk_score, a.last_seen))
        extra = len(alerts) - 1
        incident.title = lead.title + (f" (+{extra} related alert{'s' if extra != 1 else ''})" if extra else "")
        incident.updated_at = utcnow()
