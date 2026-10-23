"""Overview metrics for the dashboard."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import Alert, Event, Incident
from app.detection.types import Severity
from app.schemas.detection import MetricsOverview, SensorHealthSummary, SeverityCount, VolumePoint
from app.services.investigation import ACTIVE_ALERT_STATUSES, incident_summaries
from app.services.sensors import build_sensor_status

Window = Literal["24h", "7d"]
_WINDOWS: dict[str, tuple[timedelta, Literal["hour", "day"], str]] = {
    "24h": (timedelta(hours=24), "hour", "%Y-%m-%d %H:00:00"),
    "7d": (timedelta(days=7), "day", "%Y-%m-%d 00:00:00"),
}


def overview(db: Session, settings: Settings, window: Window) -> MetricsOverview:
    now = datetime.now(timezone.utc)
    span, bucket, fmt = _WINDOWS[window]
    since = now - span

    total_events = db.scalar(select(func.count()).select_from(Event)) or 0
    last_24h = db.scalar(select(func.count()).select_from(Event).where(Event.timestamp >= now - timedelta(hours=24))) or 0

    active = Alert.status.in_(ACTIVE_ALERT_STATUSES)
    active_alerts = db.scalar(select(func.count()).select_from(Alert).where(active)) or 0
    by_severity = dict(db.execute(select(Alert.severity, func.count()).where(active).group_by(Alert.severity)).all())

    open_incidents = db.scalar(select(func.count()).select_from(Incident).where(Incident.status != "closed")) or 0
    recent = list(db.scalars(select(Incident).order_by(Incident.last_seen.desc()).limit(5)))

    # SQLite strftime over the stored UTC timestamp; empty buckets filled with 0.
    bucket_expr = func.strftime(fmt, Event.timestamp)
    rows = dict(
        db.execute(select(bucket_expr, func.count()).where(Event.timestamp >= since).group_by(bucket_expr)).all()
    )
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    start = since.replace(minute=0, second=0, microsecond=0)
    if bucket == "day":
        start = start.replace(hour=0)
    volume: list[VolumePoint] = []
    cursor = start
    while cursor <= now:
        key = cursor.strftime(fmt)
        volume.append(VolumePoint(bucket_start=cursor, count=rows.get(key, 0)))
        cursor += step

    top_rules = [
        {"rule_id": rule_id, "active_alerts": count}
        for rule_id, count in db.execute(
            select(Alert.rule_id, func.count()).where(active).group_by(Alert.rule_id).order_by(func.count().desc()).limit(5)
        )
    ]

    sensors = build_sensor_status(db, settings)
    return MetricsOverview(
        generated_at=now,
        total_events=total_events,
        events_last_24h=last_24h,
        active_alerts=active_alerts,
        alerts_by_severity=[SeverityCount(severity=s, count=by_severity.get(s.value, 0)) for s in Severity],
        open_incidents=open_incidents,
        recent_incidents=incident_summaries(db, recent),
        sensors=[SensorHealthSummary(sensor=s.sensor, state=s.state, stale=s.stale) for s in sensors.sensors],
        event_volume=volume,
        event_volume_bucket=bucket,
        top_rules=top_rules,
    )
