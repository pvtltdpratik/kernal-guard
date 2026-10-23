"""Sensor status assembly (shared by the sensors and metrics endpoints)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collectors.registry import SENSORS
from app.core.config import Settings
from app.db.models import SensorHealth
from app.schemas.sensors import SensorStatus, SensorStatusResponse

# A sensor is stale if it hasn't been polled for this many intervals.
STALE_INTERVALS = 3


def build_sensor_status(db: Session, settings: Settings) -> SensorStatusResponse:
    now = datetime.now(timezone.utc)
    stale_after = timedelta(seconds=settings.collector_interval_seconds * STALE_INTERVALS)
    rows = {row.sensor: row for row in db.scalars(select(SensorHealth))}
    enabled = set(settings.collector_sensors)

    sensors: list[SensorStatus] = []
    for name, spec in SENSORS.items():
        row = rows.get(name)
        last_attempt = row.last_attempt_at if row else None
        sensors.append(
            SensorStatus(
                sensor=name,
                channel=spec.channel,
                description=spec.description,
                requirements=spec.requirements,
                enabled=name in enabled,
                state=row.state if row else "never_run",  # type: ignore[arg-type]
                detail=row.detail if row else None,
                stale=name in enabled and (last_attempt is None or now - last_attempt > stale_after),
                last_attempt_at=last_attempt,
                last_success_at=row.last_success_at if row else None,
                last_error_at=row.last_error_at if row else None,
                consecutive_failures=row.consecutive_failures if row else 0,
                events_ingested=row.events_ingested if row else 0,
                duplicates_skipped=row.duplicates_skipped if row else 0,
                parse_failures=row.parse_failures if row else 0,
                records_ignored=row.records_ignored if row else 0,
                records_missed=row.records_missed if row else 0,
                detection_failures=(row.detection_failures or 0) if row else 0,
            )
        )

    enabled_sensors = [s for s in sensors if s.enabled]
    return SensorStatusResponse(
        generated_at=now,
        collector_interval_seconds=settings.collector_interval_seconds,
        collector_stale=bool(enabled_sensors) and all(s.stale for s in enabled_sensors),
        sensors=sensors,
    )


def unhealthy_reasons(status: SensorStatusResponse) -> dict[str, str]:
    """Why each sensor is not currently providing telemetry (healthy sensors omitted)."""
    reasons: dict[str, str] = {}
    for s in status.sensors:
        if not s.enabled:
            reasons[s.sensor] = "disabled"
        elif s.state != "ok":
            reasons[s.sensor] = s.state.replace("_", " ")
        elif s.stale:
            reasons[s.sensor] = "stale (collector not polling)"
    return reasons
