"""Read-only context available to rules while they evaluate an event."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import ColumnElement, func, literal_column, select
from sqlalchemy.orm import Session

from app.db.models import Alert, Event, Process
from app.detection.config import DetectionConfig
from app.detection.processes import ProcessTracker, guid_key


INDEXED_DATA_FIELDS = ("ImageLoaded", "TargetFilename")


def data_key(field: str) -> ColumnElement[str]:
    """``lower(json_extract(data, '$.<field>'))`` with the path as a literal,
    so SQLite can match the expression indexes created in migration 0003
    (a bound parameter would never match an index expression)."""
    if field not in INDEXED_DATA_FIELDS:
        raise ValueError(f"{field} has no expression index; add one before querying it per event")
    return func.lower(func.json_extract(Event.data, literal_column(f"'$.{field}'")))


class DetectionContext:
    def __init__(self, session: Session, config: DetectionConfig, tracker: ProcessTracker) -> None:
        self.session = session
        self.config = config
        self.tracker = tracker
        # Per-batch scratch space for rules (a new context is built per batch).
        self.memo: dict[tuple[str, ...], object] = {}

    # ---------------------------------------------------------- processes

    def process(self, event: Event) -> Process | None:
        return self.tracker.for_event(event)

    def process_by_guid(self, host_id: str, guid: str | None) -> Process | None:
        return self.tracker.get(guid_key(host_id, guid)) if guid else None

    # ------------------------------------------------------------- events

    def events_with_data_value(
        self,
        host_id: str,
        category: str,
        field: str,
        value: str,
        since: datetime,
        until: datetime,
        limit: int = 200,
    ) -> list[Event]:
        """Events of ``category`` whose ``data[field]`` equals ``value`` (case-insensitive)."""
        statement = (
            select(Event)
            .where(
                Event.category == category,
                data_key(field) == value.lower(),
                Event.timestamp >= since,
                Event.timestamp <= until,
                Event.host_id == host_id,
            )
            .order_by(Event.timestamp)
            .limit(limit)
        )
        return list(self.session.scalars(statement))

    def process_creations_of_image(self, host_id: str, image: str, since: datetime, until: datetime) -> list[Event]:
        statement = (
            select(Event)
            .where(
                Event.host_id == host_id,
                Event.category == "process_creation",
                Event.timestamp >= since,
                Event.timestamp <= until,
                func.lower(Event.image) == image.lower(),
            )
            .order_by(Event.timestamp)
            .limit(50)
        )
        return list(self.session.scalars(statement))

    # ------------------------------------------------------------- alerts

    def active_alerts(self, alert_ids: list[str]) -> list[Alert]:
        if not alert_ids:
            return []
        return list(
            self.session.scalars(
                select(Alert).where(Alert.id.in_(alert_ids), Alert.status != "false_positive")
            )
        )

    @staticmethod
    def window(at: datetime, minutes: float) -> tuple[datetime, datetime]:
        delta = timedelta(minutes=minutes)
        return at - delta, at + delta
