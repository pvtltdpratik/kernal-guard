"""Drive the real ingestion + detection pipeline with synthetic events."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.registry import SENSORS
from app.collectors.sysmon import SYSMON_CHANNEL
from app.db.models import Alert, Incident, Process
from app.detection.config import DetectionConfig
from app.detection.engine import DetectionEngine
from app.services.ingestion import IngestionService
from tests.helpers import BASE_TIME, FakeEventLogReader


@dataclass
class Harness:
    session_factory: sessionmaker[Session]
    config: DetectionConfig = field(default_factory=DetectionConfig)
    reader: FakeEventLogReader = field(default_factory=FakeEventLogReader)
    next_record: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.engine = DetectionEngine(self.config)
        self.service = IngestionService(self.reader, self.session_factory, host_id="host-1", processor=self.engine)
        with self.session_factory() as session, session.begin():
            self.engine.sync_rule_catalog(session)

    def add(self, xml: str, at: datetime | None = None, channel: str = SYSMON_CHANNEL) -> None:
        record = self.next_record.get(channel, 0) + 1
        self.next_record[channel] = record
        self.reader.add(channel, xml, record, at)

    def run(self, *events: str | tuple[str, datetime], channel: str = SYSMON_CHANNEL) -> None:
        """Add events (optionally with timestamps) and ingest them in one cycle."""
        for item in events:
            xml, at = (item, None) if isinstance(item, str) else item
            self.add(xml, at, channel)
        sensor = next(name for name, spec in SENSORS.items() if spec.channel == channel)
        result = self.service.ingest(SENSORS[sensor])
        assert result.state == "ok", result
        assert result.detection_failures == 0, result

    def alerts(self, rule_id: str | None = None) -> list[Alert]:
        with self.session_factory() as session:
            statement = select(Alert).order_by(Alert.created_at)
            if rule_id:
                statement = statement.where(Alert.rule_id == rule_id)
            return list(session.scalars(statement))

    def rule_ids(self) -> set[str]:
        return {a.rule_id for a in self.alerts()}

    def incidents(self) -> list[Incident]:
        with self.session_factory() as session:
            return list(session.scalars(select(Incident).order_by(Incident.created_at)))

    def processes(self) -> list[Process]:
        with self.session_factory() as session:
            return list(session.scalars(select(Process).order_by(Process.first_seen)))


def at(seconds: float) -> datetime:
    return BASE_TIME + timedelta(seconds=seconds)
