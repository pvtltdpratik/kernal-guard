"""Collector loop: polls each configured sensor, applies retention periodically."""

from __future__ import annotations

import logging
import threading
import time

from sqlalchemy.orm import Session, sessionmaker

from app.collectors.base import EventLogReader, SensorSpec
from app.core.config import Settings
from app.detection.engine import DetectionEngine
from app.services.ingestion import IngestionLimits, IngestionResult, IngestionService
from app.services.retention import apply_retention

logger = logging.getLogger(__name__)

RETENTION_INTERVAL_SECONDS = 15 * 60


class CollectorRunner:
    def __init__(
        self,
        sensors: list[SensorSpec],
        reader: EventLogReader,
        session_factory: sessionmaker[Session],
        host_id: str,
        settings: Settings,
        engine: DetectionEngine | None = None,
    ) -> None:
        self.sensors = sensors
        self.session_factory = session_factory
        self.settings = settings
        if engine is not None:
            with session_factory() as session, session.begin():
                engine.sync_rule_catalog(session)
        self.service = IngestionService(
            reader,
            session_factory,
            host_id,
            IngestionLimits(
                batch_size=settings.collector_batch_size,
                max_batches=settings.collector_max_batches_per_cycle,
                max_event_xml_bytes=settings.max_event_xml_bytes,
                max_field_chars=settings.max_field_chars,
                store_raw_xml=settings.store_raw_xml,
                read_history=settings.collector_read_history,
            ),
            processor=engine,
        )
        self._last_retention = 0.0

    def run_once(self) -> list[IngestionResult]:
        results = [self.service.ingest(spec) for spec in self.sensors]
        self._maybe_apply_retention()
        return results

    def run_forever(self, stop: threading.Event) -> None:
        logger.info(
            "collector started",
            extra={"sensors": [s.name for s in self.sensors], "interval_s": self.settings.collector_interval_seconds},
        )
        while not stop.is_set():
            results = self.run_once()
            # Drain backlogs promptly; otherwise wait for the next interval.
            backlog = any(r.more_pending for r in results)
            stop.wait(0 if backlog else self.settings.collector_interval_seconds)
        logger.info("collector stopped")

    def _maybe_apply_retention(self) -> None:
        now = time.monotonic()
        if self._last_retention and now - self._last_retention < RETENTION_INTERVAL_SECONDS:
            return
        self._last_retention = now
        try:
            with self.session_factory() as session:
                apply_retention(session, self.settings.event_retention_days, self.settings.event_max_rows)
        except Exception:
            logger.exception("retention failed")
