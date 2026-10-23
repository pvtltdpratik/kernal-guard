"""Channel ingestion: read → parse → normalise → deduplicate → persist.

Guarantees
- Events and the channel bookmark are committed in the same transaction,
  so a crash mid-batch re-reads that batch on restart and the dedup key
  drops anything already stored (at-least-once read, exactly-once storage).
- A record that cannot be parsed is counted and skipped; it never blocks
  the channel.
- Log rotation (records overwritten before they were read) is measured and
  reported as ``records_missed``, never silently ignored.
- A cleared/recreated log (record IDs restarted) is detected and the
  bookmark is reset so new events are not skipped.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.base import (
    ChannelAccessDeniedError,
    ChannelUnavailableError,
    CollectorError,
    EventLogReader,
    NormalizeContext,
    RawRecord,
    SensorSpec,
)
from app.collectors.xml_parser import EventParseError, extract_record_id, parse_event_xml
from app.db.models import CollectorBookmark, Event, SensorHealth
from app.schemas.events import NormalizedEvent

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestionLimits:
    batch_size: int = 200
    max_batches: int = 10
    max_event_xml_bytes: int = 256 * 1024
    max_field_chars: int = 8192
    store_raw_xml: bool = True
    read_history: bool = True


@dataclass
class IngestionResult:
    sensor: str
    state: str = "ok"
    detail: str | None = None
    read: int = 0
    inserted: int = 0
    duplicates: int = 0
    parse_failures: int = 0
    ignored: int = 0
    missed: int = 0
    bookmark_reset: bool = False
    batches: int = 0
    more_pending: bool = False
    alerts_created: int = 0
    detection_failures: int = 0
    errors: list[str] = field(default_factory=list)


class EventProcessor(Protocol):
    """Runs on each batch's newly stored events inside the batch transaction
    (implemented by the detection engine)."""

    def process_event_ids(self, session: Session, event_ids: list[str]) -> Any: ...


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def dedup_key(host_id: str, channel: str, record_id: int, logged_at: datetime, event_id: int) -> str:
    material = f"{host_id}|{channel}|{record_id}|{logged_at.isoformat()}|{event_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


_EVENTS_TABLE = Event.__table__
_INSERT_EVENT = (
    sqlite_insert(_EVENTS_TABLE)
    .on_conflict_do_nothing(index_elements=["dedup_key"])
    .returning(_EVENTS_TABLE.c.id)
)


def _event_row(event: NormalizedEvent, ingested_at: datetime) -> dict[str, object]:
    row = event.model_dump(mode="python")
    row["id"] = uuid.uuid4().hex
    row["source"] = event.source.value
    row["category"] = event.category.value
    row["collection_status"] = event.collection_status.value
    row["ingested_at"] = ingested_at
    row["dedup_key"] = dedup_key(
        event.host_id, event.channel, event.record_id, event.logged_at, event.source_event_id
    )
    return row


class IngestionService:
    def __init__(
        self,
        reader: EventLogReader,
        session_factory: sessionmaker[Session],
        host_id: str,
        limits: IngestionLimits | None = None,
        processor: EventProcessor | None = None,
    ) -> None:
        self.reader = reader
        self.session_factory = session_factory
        self.host_id = host_id
        self.limits = limits or IngestionLimits()
        self.processor = processor

    # ------------------------------------------------------------------ public

    def ingest(self, spec: SensorSpec) -> IngestionResult:
        result = IngestionResult(sensor=spec.name)
        started = utcnow()
        try:
            start_after = self._resolve_start(spec, result)
            if start_after is not None:
                self._ingest_batches(spec, start_after, result)
        except ChannelUnavailableError:
            result.state, result.detail = "unavailable", spec.unavailable_hint
        except ChannelAccessDeniedError:
            result.state, result.detail = "access_denied", spec.access_denied_hint
        except CollectorError as exc:
            result.state, result.detail = "error", str(exc)
        except Exception as exc:  # keep the collector alive; record and continue
            logger.exception("Unexpected ingestion failure", extra={"sensor": spec.name})
            result.state, result.detail = "error", f"{exc.__class__.__name__}: {exc}"

        self._record_health(spec, result, started)
        log = logger.info if result.state == "ok" else logger.warning
        log(
            "ingestion cycle",
            extra={
                "sensor": spec.name,
                "state": result.state,
                "read": result.read,
                "inserted": result.inserted,
                "duplicates": result.duplicates,
                "parse_failures": result.parse_failures,
                "ignored": result.ignored,
                "missed": result.missed,
                "more_pending": result.more_pending,
            },
        )
        return result

    # ----------------------------------------------------------------- bookmark

    def _resolve_start(self, spec: SensorSpec, result: IngestionResult) -> int | None:
        """Return the record ID to read after, handling first run, rotation
        and cleared logs. None means there is nothing to read."""
        with self.session_factory() as session:
            bookmark = session.get(CollectorBookmark, spec.channel)

            oldest = self.reader.oldest(spec.channel)
            if oldest is None:  # empty channel
                return None

            if bookmark is None:
                if self.limits.read_history:
                    return oldest.record_id - 1
                newest = self.reader.newest(spec.channel)
                start = newest.record_id if newest else oldest.record_id - 1
                self._save_bookmark(session, spec.channel, start, newest.logged_at if newest else None)
                session.commit()
                return start

            last = bookmark.last_record_id
            if last <= 0:
                return oldest.record_id - 1

            if self._log_was_cleared(spec.channel, bookmark, oldest.record_id):
                logger.warning(
                    "Channel appears cleared or recreated; resetting bookmark",
                    extra={"sensor": spec.name, "channel": spec.channel, "previous_record_id": last},
                )
                result.bookmark_reset = True
                return oldest.record_id - 1

            if oldest.record_id > last + 1:
                # Records last+1 .. oldest-1 were overwritten before we read them.
                result.missed = oldest.record_id - last - 1
                logger.warning(
                    "Records lost to log rotation",
                    extra={"sensor": spec.name, "channel": spec.channel, "missed": result.missed},
                )
            return last

    def _log_was_cleared(self, channel: str, bookmark: CollectorBookmark, oldest_id: int) -> bool:
        last = bookmark.last_record_id
        newest = self.reader.newest(channel)
        if newest is not None and newest.record_id < last:
            return True
        if oldest_id <= last and bookmark.last_logged_at is not None:
            # The bookmarked record should still exist with the same timestamp.
            return self.reader.logged_at(channel, last) != bookmark.last_logged_at
        return False

    @staticmethod
    def _save_bookmark(session: Session, channel: str, record_id: int, logged_at: datetime | None) -> None:
        bookmark = session.get(CollectorBookmark, channel)
        if bookmark is None:
            bookmark = CollectorBookmark(channel=channel)
            session.add(bookmark)
        bookmark.last_record_id = record_id
        bookmark.last_logged_at = logged_at
        bookmark.updated_at = utcnow()

    # ------------------------------------------------------------------ batches

    def _ingest_batches(self, spec: SensorSpec, start_after: int, result: IngestionResult) -> None:
        after = start_after
        for _ in range(self.limits.max_batches):
            records = self.reader.read_after(spec.channel, after, spec.event_ids, self.limits.batch_size)
            if not records:
                result.more_pending = False
                return
            after = self._process_batch(spec, records, after, result)
            result.batches += 1
            if len(records) < self.limits.batch_size:
                result.more_pending = False
                return
        result.more_pending = True

    def _process_batch(
        self, spec: SensorSpec, records: list[RawRecord], after: int, result: IngestionResult
    ) -> int:
        rows: list[dict[str, object]] = []
        max_record_id = after
        max_logged_at: datetime | None = None
        ingested_at = utcnow()

        for raw in records:
            result.read += 1
            try:
                parsed = parse_event_xml(
                    raw.xml,
                    max_bytes=self.limits.max_event_xml_bytes,
                    max_field_chars=self.limits.max_field_chars,
                )
            except EventParseError as exc:
                result.parse_failures += 1
                record_id = extract_record_id(raw.xml[: self.limits.max_event_xml_bytes])
                if len(result.errors) < 5:
                    result.errors.append(f"record {record_id}: {exc}")
                if record_id is not None and record_id > max_record_id:
                    max_record_id, max_logged_at = record_id, None
                continue

            if parsed.record_id > max_record_id:
                max_record_id, max_logged_at = parsed.record_id, parsed.time_created

            ctx = NormalizeContext(
                host_id=self.host_id,
                channel=spec.channel,
                raw_xml=raw.xml if self.limits.store_raw_xml else None,
            )
            try:
                event = spec.normalizer(parsed, ctx)
            except Exception as exc:  # normaliser bug or unexpected schema
                result.parse_failures += 1
                logger.exception("Normaliser failed", extra={"sensor": spec.name, "record_id": parsed.record_id})
                if len(result.errors) < 5:
                    result.errors.append(f"record {parsed.record_id}: normaliser {exc.__class__.__name__}")
                continue
            if event is None:
                result.ignored += 1
                continue
            rows.append(_event_row(event, ingested_at))

        with self.session_factory() as session, session.begin():
            inserted = 0
            inserted_ids: list[str] = []
            if rows:
                # executemany with one compiled statement; a multi-row VALUES
                # clause recompiles per batch and dominated ingestion time.
                # RETURNING yields only rows not skipped by ON CONFLICT.
                inserted_ids = list(session.connection().execute(_INSERT_EVENT, rows).scalars())
                inserted = len(inserted_ids)
            if inserted_ids and self.processor is not None:
                self._run_processor(session, spec, inserted_ids, result)
            result.inserted += inserted
            result.duplicates += len(rows) - inserted
            if max_record_id > after:
                self._save_bookmark(session, spec.channel, max_record_id, max_logged_at)

        return max_record_id

    def _run_processor(
        self, session: Session, spec: SensorSpec, event_ids: list[str], result: IngestionResult
    ) -> None:
        """Detection runs in a savepoint: if it fails, the events are still
        stored (and counted for rescan) instead of the batch being retried forever."""
        assert self.processor is not None
        try:
            with session.begin_nested():
                outcome = self.processor.process_event_ids(session, event_ids)
            result.alerts_created += getattr(outcome, "alerts_created", 0)
        except Exception:
            logger.exception("Detection failed for batch", extra={"sensor": spec.name, "events": len(event_ids)})
            result.detection_failures += len(event_ids)

    # ------------------------------------------------------------------- health

    def _record_health(self, spec: SensorSpec, result: IngestionResult, started: datetime) -> None:
        with self.session_factory() as session, session.begin():
            health = session.get(SensorHealth, spec.name)
            if health is None:
                health = SensorHealth(
                    sensor=spec.name,
                    channel=spec.channel,
                    events_ingested=0,
                    duplicates_skipped=0,
                    parse_failures=0,
                    records_ignored=0,
                    records_missed=0,
                    consecutive_failures=0,
                )
                session.add(health)
            health.channel = spec.channel
            health.state = result.state
            health.last_attempt_at = started
            health.events_ingested += result.inserted
            health.duplicates_skipped += result.duplicates
            health.parse_failures += result.parse_failures
            health.records_ignored += result.ignored
            health.records_missed += result.missed
            health.detection_failures = (health.detection_failures or 0) + result.detection_failures

            if result.state == "ok":
                health.last_success_at = utcnow()
                health.consecutive_failures = 0
                notes = []
                if result.parse_failures:
                    notes.append(f"{result.parse_failures} record(s) failed to parse")
                if result.missed:
                    notes.append(f"{result.missed} record(s) lost to log rotation before collection")
                if result.bookmark_reset:
                    notes.append("log was cleared or recreated; bookmark reset")
                if result.detection_failures:
                    notes.append(
                        f"detection failed for {result.detection_failures} event(s); "
                        "run python -m app.detection rescan"
                    )
                health.detail = "; ".join(notes) or None
            else:
                health.last_error_at = utcnow()
                health.consecutive_failures += 1
                health.detail = result.detail
