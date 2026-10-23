from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.registry import SENSORS
from app.collectors.sysmon import SYSMON_CHANNEL
from app.db.models import Event
from app.services.ingestion import IngestionService
from app.services.retention import apply_retention
from tests.helpers import BASE_TIME, FakeEventLogReader, load_fixture


def seed_events(session_factory: sessionmaker[Session], count: int) -> None:
    reader = FakeEventLogReader()
    for record_id in range(1, count + 1):
        reader.add(SYSMON_CHANNEL, load_fixture("sysmon_1_process_create.xml"), record_id)
    IngestionService(reader, session_factory, host_id="host-1").ingest(SENSORS["sysmon"])


def set_ingested_at(session_factory: sessionmaker[Session], ages_days: list[int]) -> None:
    with session_factory() as session, session.begin():
        for event, age in zip(session.scalars(select(Event).order_by(Event.record_id)), ages_days):
            event.ingested_at = BASE_TIME - timedelta(days=age)


def remaining_record_ids(session_factory: sessionmaker[Session]) -> list[int]:
    with session_factory() as session:
        return list(session.scalars(select(Event.record_id).order_by(Event.record_id)))


def test_expired_events_are_purged(session_factory: sessionmaker[Session]) -> None:
    seed_events(session_factory, 4)
    set_ingested_at(session_factory, [40, 31, 29, 1])

    with session_factory() as session:
        result = apply_retention(session, retention_days=30, max_rows=1000, now=BASE_TIME)

    assert result.expired == 2
    assert remaining_record_ids(session_factory) == [3, 4]


def test_row_cap_removes_oldest_ingested(session_factory: sessionmaker[Session]) -> None:
    seed_events(session_factory, 5)
    set_ingested_at(session_factory, [5, 4, 3, 2, 1])

    with session_factory() as session:
        result = apply_retention(session, retention_days=30, max_rows=2, now=BASE_TIME)
        total = session.scalar(select(func.count()).select_from(Event))

    assert (result.expired, result.over_cap, total) == (0, 3, 2)
    assert remaining_record_ids(session_factory) == [4, 5]
