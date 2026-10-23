from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.base import ChannelAccessDeniedError, ChannelUnavailableError, SensorSpec
from app.collectors.registry import SENSORS
from app.collectors.sysmon import SYSMON_CHANNEL
from app.db.models import CollectorBookmark, Event, SensorHealth
from app.services.ingestion import IngestionLimits, IngestionService, dedup_key
from tests.helpers import BASE_TIME, FakeEventLogReader, load_fixture

SYSMON = SENSORS["sysmon"]
SYSTEM = SENSORS["system"]
PROCESS_XML = load_fixture("sysmon_1_process_create.xml")
NETWORK_XML = load_fixture("sysmon_3_network.xml")


def make_service(
    reader: FakeEventLogReader, session_factory: sessionmaker[Session], **limits: object
) -> IngestionService:
    return IngestionService(reader, session_factory, host_id="host-1", limits=IngestionLimits(**limits))  # type: ignore[arg-type]


def count_events(session_factory: sessionmaker[Session]) -> int:
    with session_factory() as session:
        return session.scalar(select(func.count()).select_from(Event)) or 0


def bookmark(session_factory: sessionmaker[Session], channel: str = SYSMON_CHANNEL) -> CollectorBookmark | None:
    with session_factory() as session:
        return session.get(CollectorBookmark, channel)


def health(session_factory: sessionmaker[Session], sensor: str = "sysmon") -> SensorHealth:
    with session_factory() as session:
        row = session.get(SensorHealth, sensor)
        assert row is not None
        return row


def seed(reader: FakeEventLogReader, ids: range, xml: str = PROCESS_XML) -> None:
    for record_id in ids:
        reader.add(SYSMON_CHANNEL, xml, record_id)


# --------------------------------------------------------------- happy path


def test_first_run_reads_retained_history(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 6))

    result = make_service(reader, session_factory).ingest(SYSMON)

    assert (result.state, result.read, result.inserted, result.duplicates) == ("ok", 5, 5, 0)
    assert count_events(session_factory) == 5
    mark = bookmark(session_factory)
    assert mark is not None and mark.last_record_id == 5
    assert mark.last_logged_at == BASE_TIME + timedelta(seconds=5)
    row = health(session_factory)
    assert row.state == "ok" and row.events_ingested == 5 and row.last_success_at is not None


def test_resumes_from_bookmark_and_reads_only_new_records(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 4))
    service = make_service(reader, session_factory)
    service.ingest(SYSMON)

    idle = service.ingest(SYSMON)
    assert (idle.read, idle.inserted) == (0, 0)

    seed(reader, range(4, 7))
    result = service.ingest(SYSMON)
    assert (result.read, result.inserted) == (3, 3)
    assert count_events(session_factory) == 6
    assert health(session_factory).events_ingested == 6


def test_restart_with_new_service_instance_uses_durable_bookmark(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 4))
    make_service(reader, session_factory).ingest(SYSMON)

    seed(reader, range(4, 5))
    result = make_service(reader, session_factory).ingest(SYSMON)  # simulated process restart
    assert (result.read, result.inserted) == (1, 1)


def test_start_at_newest_when_history_disabled(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 11))
    service = make_service(reader, session_factory, read_history=False)

    first = service.ingest(SYSMON)
    assert first.inserted == 0
    mark = bookmark(session_factory)
    assert mark is not None and mark.last_record_id == 10

    seed(reader, range(11, 13))
    assert service.ingest(SYSMON).inserted == 2


# ------------------------------------------------------------- duplicates


def test_reprocessing_after_crash_does_not_duplicate(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 6))
    service = make_service(reader, session_factory)
    service.ingest(SYSMON)

    # Simulate a crash where events 3..5 were stored but the bookmark still
    # points at record 2 (as it would if the commit had been split).
    with session_factory() as session, session.begin():
        mark = session.get(CollectorBookmark, SYSMON_CHANNEL)
        assert mark is not None
        mark.last_record_id = 2
        mark.last_logged_at = reader.logged_at(SYSMON_CHANNEL, 2)

    result = service.ingest(SYSMON)
    assert (result.read, result.inserted, result.duplicates) == (3, 0, 3)
    assert count_events(session_factory) == 5
    assert health(session_factory).duplicates_skipped == 3


def test_inconsistent_bookmark_triggers_reread_without_duplicates(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 6))
    service = make_service(reader, session_factory)
    service.ingest(SYSMON)

    # Bookmark ID rewound but timestamp left at record 5: looks like a cleared log.
    with session_factory() as session, session.begin():
        session.get(CollectorBookmark, SYSMON_CHANNEL).last_record_id = 2  # type: ignore[union-attr]

    result = service.ingest(SYSMON)
    assert result.bookmark_reset is True
    assert (result.read, result.inserted, result.duplicates) == (5, 0, 5)


def test_dedup_key_depends_on_logged_at() -> None:
    a = dedup_key("h", "c", 7, BASE_TIME, 1)
    assert a == dedup_key("h", "c", 7, BASE_TIME, 1)
    assert a != dedup_key("h", "c", 7, BASE_TIME + timedelta(microseconds=1), 1)
    assert a != dedup_key("other-host", "c", 7, BASE_TIME, 1)


# ---------------------------------------------------- bad and unwanted input


def test_malformed_record_is_counted_and_skipped(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 3))
    reader.add_raw(SYSMON_CHANNEL, load_fixture("hostile_malformed.xml").replace("5003", "3"), 3)
    seed(reader, range(4, 5))

    result = make_service(reader, session_factory).ingest(SYSMON)

    assert (result.state, result.read, result.inserted, result.parse_failures) == ("ok", 4, 3, 1)
    mark = bookmark(session_factory)
    assert mark is not None and mark.last_record_id == 4  # poison record did not block the channel
    row = health(session_factory)
    assert row.parse_failures == 1
    assert row.detail is not None and "failed to parse" in row.detail


def test_entity_expansion_record_is_rejected_not_expanded(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    reader.add_raw(SYSMON_CHANNEL, load_fixture("hostile_billion_laughs.xml").replace("5001", "1"), 1)
    result = make_service(reader, session_factory).ingest(SYSMON)
    assert (result.parse_failures, result.inserted) == (1, 0)


def test_oversized_record_is_rejected(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 2))
    reader.add(SYSMON_CHANNEL, PROCESS_XML.replace("/silent", "/silent " + "A" * 10_000), 2)

    result = make_service(reader, session_factory, max_event_xml_bytes=8192).ingest(SYSMON)
    assert (result.inserted, result.parse_failures) == (1, 1)


def test_ignored_events_counted(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    reader.add(SYSMON_CHANNEL, load_fixture("sysmon_24_clipboard.xml"), 1)
    seed(reader, range(2, 3))

    result = make_service(reader, session_factory).ingest(SYSMON)
    assert (result.inserted, result.ignored) == (1, 1)
    assert health(session_factory).records_ignored == 1


def test_normaliser_exception_does_not_stop_ingestion(session_factory: sessionmaker[Session]) -> None:
    def explode(parsed, ctx):  # type: ignore[no-untyped-def]
        if parsed.record_id == 2:
            raise KeyError("boom")
        return SYSMON.normalizer(parsed, ctx)

    spec = SensorSpec(name="sysmon", channel=SYSMON_CHANNEL, source=SYSMON.source, normalizer=explode)
    reader = FakeEventLogReader()
    seed(reader, range(1, 4))

    result = make_service(reader, session_factory).ingest(spec)
    assert (result.state, result.inserted, result.parse_failures) == ("ok", 2, 1)


def test_raw_xml_not_stored_when_disabled(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 2))
    make_service(reader, session_factory, store_raw_xml=False).ingest(SYSMON)
    with session_factory() as session:
        assert session.scalar(select(Event.raw_xml)) is None


# --------------------------------------------------- rotation and clearing


def test_records_lost_to_rotation_are_reported(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 6))
    service = make_service(reader, session_factory)
    service.ingest(SYSMON)

    seed(reader, range(6, 21))
    reader.drop_older_than(SYSMON_CHANNEL, 10)  # records 6..9 overwritten before collection

    result = service.ingest(SYSMON)
    assert (result.missed, result.inserted) == (4, 11)
    row = health(session_factory)
    assert row.records_missed == 4
    assert row.detail is not None and "lost to log rotation" in row.detail


def test_cleared_log_with_lower_record_ids_resets_bookmark(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(100, 105))
    service = make_service(reader, session_factory)
    service.ingest(SYSMON)

    reader.clear(SYSMON_CHANNEL)
    for record_id in range(1, 4):  # new numbering, later timestamps
        reader.add(SYSMON_CHANNEL, PROCESS_XML, record_id, BASE_TIME + timedelta(hours=1, seconds=record_id))

    result = service.ingest(SYSMON)
    assert result.bookmark_reset is True
    assert result.inserted == 3
    assert count_events(session_factory) == 8
    mark = bookmark(session_factory)
    assert mark is not None and mark.last_record_id == 3


def test_cleared_log_that_regrew_past_bookmark_is_detected(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 4))
    service = make_service(reader, session_factory)
    service.ingest(SYSMON)

    reader.clear(SYSMON_CHANNEL)
    for record_id in range(1, 7):  # regrew beyond old bookmark (3) with different timestamps
        reader.add(SYSMON_CHANNEL, PROCESS_XML, record_id, BASE_TIME + timedelta(days=1, seconds=record_id))

    result = service.ingest(SYSMON)
    assert result.bookmark_reset is True
    assert result.inserted == 6  # records 1..3 are new events, not duplicates


def test_empty_channel_is_ok(session_factory: sessionmaker[Session]) -> None:
    result = make_service(FakeEventLogReader(), session_factory).ingest(SYSMON)
    assert (result.state, result.read) == ("ok", 0)


# ------------------------------------------------------------ availability


def test_missing_channel_reported_as_unavailable(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader(errors={SYSMON_CHANNEL: ChannelUnavailableError(SYSMON_CHANNEL)})
    service = make_service(reader, session_factory)

    first = service.ingest(SYSMON)
    service.ingest(SYSMON)

    assert first.state == "unavailable"
    row = health(session_factory)
    assert row.state == "unavailable"
    assert row.detail is not None and "Sysmon" in row.detail
    assert row.consecutive_failures == 2
    assert row.last_success_at is None


def test_access_denied_reported(session_factory: sessionmaker[Session]) -> None:
    security = SENSORS["security"]
    reader = FakeEventLogReader(errors={"Security": ChannelAccessDeniedError("Security")})
    result = make_service(reader, session_factory).ingest(security)
    assert result.state == "access_denied"
    assert "Event Log Readers" in (health(session_factory, "security").detail or "")


def test_recovery_resets_failure_counter(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader(errors={SYSMON_CHANNEL: ChannelUnavailableError(SYSMON_CHANNEL)})
    service = make_service(reader, session_factory)
    service.ingest(SYSMON)

    reader.errors.clear()
    seed(reader, range(1, 3))
    service.ingest(SYSMON)
    row = health(session_factory)
    assert (row.state, row.consecutive_failures, row.detail) == ("ok", 0, None)


def test_unexpected_reader_error_is_contained(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader(errors={SYSMON_CHANNEL: RuntimeError("handle closed")})
    result = make_service(reader, session_factory).ingest(SYSMON)
    assert result.state == "error"
    assert "handle closed" in (health(session_factory).detail or "")


# ------------------------------------------------------- batching/filtering


def test_batches_are_bounded_per_cycle(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    seed(reader, range(1, 11))
    service = make_service(reader, session_factory, batch_size=3, max_batches=2)

    first = service.ingest(SYSMON)
    assert (first.inserted, first.batches, first.more_pending) == (6, 2, True)

    second = service.ingest(SYSMON)
    assert (second.inserted, second.more_pending) == (4, False)
    assert count_events(session_factory) == 10


def test_event_id_filter_applied(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    reader.add("System", load_fixture("system_7045_service_install.xml"), 10)
    reader.add("System", NETWORK_XML.replace("Microsoft-Windows-Sysmon", "Other"), 11)  # EventID 3: filtered out
    reader.add("System", load_fixture("system_104_log_cleared.xml"), 12)

    result = make_service(reader, session_factory).ingest(SYSTEM)
    assert (result.read, result.inserted) == (2, 2)


def test_stored_event_round_trip(session_factory: sessionmaker[Session]) -> None:
    reader = FakeEventLogReader()
    reader.add(SYSMON_CHANNEL, PROCESS_XML, 1)
    make_service(reader, session_factory).ingest(SYSMON)

    with session_factory() as session:
        event = session.scalars(select(Event)).one()
    assert event.timestamp.tzinfo is not None
    assert event.category == "process_creation"
    assert event.collection_status == "complete"
    assert event.host_id == "host-1"
    assert event.raw_xml is not None and "<EventRecordID>1</EventRecordID>" in event.raw_xml
