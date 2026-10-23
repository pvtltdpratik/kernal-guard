from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.collectors.xml_parser import (
    EventParseError,
    OversizedEventError,
    extract_record_id,
    parse_event_xml,
    parse_windows_time,
)
from tests.helpers import load_fixture

LIMITS = {"max_bytes": 256 * 1024, "max_field_chars": 8192}


def test_parses_system_fields_and_event_data() -> None:
    parsed = parse_event_xml(load_fixture("sysmon_1_process_create.xml"), **LIMITS)

    assert parsed.provider == "Microsoft-Windows-Sysmon"
    assert parsed.event_id == 1
    assert parsed.record_id == 1001
    assert parsed.time_created == datetime(2026, 10, 20, 9, 15, 2, 456789, tzinfo=timezone.utc)
    assert parsed.channel == "Microsoft-Windows-Sysmon/Operational"
    assert parsed.computer == "WORKSTATION01"
    assert parsed.data["Image"] == r"C:\Users\alice\AppData\Local\Temp\updater.exe"
    assert parsed.data["ParentProcessId"] == "5120"
    assert parsed.truncated_fields == []


def test_flattens_user_data_events() -> None:
    parsed = parse_event_xml(load_fixture("system_104_log_cleared.xml"), **LIMITS)
    assert parsed.data["SubjectUserName"] == "alice"
    assert parsed.data["Channel"] == "Application"
    assert parsed.data["BackupPath"] is None


@pytest.mark.parametrize(
    "fixture", ["hostile_billion_laughs.xml", "hostile_external_entity.xml", "hostile_malformed.xml"]
)
def test_rejects_hostile_or_malformed_xml(fixture: str) -> None:
    with pytest.raises(EventParseError):
        parse_event_xml(load_fixture(fixture), **LIMITS)


def test_external_entity_content_never_appears() -> None:
    with pytest.raises(EventParseError) as info:
        parse_event_xml(load_fixture("hostile_external_entity.xml"), **LIMITS)
    assert "fonts" not in str(info.value).lower()  # win.ini content


def test_rejects_oversized_event_before_parsing() -> None:
    xml = load_fixture("sysmon_1_process_create.xml")
    with pytest.raises(OversizedEventError):
        parse_event_xml(xml, max_bytes=len(xml) - 1, max_field_chars=8192)


def test_caps_long_field_values_and_reports_them() -> None:
    xml = load_fixture("sysmon_1_process_create.xml").replace("/silent", "/silent " + "A" * 500)
    parsed = parse_event_xml(xml, max_bytes=256 * 1024, max_field_chars=300)
    assert parsed.data["CommandLine"] is not None and len(parsed.data["CommandLine"]) == 300
    assert parsed.truncated_fields == ["CommandLine"]


def test_rejects_non_event_root() -> None:
    with pytest.raises(EventParseError, match="root"):
        parse_event_xml("<Other xmlns='http://schemas.microsoft.com/win/2004/08/events/event'/>", **LIMITS)


def test_rejects_event_without_record_id() -> None:
    xml = load_fixture("sysmon_3_network.xml").replace("<EventRecordID>1003</EventRecordID>", "")
    with pytest.raises(EventParseError, match="EventRecordID"):
        parse_event_xml(xml, **LIMITS)


def test_duplicate_data_names_are_preserved() -> None:
    xml = load_fixture("sysmon_3_network.xml").replace(
        "</EventData>", "<Data Name='SourcePort'>1</Data></EventData>"
    )
    parsed = parse_event_xml(xml, **LIMITS)
    assert parsed.data["SourcePort"] == "51544"
    assert parsed.data["SourcePort_2"] == "1"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-07-29T14:28:07.1834784Z", datetime(2026, 7, 29, 14, 28, 7, 183478, tzinfo=timezone.utc)),
        ("2026-10-20 09:15:02.451", datetime(2026, 10, 20, 9, 15, 2, 451000, tzinfo=timezone.utc)),
        ("2026-10-20T09:00:00Z", datetime(2026, 10, 20, 9, 0, 0, tzinfo=timezone.utc)),
    ],
)
def test_parse_windows_time(value: str, expected: datetime) -> None:
    assert parse_windows_time(value) == expected


def test_parse_windows_time_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_windows_time("yesterday")


def test_extract_record_id_from_broken_xml() -> None:
    assert extract_record_id(load_fixture("hostile_malformed.xml")) == 5003
    assert extract_record_id("<nothing/>") is None
