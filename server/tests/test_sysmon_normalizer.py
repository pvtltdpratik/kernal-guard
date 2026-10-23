from __future__ import annotations

from datetime import datetime, timezone

from app.collectors.base import NormalizeContext
from app.collectors.sysmon import SYSMON_CHANNEL, normalize_sysmon
from app.collectors.xml_parser import parse_event_xml
from app.schemas.events import CollectionStatus, EventCategory, EventSource, NormalizedEvent
from tests.helpers import load_fixture

PROC_GUID = "{3f1b2c4d-1a2b-6716-0b04-000000002b00}"
TEMP_IMAGE = r"C:\Users\alice\AppData\Local\Temp\updater.exe"


def normalize(fixture: str, max_field_chars: int = 8192, xml: str | None = None) -> NormalizedEvent | None:
    raw = xml if xml is not None else load_fixture(fixture)
    parsed = parse_event_xml(raw, max_bytes=256 * 1024, max_field_chars=max_field_chars)
    return normalize_sysmon(parsed, NormalizeContext(host_id="host-1", channel=SYSMON_CHANNEL, raw_xml=raw))


def test_process_creation() -> None:
    event = normalize("sysmon_1_process_create.xml")
    assert event is not None
    assert event.source == EventSource.SYSMON
    assert event.category == EventCategory.PROCESS_CREATION
    assert event.process_guid == PROC_GUID
    assert event.process_id == 7432
    assert event.image == TEMP_IMAGE
    assert event.parent_process_id == 5120
    assert event.parent_image == r"C:\Windows\explorer.exe"
    assert event.user == r"WORKSTATION01\alice"
    assert event.sha256 == "3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a"
    assert event.md5 == "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    assert event.imphash == "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    # Activity time comes from Sysmon's UtcTime; logged_at from TimeCreated.
    assert event.timestamp == datetime(2026, 10, 20, 9, 15, 2, 451000, tzinfo=timezone.utc)
    assert event.logged_at == datetime(2026, 10, 20, 9, 15, 2, 456789, tzinfo=timezone.utc)
    assert event.collection_status == CollectionStatus.COMPLETE
    assert event.missing_fields == []
    assert event.data["CommandLine"].endswith("/silent")
    # Signature fields are not reported by Sysmon event 1; they must stay unknown.
    assert event.signed is None and event.signature is None


def test_network_connection() -> None:
    event = normalize("sysmon_3_network.xml")
    assert event is not None
    assert event.category == EventCategory.NETWORK_CONNECTION
    assert event.process_guid == PROC_GUID
    assert event.data["DestinationIp"] == "203.0.113.50"
    assert event.sha256 is None


def test_driver_load_has_no_process_but_has_signature() -> None:
    event = normalize("sysmon_6_driver_load.xml")
    assert event is not None
    assert event.category == EventCategory.DRIVER_LOAD
    assert event.process_id is None and event.image is None
    assert event.signed is True
    assert event.signature == "Example Hardware Vendor Inc."
    assert event.signature_status == "Valid"
    assert event.sha256 == "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233"


def test_unsigned_image_load() -> None:
    event = normalize("sysmon_7_image_load_unsigned.xml")
    assert event is not None
    assert event.category == EventCategory.IMAGE_LOAD
    assert event.image == TEMP_IMAGE  # loading process
    assert event.data["ImageLoaded"].endswith("hook.dll")
    assert event.signed is False
    assert event.signature is None  # '-' placeholder treated as absent
    assert event.signature_status == "Unavailable"


def test_remote_thread_uses_source_process() -> None:
    event = normalize("sysmon_8_remote_thread.xml")
    assert event is not None
    assert event.category == EventCategory.REMOTE_THREAD
    assert event.process_guid == PROC_GUID
    assert event.process_id == 7432
    assert event.data["TargetImage"] == r"C:\Windows\explorer.exe"


def test_process_access_uses_upper_case_guid_fields() -> None:
    event = normalize("sysmon_10_process_access.xml")
    assert event is not None
    assert event.category == EventCategory.PROCESS_ACCESS
    assert event.process_guid == PROC_GUID
    assert event.data["GrantedAccess"] == "0x1010"
    assert event.collection_status == CollectionStatus.COMPLETE


def test_file_create_and_registry_set() -> None:
    file_event = normalize("sysmon_11_file_create.xml")
    registry_event = normalize("sysmon_13_registry_set.xml")
    assert file_event is not None and file_event.category == EventCategory.FILE_CREATE
    assert registry_event is not None and registry_event.category == EventCategory.REGISTRY_VALUE_SET
    assert "CurrentVersion\\Run" in registry_event.data["TargetObject"]


def test_missing_required_fields_marked_partial() -> None:
    event = normalize("sysmon_1_missing_fields.xml")
    assert event is not None
    assert event.collection_status == CollectionStatus.PARTIAL
    assert set(event.missing_fields) == {"ProcessGuid", "Image"}
    assert event.process_id == 812
    assert event.image is None
    assert event.sha256 is None  # malformed hash is dropped, not stored


def test_truncated_values_marked() -> None:
    xml = load_fixture("sysmon_1_process_create.xml").replace("/silent", "/silent " + "A" * 500)
    event = normalize("", max_field_chars=300, xml=xml)
    assert event is not None
    assert event.collection_status == CollectionStatus.TRUNCATED
    assert event.data["_kg_truncated"] == ["CommandLine"]


def test_clipboard_events_are_not_collected() -> None:
    assert normalize("sysmon_24_clipboard.xml") is None


def test_events_from_other_providers_ignored() -> None:
    xml = load_fixture("sysmon_1_process_create.xml").replace(
        "Name='Microsoft-Windows-Sysmon'", "Name='Some-Other-Provider'"
    )
    assert normalize("", xml=xml) is None


def test_unknown_event_id_kept_as_other() -> None:
    xml = load_fixture("sysmon_3_network.xml").replace("<EventID>3</EventID>", "<EventID>99</EventID>")
    event = normalize("", xml=xml)
    assert event is not None
    assert event.category == EventCategory.OTHER
    assert event.source_event_id == 99
