from __future__ import annotations

from app.collectors.base import NormalizeContext
from app.collectors.windows_eventlog import normalize_windows_event
from app.collectors.xml_parser import parse_event_xml
from app.schemas.events import CollectionStatus, EventCategory, EventSource, NormalizedEvent
from tests.helpers import load_fixture


def normalize(fixture: str, channel: str, xml: str | None = None) -> NormalizedEvent | None:
    raw = xml if xml is not None else load_fixture(fixture)
    parsed = parse_event_xml(raw, max_bytes=256 * 1024, max_field_chars=8192)
    return normalize_windows_event(parsed, NormalizeContext(host_id="host-1", channel=channel, raw_xml=None))


def test_service_install_7045() -> None:
    event = normalize("system_7045_service_install.xml", "System")
    assert event is not None
    assert event.source == EventSource.WINDOWS_EVENTLOG
    assert event.category == EventCategory.SERVICE_INSTALL
    assert event.data["ImagePath"] == '"C:\\Program Files\\Example\\svc.exe"'
    # services.exe logs the event; it is not the installer, so nothing is promoted.
    assert event.process_id is None and event.image is None
    assert event.collection_status == CollectionStatus.COMPLETE


def test_log_cleared_104() -> None:
    event = normalize("system_104_log_cleared.xml", "System")
    assert event is not None
    assert event.category == EventCategory.LOG_CLEARED
    assert event.user == "WORKSTATION01\\alice"
    assert event.data["Channel"] == "Application"


def test_security_process_creation_4688_hex_pids() -> None:
    event = normalize("security_4688_process_create.xml", "Security")
    assert event is not None
    assert event.category == EventCategory.PROCESS_CREATION
    assert event.process_id == 0x1D08
    assert event.parent_process_id == 0x1400
    assert event.image == r"C:\Users\alice\AppData\Local\Temp\updater.exe"
    assert event.parent_image == r"C:\Windows\explorer.exe"
    assert event.user == "WORKSTATION01\\alice"
    # 4688 has no process GUID; correlation must fall back to PID + time.
    assert event.process_guid is None


def test_unhandled_provider_event_pair_ignored() -> None:
    xml = load_fixture("system_7045_service_install.xml").replace(
        "Name='Service Control Manager'", "Name='Spoofed-Provider'"
    )
    assert normalize("", "System", xml=xml) is None
