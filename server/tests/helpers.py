"""Test helpers: fixture loading and an in-memory EventLogReader."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.collectors.base import RawRecord, RecordMarker

FIXTURES = Path(__file__).parent / "fixtures" / "events"

_EVENT_ID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def windows_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def with_record(xml: str, record_id: int, logged_at: datetime) -> str:
    """Return a copy of fixture XML re-stamped with a new record ID and TimeCreated."""
    xml = re.sub(r"<EventRecordID>\d+</EventRecordID>", f"<EventRecordID>{record_id}</EventRecordID>", xml)
    return re.sub(r"<TimeCreated SystemTime='[^']+'/>", f"<TimeCreated SystemTime='{windows_time(logged_at)}'/>", xml)


BASE_TIME = datetime(2026, 10, 20, 9, 0, 0, tzinfo=timezone.utc)

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&apos;")


def build_event(
    event_id: int,
    fields: dict[str, str],
    provider: str = "Microsoft-Windows-Sysmon",
    channel: str = "Microsoft-Windows-Sysmon/Operational",
) -> str:
    """Synthetic event XML in EvtRender format. Without a UtcTime field, the
    event timestamp equals TimeCreated, which FakeEventLogReader.add controls."""
    data = "".join(f"<Data Name='{k}'>{_escape(v)}</Data>" for k, v in fields.items())
    return (
        f"<Event xmlns='{_NS}'><System><Provider Name='{provider}'/><EventID>{event_id}</EventID>"
        f"<TimeCreated SystemTime='2026-10-20T09:00:00.0000000Z'/><EventRecordID>1</EventRecordID>"
        f"<Channel>{channel}</Channel><Computer>WORKSTATION01</Computer></System>"
        f"<EventData>{data}</EventData></Event>"
    )


TEMP_EXE = r"C:\Users\alice\AppData\Local\Temp\updater.exe"
GUID_A = "{aaaaaaaa-0000-0000-0000-000000000001}"
GUID_B = "{bbbbbbbb-0000-0000-0000-000000000002}"
GUID_C = "{cccccccc-0000-0000-0000-000000000003}"
GUID_PARENT = "{eeeeeeee-0000-0000-0000-00000000000e}"


def proc_create(guid: str = GUID_A, pid: int = 7432, image: str = TEMP_EXE, parent_guid: str = GUID_PARENT,
                parent_image: str = r"C:\Windows\explorer.exe", **extra: str) -> str:
    return build_event(1, {"ProcessGuid": guid, "ProcessId": str(pid), "Image": image,
                           "CommandLine": f'"{image}"', "User": r"WORKSTATION01\alice",
                           "ParentProcessGuid": parent_guid, "ParentProcessId": "5120",
                           "ParentImage": parent_image, **extra})


def network(guid: str = GUID_A, pid: int = 7432, image: str = TEMP_EXE, ip: str = "93.184.215.14",
            initiated: str = "true") -> str:
    return build_event(3, {"ProcessGuid": guid, "ProcessId": str(pid), "Image": image, "Protocol": "tcp",
                           "Initiated": initiated, "SourceIp": "192.168.1.23", "SourcePort": "51544",
                           "DestinationIp": ip, "DestinationHostname": "-", "DestinationPort": "443"})


def registry_set(target: str, details: str, guid: str = GUID_A, image: str = TEMP_EXE) -> str:
    return build_event(13, {"EventType": "SetValue", "ProcessGuid": guid, "ProcessId": "7432", "Image": image,
                            "TargetObject": target, "Details": details})


def file_create(target: str, guid: str = GUID_A, image: str = TEMP_EXE) -> str:
    return build_event(11, {"ProcessGuid": guid, "ProcessId": "7432", "Image": image, "TargetFilename": target})


def image_load(dll: str, guid: str, image: str, signed: str = "false") -> str:
    return build_event(7, {"ProcessGuid": guid, "ProcessId": "100", "Image": image, "ImageLoaded": dll,
                           "Signed": signed, "Signature": "-" if signed == "false" else "Microsoft Windows",
                           "SignatureStatus": "Unavailable" if signed == "false" else "Valid"})


def process_access(target_image: str, access: str, call_trace: str = r"C:\Windows\SYSTEM32\ntdll.dll+9d4c4",
                   guid: str = GUID_A, image: str = TEMP_EXE) -> str:
    return build_event(10, {"SourceProcessGUID": guid, "SourceProcessId": "7432", "SourceThreadId": "1",
                            "SourceImage": image, "TargetProcessGUID": GUID_C, "TargetProcessId": "720",
                            "TargetImage": target_image, "GrantedAccess": access, "CallTrace": call_trace})


def service_install(name: str, image_path: str) -> str:
    return build_event(7045, {"ServiceName": name, "ImagePath": image_path, "ServiceType": "user mode service",
                              "StartType": "auto start", "AccountName": "LocalSystem"},
                       provider="Service Control Manager", channel="System")


@dataclass
class StoredRecord:
    record_id: int
    logged_at: datetime
    xml: str
    event_id: int


@dataclass
class FakeEventLogReader:
    """Mimics wevtapi semantics: records ordered by ID, filterable by event ID."""

    channels: dict[str, list[StoredRecord]] = field(default_factory=dict)
    errors: dict[str, Exception] = field(default_factory=dict)
    read_calls: int = 0

    def add(self, channel: str, xml: str, record_id: int, logged_at: datetime | None = None) -> StoredRecord:
        logged_at = logged_at or BASE_TIME + timedelta(seconds=record_id)
        stamped = with_record(xml, record_id, logged_at)
        match = _EVENT_ID.search(stamped)
        record = StoredRecord(record_id, logged_at, stamped, int(match.group(1)) if match else 0)
        self.channels.setdefault(channel, []).append(record)
        self.channels[channel].sort(key=lambda r: r.record_id)
        return record

    def add_raw(self, channel: str, xml: str, record_id: int, event_id: int = 1) -> None:
        """Add a record whose XML is stored verbatim (e.g. malformed input)."""
        self.channels.setdefault(channel, []).append(StoredRecord(record_id, BASE_TIME, xml, event_id))
        self.channels[channel].sort(key=lambda r: r.record_id)

    def clear(self, channel: str) -> None:
        self.channels[channel] = []

    def drop_older_than(self, channel: str, record_id: int) -> None:
        """Simulate log rotation overwriting the oldest records."""
        self.channels[channel] = [r for r in self.channels[channel] if r.record_id >= record_id]

    def _records(self, channel: str) -> list[StoredRecord]:
        if channel in self.errors:
            raise self.errors[channel]
        return self.channels.get(channel, [])

    def oldest(self, channel: str) -> RecordMarker | None:
        records = self._records(channel)
        return RecordMarker(records[0].record_id, records[0].logged_at) if records else None

    def newest(self, channel: str) -> RecordMarker | None:
        records = self._records(channel)
        return RecordMarker(records[-1].record_id, records[-1].logged_at) if records else None

    def logged_at(self, channel: str, record_id: int) -> datetime | None:
        for record in self._records(channel):
            if record.record_id == record_id:
                return record.logged_at
        return None

    def read_after(
        self, channel: str, after_record_id: int, event_ids: frozenset[int] | None, max_records: int
    ) -> list[RawRecord]:
        self.read_calls += 1
        matching = [
            r for r in self._records(channel)
            if r.record_id > after_record_id and (not event_ids or r.event_id in event_ids)
        ]
        return [RawRecord(xml=r.xml) for r in matching[:max_records]]
