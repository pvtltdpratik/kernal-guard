"""Sysmon (Microsoft-Windows-Sysmon/Operational) normalisation.

Each Sysmon event ID maps to a category and tells us which fields carry the
acting process and which file the hash/signature columns describe:

- Process fields hold the *acting* process (for 8/10, the source process).
- Hash/signature columns describe the event's *subject file*: the process
  image for event 1, the loaded module for 6/7, the deleted file for 23/26.

All original EventData fields are preserved in ``data``.

Reference: https://learn.microsoft.com/sysinternals/downloads/sysmon#events
"""

from __future__ import annotations

from dataclasses import dataclass

from app.collectors.base import NormalizeContext
from app.collectors.fields import clean, parse_hashes, to_bool, to_int
from app.collectors.xml_parser import ParsedEvent, parse_windows_time
from app.schemas.events import CollectionStatus, EventCategory, EventSource, NormalizedEvent

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


@dataclass(frozen=True)
class _Spec:
    category: EventCategory
    guid: str | None = "ProcessGuid"
    pid: str | None = "ProcessId"
    image: str | None = "Image"
    user: str | None = "User"
    parent_guid: str | None = None
    parent_pid: str | None = None
    parent_image: str | None = None
    hashes: str | None = None
    signature: bool = False
    required: tuple[str, ...] = ("ProcessGuid", "ProcessId", "Image")



_SPECS: dict[int, _Spec] = {
    1: _Spec(
        EventCategory.PROCESS_CREATION,
        parent_guid="ParentProcessGuid",
        parent_pid="ParentProcessId",
        parent_image="ParentImage",
        hashes="Hashes",
    ),
    2: _Spec(EventCategory.FILE_TIME_CHANGE, required=("ProcessGuid", "TargetFilename")),
    3: _Spec(EventCategory.NETWORK_CONNECTION, required=("ProcessGuid", "DestinationIp", "DestinationPort")),
    4: _Spec(EventCategory.SENSOR_STATE, guid=None, pid=None, image=None, user=None, required=("State",)),
    5: _Spec(EventCategory.PROCESS_TERMINATION),
    6: _Spec(
        EventCategory.DRIVER_LOAD, guid=None, pid=None, image=None, user=None,
        hashes="Hashes", signature=True, required=("ImageLoaded",),
    ),
    7: _Spec(
        EventCategory.IMAGE_LOAD, hashes="Hashes", signature=True,
        required=("ProcessGuid", "Image", "ImageLoaded"),
    ),
    8: _Spec(
        EventCategory.REMOTE_THREAD, guid="SourceProcessGuid", pid="SourceProcessId",
        image="SourceImage", user="SourceUser",
        required=("SourceProcessGuid", "TargetProcessGuid", "SourceImage", "TargetImage"),
    ),
    9: _Spec(EventCategory.RAW_ACCESS_READ, required=("ProcessGuid", "Device")),
    # Note Sysmon spells these GUID in upper case for event 10.
    10: _Spec(
        EventCategory.PROCESS_ACCESS, guid="SourceProcessGUID", pid="SourceProcessId",
        image="SourceImage", user="SourceUser",
        required=("SourceProcessGUID", "TargetProcessGUID", "SourceImage", "TargetImage", "GrantedAccess"),
    ),
    11: _Spec(EventCategory.FILE_CREATE, required=("ProcessGuid", "TargetFilename")),
    12: _Spec(EventCategory.REGISTRY_KEY, required=("ProcessGuid", "TargetObject", "EventType")),
    13: _Spec(EventCategory.REGISTRY_VALUE_SET, required=("ProcessGuid", "TargetObject")),
    14: _Spec(EventCategory.REGISTRY_RENAME, required=("ProcessGuid", "TargetObject", "NewName")),
    15: _Spec(EventCategory.FILE_STREAM, hashes="Hash", required=("ProcessGuid", "TargetFilename")),
    16: _Spec(EventCategory.SENSOR_STATE, guid=None, pid=None, image=None, user=None, required=("Configuration",)),
    17: _Spec(EventCategory.PIPE, required=("ProcessGuid", "PipeName")),
    18: _Spec(EventCategory.PIPE, required=("ProcessGuid", "PipeName")),
    19: _Spec(EventCategory.WMI, guid=None, pid=None, image=None, required=("EventType",)),
    20: _Spec(EventCategory.WMI, guid=None, pid=None, image=None, required=("EventType",)),
    21: _Spec(EventCategory.WMI, guid=None, pid=None, image=None, required=("EventType",)),
    22: _Spec(EventCategory.DNS_QUERY, required=("ProcessGuid", "QueryName")),
    23: _Spec(EventCategory.FILE_DELETE, hashes="Hashes", required=("ProcessGuid", "TargetFilename")),
    25: _Spec(EventCategory.PROCESS_TAMPERING, required=("ProcessGuid", "Type")),
    26: _Spec(EventCategory.FILE_DELETE, hashes="Hashes", required=("ProcessGuid", "TargetFilename")),
    29: _Spec(EventCategory.FILE_CREATE, hashes="Hashes", required=("ProcessGuid", "TargetFilename")),
    255: _Spec(EventCategory.SENSOR_STATE, guid=None, pid=None, image=None, user=None, required=("ID",)),
}

# Events deliberately not normalised:
# 24 ClipboardChange - relates to clipboard contents; KernelGuard does not collect it.
# 27/28 FileBlock*  - Sysmon blocking actions; stored as OTHER if they appear.
_EXCLUDED = {24}


def normalize_sysmon(parsed: ParsedEvent, ctx: NormalizeContext) -> NormalizedEvent | None:
    if parsed.provider is not None and parsed.provider != SYSMON_PROVIDER:
        return None
    if parsed.event_id in _EXCLUDED:
        return None

    spec = _SPECS.get(parsed.event_id, _Spec(EventCategory.OTHER, required=()))
    data = parsed.data

    def field(name: str | None) -> str | None:
        return clean(data.get(name)) if name else None

    missing = [name for name in spec.required if field(name) is None]

    hashes = parse_hashes(field(spec.hashes))

    timestamp = parsed.time_created
    utc_time = field("UtcTime")
    if utc_time:
        try:
            timestamp = parse_windows_time(utc_time)
        except ValueError:
            missing.append("UtcTime(unparseable)")

    out_data: dict[str, object] = dict(data)
    if parsed.truncated_fields:
        out_data["_kg_truncated"] = list(parsed.truncated_fields)

    if missing:
        status = CollectionStatus.PARTIAL
    elif parsed.truncated_fields:
        status = CollectionStatus.TRUNCATED
    else:
        status = CollectionStatus.COMPLETE

    return NormalizedEvent(
        source=EventSource.SYSMON,
        channel=ctx.channel,
        provider=parsed.provider,
        source_event_id=parsed.event_id,
        record_id=parsed.record_id,
        timestamp=timestamp,
        logged_at=parsed.time_created,
        host_id=ctx.host_id,
        hostname=parsed.computer,
        process_guid=field(spec.guid),
        process_id=to_int(field(spec.pid)),
        image=field(spec.image),
        parent_process_guid=field(spec.parent_guid),
        parent_process_id=to_int(field(spec.parent_pid)),
        parent_image=field(spec.parent_image),
        user=field(spec.user),
        sha256=hashes.get("SHA256"),
        sha1=hashes.get("SHA1"),
        md5=hashes.get("MD5"),
        imphash=hashes.get("IMPHASH"),
        signed=to_bool(field("Signed")) if spec.signature else None,
        signature=field("Signature") if spec.signature else None,
        signature_status=field("SignatureStatus") if spec.signature else None,
        category=spec.category,
        data=out_data,
        collection_status=status,
        missing_fields=missing,
        raw_xml=ctx.raw_xml,
    )
