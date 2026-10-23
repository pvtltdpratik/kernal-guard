"""Safe parsing of Windows event XML (as rendered by EvtRender).

Hardening:
- Input is size-checked before parsing.
- defusedxml rejects DTDs, entity declarations and external references,
  none of which legitimate event XML contains.
- Every value is length-capped; capped field names are reported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

_RECORD_ID_RE = re.compile(r"<EventRecordID>(\d{1,20})</EventRecordID>")
# 2026-07-29T14:28:07.1834784Z (Windows emits 7 fractional digits)
_SYSTEM_TIME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z?$")


class EventParseError(ValueError):
    """The record could not be parsed as Windows event XML."""


class OversizedEventError(EventParseError):
    pass


@dataclass(frozen=True)
class ParsedEvent:
    provider: str | None
    event_id: int
    record_id: int
    time_created: datetime
    channel: str | None
    computer: str | None
    user_sid: str | None
    data: dict[str, str | None]
    truncated_fields: list[str] = field(default_factory=list)


def parse_windows_time(value: str) -> datetime:
    """Parse Windows/Sysmon UTC timestamps, keeping microsecond precision."""
    match = _SYSTEM_TIME_RE.match(value.strip())
    if not match:
        raise ValueError(f"Unrecognised timestamp: {value!r}")
    date_part, time_part, fraction = match.groups()
    micro = (fraction or "0")[:6].ljust(6, "0")
    return datetime.fromisoformat(f"{date_part}T{time_part}.{micro}").replace(tzinfo=timezone.utc)


def extract_record_id(xml: str) -> int | None:
    """Best-effort record ID from XML that failed full parsing, so a poison
    record can still advance the bookmark instead of blocking the channel."""
    match = _RECORD_ID_RE.search(xml)
    return int(match.group(1)) if match else None


def _text(parent: Element | None, tag: str) -> str | None:
    if parent is None:
        return None
    node = parent.find(f"{NS}{tag}")
    if node is None or node.text is None:
        return None
    return node.text.strip() or None


def _cap(value: str | None, limit: int) -> tuple[str | None, bool]:
    if value is not None and len(value) > limit:
        return value[:limit], True
    return value, False


def _collect_data(root: Element, max_field_chars: int) -> tuple[dict[str, str | None], list[str]]:
    data: dict[str, str | None] = {}
    truncated: list[str] = []

    def put(key: str, value: str | None) -> None:
        capped, was_truncated = _cap(value, max_field_chars)
        if key in data:  # duplicate names: keep all, suffix later ones
            index = 2
            while f"{key}_{index}" in data:
                index += 1
            key = f"{key}_{index}"
        data[key] = capped
        if was_truncated:
            truncated.append(key)

    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        for position, node in enumerate(event_data.findall(f"{NS}Data")):
            put(node.get("Name") or f"Data{position}", node.text)

    # Some events (e.g. log-cleared 104/1102) use <UserData><Something xmlns=...>...</></UserData>
    user_data = root.find(f"{NS}UserData")
    if user_data is not None:
        for container in user_data:
            for node in container:
                local_name = node.tag.rsplit("}", 1)[-1]
                put(local_name, node.text)

    return data, truncated


def parse_event_xml(xml: str, *, max_bytes: int, max_field_chars: int) -> ParsedEvent:
    if len(xml.encode("utf-8", errors="replace")) > max_bytes:
        raise OversizedEventError(f"Event XML exceeds {max_bytes} bytes")

    try:
        root = SafeET.fromstring(xml, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (SafeET.ParseError, DefusedXmlException) as exc:
        raise EventParseError(f"Malformed or unsafe event XML: {exc.__class__.__name__}") from exc

    if root.tag != f"{NS}Event":
        raise EventParseError(f"Unexpected root element {root.tag!r}")

    system = root.find(f"{NS}System")
    if system is None:
        raise EventParseError("Missing <System> element")

    event_id_text = _text(system, "EventID")
    record_id_text = _text(system, "EventRecordID")
    time_node = system.find(f"{NS}TimeCreated")
    if not event_id_text or not record_id_text or time_node is None or not time_node.get("SystemTime"):
        raise EventParseError("Missing EventID, EventRecordID or TimeCreated")

    try:
        event_id = int(event_id_text)
        record_id = int(record_id_text)
        time_created = parse_windows_time(time_node.get("SystemTime", ""))
    except ValueError as exc:
        raise EventParseError(str(exc)) from exc

    provider_node = system.find(f"{NS}Provider")
    security_node = system.find(f"{NS}Security")
    data, truncated = _collect_data(root, max_field_chars)

    return ParsedEvent(
        provider=provider_node.get("Name") if provider_node is not None else None,
        event_id=event_id,
        record_id=record_id,
        time_created=time_created,
        channel=_text(system, "Channel"),
        computer=_text(system, "Computer"),
        user_sid=security_node.get("UserID") if security_node is not None else None,
        data=data,
        truncated_fields=truncated,
    )
