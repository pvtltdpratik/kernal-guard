"""Windows Event Log reader using the documented Evt* API (wevtapi) via pywin32.

This is the only module that calls Windows APIs. It is strictly read-only:
it opens query handles and renders XML, and never clears, writes or
reconfigures any log.
"""

from __future__ import annotations

import sys
from datetime import datetime

from app.collectors.base import (
    ChannelAccessDeniedError,
    ChannelUnavailableError,
    CollectorError,
    RawRecord,
    RecordMarker,
)
from app.collectors.xml_parser import NS, parse_windows_time

# winerror codes observed from EvtQuery
ERROR_ACCESS_DENIED = 5
ERROR_EVT_CHANNEL_NOT_FOUND = 15007
ERROR_EVT_INVALID_QUERY = 15001

_NEXT_TIMEOUT_MS = 2000


def build_query(after_record_id: int, event_ids: frozenset[int] | None) -> str:
    """XPath filter; inputs are integers so no injection is possible."""
    clauses = [f"EventRecordID > {int(after_record_id)}"]
    if event_ids:
        clauses.append("(" + " or ".join(f"EventID={int(i)}" for i in sorted(event_ids)) + ")")
    return f"*[System[{' and '.join(clauses)}]]"


class WindowsEventLogReader:
    def __init__(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("WindowsEventLogReader requires Windows")
        import pywintypes
        import win32evtlog

        self._evt = win32evtlog
        self._error = pywintypes.error

    def _query(self, channel: str, query: str, reverse: bool = False) -> object:
        direction = self._evt.EvtQueryReverseDirection if reverse else self._evt.EvtQueryForwardDirection
        try:
            return self._evt.EvtQuery(channel, self._evt.EvtQueryChannelPath | direction, query)
        except self._error as exc:
            if exc.winerror == ERROR_EVT_CHANNEL_NOT_FOUND:
                raise ChannelUnavailableError(channel) from exc
            if exc.winerror == ERROR_ACCESS_DENIED:
                raise ChannelAccessDeniedError(channel) from exc
            raise CollectorError(f"EvtQuery failed ({exc.winerror}): {exc.strerror}") from exc

    def _next(self, handle: object, count: int) -> list[str]:
        try:
            events = self._evt.EvtNext(handle, count, _NEXT_TIMEOUT_MS, 0)
        except self._error as exc:
            raise CollectorError(f"EvtNext failed ({exc.winerror}): {exc.strerror}") from exc
        return [self._evt.EvtRender(event, self._evt.EvtRenderEventXml) for event in events]

    def _marker(self, channel: str, query: str, reverse: bool) -> RecordMarker | None:
        rendered = self._next(self._query(channel, query, reverse), 1)
        if not rendered:
            return None
        return _marker_from_xml(rendered[0])

    def oldest(self, channel: str) -> RecordMarker | None:
        return self._marker(channel, "*", reverse=False)

    def newest(self, channel: str) -> RecordMarker | None:
        return self._marker(channel, "*", reverse=True)

    def logged_at(self, channel: str, record_id: int) -> datetime | None:
        marker = self._marker(channel, f"*[System[EventRecordID={int(record_id)}]]", reverse=False)
        return marker.logged_at if marker else None

    def read_after(
        self, channel: str, after_record_id: int, event_ids: frozenset[int] | None, max_records: int
    ) -> list[RawRecord]:
        handle = self._query(channel, build_query(after_record_id, event_ids))
        return [RawRecord(xml=xml) for xml in self._next(handle, max_records)]


def _marker_from_xml(xml: str) -> RecordMarker | None:
    # Only System fields are needed; avoid a full parse of EventData.
    import defusedxml.ElementTree as SafeET

    root = SafeET.fromstring(xml, forbid_dtd=True)
    system = root.find(f"{NS}System")
    if system is None:
        return None
    record = system.find(f"{NS}EventRecordID")
    created = system.find(f"{NS}TimeCreated")
    if record is None or record.text is None or created is None:
        return None
    return RecordMarker(record_id=int(record.text), logged_at=parse_windows_time(created.get("SystemTime", "")))
