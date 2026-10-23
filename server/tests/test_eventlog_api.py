"""Tests for the Windows Event Log reader.

``build_query`` tests run everywhere. Live tests read real channels on this
host and are opt-in: set ``KG_LIVE_TESTS=1``. They only read.
"""

from __future__ import annotations

import os
import sys

import pytest

from app.collectors.base import ChannelUnavailableError
from app.collectors.eventlog_api import build_query

live = pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("KG_LIVE_TESTS") != "1",
    reason="live Windows Event Log tests are opt-in (KG_LIVE_TESTS=1)",
)


def test_build_query_without_filter() -> None:
    assert build_query(41, None) == "*[System[EventRecordID > 41]]"


def test_build_query_with_event_ids_sorted() -> None:
    assert build_query(0, frozenset({7045, 104})) == "*[System[EventRecordID > 0 and (EventID=104 or EventID=7045)]]"


@live
def test_live_system_channel_round_trip() -> None:
    from app.collectors.eventlog_api import WindowsEventLogReader
    from app.collectors.xml_parser import parse_event_xml

    reader = WindowsEventLogReader()
    oldest, newest = reader.oldest("System"), reader.newest("System")
    assert oldest is not None and newest is not None
    assert oldest.record_id <= newest.record_id
    assert reader.logged_at("System", newest.record_id) == newest.logged_at

    records = reader.read_after("System", newest.record_id - 3, None, 10)
    assert 1 <= len(records) <= 3
    parsed = [parse_event_xml(r.xml, max_bytes=256 * 1024, max_field_chars=8192) for r in records]
    assert [p.record_id for p in parsed] == sorted(p.record_id for p in parsed)
    assert all(p.record_id > newest.record_id - 3 for p in parsed)


@live
def test_live_missing_channel_is_unavailable() -> None:
    from app.collectors.eventlog_api import WindowsEventLogReader

    with pytest.raises(ChannelUnavailableError):
        WindowsEventLogReader().oldest("KernelGuard-Test/DoesNotExist")
