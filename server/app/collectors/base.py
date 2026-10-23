"""Collector interfaces.

A sensor is a (channel, normaliser) pair read through an ``EventLogReader``.
The ingestion service only depends on these interfaces, so new sources
(e.g. a native ETW reader) can be added without touching detection code.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from app.collectors.xml_parser import ParsedEvent
from app.schemas.events import EventSource, NormalizedEvent


class CollectorError(Exception):
    """Base class for errors reading a channel."""


class ChannelUnavailableError(CollectorError):
    """The channel does not exist (e.g. Sysmon not installed)."""


class ChannelAccessDeniedError(CollectorError):
    """The collector's account may not read the channel."""


@dataclass(frozen=True)
class RawRecord:
    xml: str


@dataclass(frozen=True)
class RecordMarker:
    record_id: int
    logged_at: datetime


class EventLogReader(Protocol):
    """Read-only access to an event channel, ordered by EventRecordID."""

    def oldest(self, channel: str) -> RecordMarker | None: ...

    def newest(self, channel: str) -> RecordMarker | None: ...

    def logged_at(self, channel: str, record_id: int) -> datetime | None:
        """TimeCreated of a specific record, or None if it no longer exists."""
        ...

    def read_after(
        self, channel: str, after_record_id: int, event_ids: frozenset[int] | None, max_records: int
    ) -> list[RawRecord]: ...


@dataclass(frozen=True)
class NormalizeContext:
    host_id: str
    channel: str
    raw_xml: str | None


Normalizer = Callable[[ParsedEvent, NormalizeContext], "NormalizedEvent | None"]


@dataclass(frozen=True)
class SensorSpec:
    name: str
    channel: str
    source: EventSource
    normalizer: Normalizer
    # None = all events on the channel.
    event_ids: frozenset[int] | None = None
    unavailable_hint: str = "Channel not found on this host."
    access_denied_hint: str = (
        "Run the collector elevated, or add its account to the 'Event Log Readers' group."
    )
    description: str = ""
    requirements: list[str] = field(default_factory=list)
