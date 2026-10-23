"""Common normalised event schema and API representations."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventCategory(str, Enum):
    PROCESS_CREATION = "process_creation"
    PROCESS_TERMINATION = "process_termination"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    IMAGE_LOAD = "image_load"
    DRIVER_LOAD = "driver_load"
    PROCESS_ACCESS = "process_access"
    REMOTE_THREAD = "remote_thread"
    PROCESS_TAMPERING = "process_tampering"
    FILE_CREATE = "file_create"
    FILE_TIME_CHANGE = "file_time_change"
    FILE_STREAM = "file_stream"
    FILE_DELETE = "file_delete"
    RAW_ACCESS_READ = "raw_access_read"
    REGISTRY_KEY = "registry_key"
    REGISTRY_VALUE_SET = "registry_value_set"
    REGISTRY_RENAME = "registry_rename"
    PIPE = "pipe"
    WMI = "wmi"
    SERVICE_INSTALL = "service_install"
    LOG_CLEARED = "log_cleared"
    SENSOR_STATE = "sensor_state"
    OTHER = "other"


class CollectionStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    TRUNCATED = "truncated"


class EventSource(str, Enum):
    SYSMON = "sysmon"
    WINDOWS_EVENTLOG = "windows_eventlog"


class NormalizedEvent(BaseModel):
    """Collector output, before persistence. Every optional field is None
    unless the source event actually carried it."""

    source: EventSource
    channel: str
    provider: str | None = None
    source_event_id: int
    record_id: int
    timestamp: datetime
    logged_at: datetime
    host_id: str
    hostname: str | None = None

    process_guid: str | None = None
    process_id: int | None = None
    image: str | None = None
    parent_process_guid: str | None = None
    parent_process_id: int | None = None
    parent_image: str | None = None
    user: str | None = None

    sha256: str | None = None
    sha1: str | None = None
    md5: str | None = None
    imphash: str | None = None
    signed: bool | None = None
    signature: str | None = None
    signature_status: str | None = None

    category: EventCategory
    data: dict[str, Any] = Field(default_factory=dict)
    collection_status: CollectionStatus = CollectionStatus.COMPLETE
    missing_fields: list[str] = Field(default_factory=list)
    raw_xml: str | None = None


class EventSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source: EventSource
    channel: str
    source_event_id: int
    record_id: int
    timestamp: datetime
    ingested_at: datetime
    host_id: str
    hostname: str | None
    category: EventCategory
    process_guid: str | None
    process_id: int | None
    image: str | None
    parent_process_id: int | None
    parent_image: str | None
    user: str | None
    collection_status: CollectionStatus


class EventDetail(EventSummary):
    provider: str | None
    logged_at: datetime
    parent_process_guid: str | None
    sha256: str | None
    sha1: str | None
    md5: str | None
    imphash: str | None
    signed: bool | None
    signature: str | None
    signature_status: str | None
    data: dict[str, Any]
    missing_fields: list[str]
    raw_xml: str | None = Field(default=None, description="Only returned when include_raw=true")
