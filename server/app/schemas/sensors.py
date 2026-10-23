"""Sensor status schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

SensorState = Literal["ok", "unavailable", "access_denied", "error", "never_run"]


class SensorStatus(BaseModel):
    sensor: str
    channel: str
    description: str
    requirements: list[str]
    enabled: bool
    state: SensorState
    detail: str | None
    stale: bool
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    last_error_at: datetime | None
    consecutive_failures: int
    events_ingested: int
    duplicates_skipped: int
    parse_failures: int
    records_ignored: int
    records_missed: int
    detection_failures: int


class SensorStatusResponse(BaseModel):
    generated_at: datetime
    collector_interval_seconds: int
    # True when no enabled sensor has attempted collection recently:
    # the collector process is probably not running.
    collector_stale: bool
    sensors: list[SensorStatus]
