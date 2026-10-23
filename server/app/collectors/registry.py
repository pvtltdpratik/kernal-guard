"""The sensors KernelGuard knows how to run."""

from __future__ import annotations

from app.collectors.base import SensorSpec
from app.collectors.sysmon import SYSMON_CHANNEL, normalize_sysmon
from app.collectors.windows_eventlog import SECURITY_EVENT_IDS, SYSTEM_EVENT_IDS, normalize_windows_event
from app.schemas.events import EventSource

SENSORS: dict[str, SensorSpec] = {
    "sysmon": SensorSpec(
        name="sysmon",
        channel=SYSMON_CHANNEL,
        source=EventSource.SYSMON,
        normalizer=normalize_sysmon,
        event_ids=None,
        unavailable_hint=(
            "Sysmon channel not found. Install Sysmon with the KernelGuard configuration "
            "(see server/config/sysmon/README.md)."
        ),
        description="Process, network, image/driver load, process access, file and registry telemetry.",
        requirements=["Sysmon installed", "Administrator or Event Log Readers membership"],
    ),
    "system": SensorSpec(
        name="system",
        channel="System",
        source=EventSource.WINDOWS_EVENTLOG,
        normalizer=normalize_windows_event,
        event_ids=SYSTEM_EVENT_IDS,
        description="Service installation (7045) and log clearing (104).",
        requirements=["Readable by standard users"],
    ),
    "security": SensorSpec(
        name="security",
        channel="Security",
        source=EventSource.WINDOWS_EVENTLOG,
        normalizer=normalize_windows_event,
        event_ids=SECURITY_EVENT_IDS,
        description="Process creation (4688), service installation (4697), audit log cleared (1102).",
        requirements=[
            "Administrator or Event Log Readers membership",
            "Audit Process Creation policy enabled for 4688",
        ],
    ),
}
