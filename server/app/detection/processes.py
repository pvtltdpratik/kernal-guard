"""Process tracking: builds ``processes`` rows from events.

Handles the awkward realities of endpoint telemetry:
- PID reuse: identity is the Sysmon ProcessGuid, or PID + creation time.
- Out-of-order delivery: a process first seen through a network event gets
  a row with ``creation_observed = False``; its creation event fills the
  gaps later. ``first_seen``/``last_seen`` take min/max, not arrival order.
- Missing events: unknown fields stay NULL, never guessed.
- Conflicting evidence: the first value wins and disagreements are recorded
  in ``conflicts`` for the analyst, rather than silently overwritten.
- Idempotence: re-observing the same event (rescan) changes nothing.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models import Event, Process

MAX_CONFLICTS = 20

# Fields filled first-wins; compared case-insensitively where paths/users.
_CASE_INSENSITIVE = {"image", "parent_image", "user"}


def guid_key(host_id: str, guid: str) -> str:
    return f"guid:{host_id}:{guid.lower()}"


def pid_key(host_id: str, pid: int, start: datetime) -> str:
    return f"pid:{host_id}:{pid}:{start.strftime('%Y%m%dT%H%M%S')}"


def event_process_key(event: Event) -> str | None:
    """Identity of the event's acting process, if determinable from the event."""
    if event.process_guid:
        return guid_key(event.host_id, event.process_guid)
    if event.category == "process_creation" and event.process_id is not None:
        return pid_key(event.host_id, event.process_id, event.timestamp)
    return None


class ProcessTracker:
    def __init__(self, session: Session) -> None:
        self.session = session
        self._cache: dict[str, Process] = {}

    # ------------------------------------------------------------- lookups

    def get(self, key: str) -> Process | None:
        if key in self._cache:
            return self._cache[key]
        process = self.session.scalar(select(Process).where(Process.key == key))
        if process is not None:
            self._cache[key] = process
        return process

    def find_by_pid(self, host_id: str, pid: int, at: datetime) -> Process | None:
        """The process that held ``pid`` at time ``at`` (PID-reuse aware)."""
        statement = (
            select(Process)
            .where(
                Process.host_id == host_id,
                Process.process_id == pid,
                or_(Process.start_time.is_(None), Process.start_time <= at),
                or_(Process.end_time.is_(None), Process.end_time >= at),
            )
            .order_by(Process.start_time.desc())
            .limit(1)
        )
        return self.session.scalar(statement)

    def for_event(self, event: Event) -> Process | None:
        key = event_process_key(event)
        if key:
            return self.get(key)
        if event.process_id is not None:
            return self.find_by_pid(event.host_id, event.process_id, event.timestamp)
        return None

    # ------------------------------------------------------------ updates

    def observe(self, event: Event) -> Process | None:
        key = event_process_key(event)
        if key is None:
            return None

        process = self._get_or_create(key, event)
        is_creation = event.category == "process_creation"
        data = event.data or {}

        self._merge(process, event, "process_guid", event.process_guid)
        self._merge(process, event, "process_id", event.process_id)
        self._merge(process, event, "image", event.image)
        self._merge(process, event, "user", event.user)
        if is_creation:
            self._merge(process, event, "parent_process_guid", event.parent_process_guid)
            self._merge(process, event, "parent_process_id", event.parent_process_id)
            self._merge(process, event, "parent_image", event.parent_image)
            self._merge(process, event, "command_line", data.get("CommandLine") or None)
            self._merge(process, event, "integrity_level", data.get("IntegrityLevel"))
            for algo in ("sha256", "sha1", "md5", "imphash"):
                self._merge(process, event, algo, getattr(event, algo))
            self._merge(process, event, "start_time", event.timestamp)
            process.creation_observed = True
        if event.category == "process_termination":
            self._merge(process, event, "end_time", event.timestamp)

        process.first_seen = min(process.first_seen, event.timestamp)
        process.last_seen = max(process.last_seen, event.timestamp)
        if event.source not in process.sources:
            process.sources = [*process.sources, event.source]

        if is_creation and event.parent_process_guid:
            self._observe_parent(event)
        return process

    def _observe_parent(self, event: Event) -> None:
        """Record what the child's creation event tells us about its parent."""
        parent = self._get_or_create(guid_key(event.host_id, event.parent_process_guid or ""), event)
        self._merge(parent, event, "process_guid", event.parent_process_guid)
        self._merge(parent, event, "process_id", event.parent_process_id)
        self._merge(parent, event, "image", event.parent_image)
        parent.first_seen = min(parent.first_seen, event.timestamp)
        parent.last_seen = max(parent.last_seen, event.timestamp)

    def _get_or_create(self, key: str, event: Event) -> Process:
        process = self.get(key)
        if process is None:
            process = Process(
                key=key,
                host_id=event.host_id,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                creation_observed=False,
                sources=[],
                conflicts=[],
            )
            self.session.add(process)
            self._cache[key] = process
        return process

    @staticmethod
    def _merge(process: Process, event: Event, field: str, value: object) -> None:
        if value is None or value == "":
            return
        current = getattr(process, field)
        if current is None:
            setattr(process, field, value)
            return
        same = (
            str(current).lower() == str(value).lower() if field in _CASE_INSENSITIVE else current == value
        )
        if same:
            return
        conflict = {"field": field, "kept": str(current), "observed": str(value), "event_id": event.id}
        if len(process.conflicts) < MAX_CONFLICTS and not any(
            c["field"] == field and c["observed"] == conflict["observed"] for c in process.conflicts
        ):
            process.conflicts = [*process.conflicts, conflict]
