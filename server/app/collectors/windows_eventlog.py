"""Normalisation for selected built-in Windows Event Log events.

Only events with security value and a stable documented schema are kept:

System channel
- 7045  Service Control Manager: a service was installed (persistence).
- 104   Eventlog: a log was cleared (anti-forensics).

Security channel (requires elevation or Event Log Readers membership)
- 4688  A new process was created (needs "Audit Process Creation";
        command lines need an additional policy setting).
- 4697  A service was installed (needs "Audit Security System Extension").
- 1102  The audit log was cleared.

Any other event delivered for these channels is ignored.
"""

from __future__ import annotations

from collections.abc import Callable

from app.collectors.base import NormalizeContext
from app.collectors.fields import clean, to_int
from app.collectors.xml_parser import ParsedEvent
from app.schemas.events import CollectionStatus, EventCategory, EventSource, NormalizedEvent

SCM_PROVIDER = "Service Control Manager"
EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"

SYSTEM_EVENT_IDS = frozenset({7045, 104})
SECURITY_EVENT_IDS = frozenset({4688, 4697, 1102})


def _account(data: dict[str, str | None], user_key: str, domain_key: str) -> str | None:
    user = clean(data.get(user_key))
    if user is None:
        return None
    domain = clean(data.get(domain_key))
    return f"{domain}\\{user}" if domain else user


def _build(
    parsed: ParsedEvent,
    ctx: NormalizeContext,
    category: EventCategory,
    required: tuple[str, ...],
    **fields: object,
) -> NormalizedEvent:
    missing = [name for name in required if clean(parsed.data.get(name)) is None]
    data: dict[str, object] = dict(parsed.data)
    if parsed.truncated_fields:
        data["_kg_truncated"] = list(parsed.truncated_fields)
    if missing:
        status = CollectionStatus.PARTIAL
    elif parsed.truncated_fields:
        status = CollectionStatus.TRUNCATED
    else:
        status = CollectionStatus.COMPLETE

    return NormalizedEvent(
        source=EventSource.WINDOWS_EVENTLOG,
        channel=ctx.channel,
        provider=parsed.provider,
        source_event_id=parsed.event_id,
        record_id=parsed.record_id,
        timestamp=parsed.time_created,
        logged_at=parsed.time_created,
        host_id=ctx.host_id,
        hostname=parsed.computer,
        category=category,
        data=data,
        collection_status=status,
        missing_fields=missing,
        raw_xml=ctx.raw_xml,
        **fields,  # type: ignore[arg-type]
    )


def _service_install_7045(parsed: ParsedEvent, ctx: NormalizeContext) -> NormalizedEvent:
    # The logging process (services.exe) is not the installer, so no process
    # fields are promoted; the installed binary path stays in data.ImagePath.
    return _build(parsed, ctx, EventCategory.SERVICE_INSTALL, ("ServiceName", "ImagePath"))


def _log_cleared(parsed: ParsedEvent, ctx: NormalizeContext) -> NormalizedEvent:
    return _build(
        parsed, ctx, EventCategory.LOG_CLEARED, ("SubjectUserName",),
        user=_account(parsed.data, "SubjectUserName", "SubjectDomainName"),
    )


def _process_creation_4688(parsed: ParsedEvent, ctx: NormalizeContext) -> NormalizedEvent:
    data = parsed.data
    return _build(
        parsed, ctx, EventCategory.PROCESS_CREATION, ("NewProcessId", "NewProcessName"),
        process_id=to_int(data.get("NewProcessId")),
        image=clean(data.get("NewProcessName")),
        parent_process_id=to_int(data.get("ProcessId")),
        parent_image=clean(data.get("ParentProcessName")),
        user=_account(data, "SubjectUserName", "SubjectDomainName"),
    )


def _service_install_4697(parsed: ParsedEvent, ctx: NormalizeContext) -> NormalizedEvent:
    return _build(
        parsed, ctx, EventCategory.SERVICE_INSTALL, ("ServiceName", "ServiceFileName"),
        user=_account(parsed.data, "SubjectUserName", "SubjectDomainName"),
    )


_HANDLERS: dict[tuple[str, int], Callable[[ParsedEvent, NormalizeContext], NormalizedEvent]] = {
    (SCM_PROVIDER, 7045): _service_install_7045,
    (EVENTLOG_PROVIDER, 104): _log_cleared,
    (SECURITY_PROVIDER, 4688): _process_creation_4688,
    (SECURITY_PROVIDER, 4697): _service_install_4697,
    # 1102 is logged by the Eventlog provider on the Security channel.
    (EVENTLOG_PROVIDER, 1102): _log_cleared,
}


def normalize_windows_event(parsed: ParsedEvent, ctx: NormalizeContext) -> NormalizedEvent | None:
    handler = _HANDLERS.get((parsed.provider or "", parsed.event_id))
    return handler(parsed, ctx) if handler else None
