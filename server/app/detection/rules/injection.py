"""Category 3: suspicious process access and remote-thread activity."""

from __future__ import annotations

from app.db.models import Event
from app.detection.context import DetectionContext
from app.detection.paths import normalize_path
from app.detection.processes import guid_key
from app.detection.rules.base import EventRule
from app.detection.types import Confidence, Finding, MitreMapping, RuleMeta, Severity

T1055 = MitreMapping("T1055", "Process Injection", "Defense Evasion", "consistent_with")

# Windows components that legitimately create threads in or read other processes.
_SYSTEM_SOURCES = {
    "c:\\windows\\system32\\csrss.exe",
    "c:\\windows\\system32\\wininit.exe",
    "c:\\windows\\system32\\services.exe",
    "c:\\windows\\system32\\smss.exe",
    "c:\\windows\\system32\\lsm.exe",
    # Measured 2026-10-24: winlogon/dwm start threads in csrss during normal session handling.
    "c:\\windows\\system32\\winlogon.exe",
    "c:\\windows\\system32\\dwm.exe",
}

PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
# A handle needs at least one of these rights to place or start code in the
# target. Query/synchronize-only handles (e.g. 0x1000, 0x101401) cannot inject.
INJECTION_RIGHTS = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE


def _access_mask(value: str | None) -> int | None:
    try:
        return int(value or "", 16)
    except ValueError:
        return None


def _same_image(event: Event, target_field: str) -> bool:
    """Source and target are instances of the same program (multi-process apps)."""
    target = (event.data or {}).get(target_field)
    return bool(event.image and target) and normalize_path(event.image) == normalize_path(target)


def _is_defender(image: str) -> bool:
    path = normalize_path(image)
    return path.startswith("c:\\programdata\\microsoft\\windows defender\\platform\\") and path.endswith(
        "\\msmpeng.exe"
    )


def _target_entity(event: Event, guid_field: str) -> list[str]:
    guid = (event.data or {}).get(guid_field)
    return [f"process:{guid_key(event.host_id, guid)}"] if guid else []


class RemoteThreadCreated(EventRule):
    meta = RuleMeta(
        rule_id="KG-INJ-001",
        name="Remote thread created in another process",
        description="A process started a thread inside a different process.",
        category="injection",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        rationale=(
            "CreateRemoteThread is a classic code-injection primitive. A thread start address outside "
            "any loaded module indicates code running from injected memory."
        ),
        required_evidence=("Sysmon 8 (CreateRemoteThread)",),
        false_positives=(
            "Debuggers and profilers",
            "Security products and accessibility tools that inject helper threads",
            "Some game overlays and input-method editors",
        ),
        mitre=(T1055,),
        version=2,
    )
    categories = frozenset({"remote_thread"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        data = event.data or {}
        source = normalize_path(event.image)
        if source in _SYSTEM_SOURCES or _is_defender(source):
            return []
        target_image = data.get("TargetImage") or "unknown process"
        start_module = (data.get("StartModule") or "").strip()
        unbacked = start_module in ("", "-")
        # Multi-process apps (Electron, browsers) start threads in their own
        # children at addresses inside their own image. Only unbacked starts
        # into another instance of the same program are kept (measured
        # 2026-10-24: VS Code -> VS Code was the only remote thread observed).
        if not unbacked and _same_image(event, "TargetImage"):
            return []
        adjustments = [("thread start address is not inside any loaded module", 25)] if unbacked else []
        return [
            Finding(
                title=f"Remote thread: {event.image} -> {target_image}",
                subject=self.subject(event.host_id, event.process_guid, data.get("TargetProcessGuid")),
                event_ids=[event.id],
                observations=[
                    self.observed(
                        event,
                        f"{self.process_label(event)} created thread {data.get('NewThreadId')} in {target_image} "
                        f"(PID {data.get('TargetProcessId')}) at {data.get('StartAddress')}"
                        + (f" in module {start_module}" if not unbacked else " (no backing module)")
                        + ".",
                    ),
                    self.inferred("Remote thread creation is consistent with code injection, but also used by debuggers and security tools."),
                ],
                entities=[*self.process_entities(event, ctx), *_target_entity(event, "TargetProcessGuid")],
                severity=Severity.HIGH if unbacked else None,
                adjustments=adjustments,
                process_guid=event.process_guid,
                process_id=event.process_id,
                image=event.image,
            )
        ]


class LsassMemoryAccess(EventRule):
    meta = RuleMeta(
        rule_id="KG-CRED-001",
        name="LSASS opened with memory-read access",
        description="A non-system process opened lsass.exe with PROCESS_VM_READ.",
        category="injection",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        rationale=(
            "Reading LSASS memory is how credential dumpers (Mimikatz, procdump -ma lsass) obtain "
            "password hashes and tickets."
        ),
        required_evidence=("Sysmon 10 (process access) targeting lsass.exe",),
        false_positives=(
            "Endpoint security and backup agents",
            "Windows Error Reporting collecting a crash dump of LSASS",
            "Administrators deliberately creating a memory dump for debugging",
        ),
        mitre=(MitreMapping("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access", "consistent_with"),),
    )
    categories = frozenset({"process_access"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        data = event.data or {}
        if not (data.get("TargetImage") or "").lower().endswith("\\lsass.exe"):
            return []
        source = normalize_path(event.image)
        if source in _SYSTEM_SOURCES or _is_defender(source):
            return []
        try:
            access = int(data.get("GrantedAccess") or "0", 16)
        except ValueError:
            return []
        if not access & PROCESS_VM_READ:
            return []
        call_trace = (data.get("CallTrace") or "").lower()
        adjustments: list[tuple[str, int]] = []
        if "dbghelp.dll" in call_trace or "dbgcore.dll" in call_trace:
            adjustments.append(("call trace includes dbghelp/dbgcore (MiniDumpWriteDump)", 15))
        if "unknown(" in call_trace:
            adjustments.append(("call trace includes code outside any loaded module", 10))
        return [
            Finding(
                title=f"LSASS memory access by {event.image}",
                subject=self.subject(event.host_id, event.process_guid),
                event_ids=[event.id],
                observations=[
                    self.observed(event, f"{self.process_label(event)} opened lsass.exe with access mask {data.get('GrantedAccess')} (includes PROCESS_VM_READ)."),
                    *[self.inferred(f"Risk factor: {reason}.") for reason, _ in adjustments],
                ],
                entities=[*self.process_entities(event, ctx), *_target_entity(event, "TargetProcessGUID")],
                severity=Severity.CRITICAL if adjustments else None,
                adjustments=adjustments,
                uncertainty=["Read access was granted; whether memory was actually read or dumped is not observed."],
                process_guid=event.process_guid,
                process_id=event.process_id,
                image=event.image,
            )
        ]


class AccessFromUnbackedCode(EventRule):
    meta = RuleMeta(
        rule_id="KG-INJ-002",
        name="Injection-capable handle opened from unbacked code",
        description=(
            "Code outside any loaded module opened another program's process with rights that allow "
            "writing memory or starting threads."
        ),
        category="injection",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        rationale=(
            "Code executing from memory without a backing file is typical of injected shellcode or reflective "
            "loading. Requiring write/operation/create-thread rights limits this to handles that could be used "
            "to inject; JIT runtimes routinely open query-only handles from unbacked code."
        ),
        required_evidence=(
            "Sysmon 10 with CallTrace containing UNKNOWN(...) and GrantedAccess including "
            "PROCESS_VM_WRITE, PROCESS_VM_OPERATION or PROCESS_CREATE_THREAD",
        ),
        false_positives=(
            "JIT-compiled runtimes (.NET, Java, Electron/V8) that also request write access",
            "Packers/protectors and some game anti-cheat components",
        ),
        mitre=(T1055,),
        version=3,
    )
    categories = frozenset({"process_access"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        data = event.data or {}
        if "unknown(" not in (data.get("CallTrace") or "").lower():
            return []
        if (data.get("TargetImage") or "").lower().endswith("\\lsass.exe"):
            return []  # covered by KG-CRED-001
        # v2 (measured 2026-10-24): 175 alerts in 9 minutes, all JIT runtimes
        # (Claude desktop, VS Code, pwsh, PowerToys) opening query-only handles
        # or their own sibling processes. Neither can inject.
        mask = _access_mask(data.get("GrantedAccess"))
        if mask is None or not mask & INJECTION_RIGHTS:
            return []
        if _same_image(event, "TargetImage"):
            return []
        # CreateProcess hands the parent a full-access handle to its child; JIT
        # parents (Electron, .NET, bash) then show unbacked frames. Measured
        # 2026-10-24: 1,000+ occurrences, all parent->child.
        target = ctx.process_by_guid(event.host_id, data.get("TargetProcessGUID"))
        if target is not None and event.process_guid and target.parent_process_guid == event.process_guid:
            return []
        return [
            Finding(
                title=f"Injection-capable access from unbacked code: {event.image} -> {data.get('TargetImage')}",
                # One alert per source/target program pair; repeats become occurrences.
                subject=self.subject(event.host_id, normalize_path(event.image), normalize_path(data.get("TargetImage"))),
                event_ids=[event.id],
                observations=[
                    self.observed(
                        event,
                        f"{self.process_label(event)} opened {data.get('TargetImage')} (access {data.get('GrantedAccess')}); "
                        f"call trace: {data.get('CallTrace')}.",
                    )
                ],
                entities=[*self.process_entities(event, ctx), *_target_entity(event, "TargetProcessGUID")],
                process_guid=event.process_guid,
                process_id=event.process_id,
                image=event.image,
            )
        ]
