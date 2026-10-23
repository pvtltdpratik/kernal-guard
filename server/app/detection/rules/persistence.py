"""Category 2: persistence-related registry, startup and service changes."""

from __future__ import annotations

import re

from app.db.models import Event
from app.detection.context import DetectionContext
from app.detection.paths import (
    PROXY_EXECUTION,
    SCRIPT_HOSTS,
    basename,
    executable_from_command,
    is_startup_folder,
    is_user_writable,
    normalize_path,
)
from app.detection.rules.base import EventRule
from app.detection.types import Confidence, Finding, MitreMapping, RuleMeta, Severity

T1547_001 = MitreMapping("T1547.001", "Registry Run Keys / Startup Folder", "Persistence")
T1543_003 = MitreMapping("T1543.003", "Windows Service", "Persistence")

_RUN_KEY = re.compile(
    r"\\currentversion\\(run|runonce|runonceex|runservices|runservicesonce)\\|\\policies\\explorer\\run\\",
    re.IGNORECASE,
)


def _command_reasons(command: str | None) -> list[tuple[str, int]]:
    """Score adjustments explaining why an autostart command looks risky."""
    reasons: list[tuple[str, int]] = []
    exe = executable_from_command(command)
    if exe and is_user_writable(exe):
        reasons.append((f"autostart target {exe} is in a user-writable location", 20))
    name = basename(exe)
    if name in SCRIPT_HOSTS or name in PROXY_EXECUTION:
        reasons.append((f"autostart command runs through {name}", 15))
    if command and re.search(r"-enc(odedcommand)?\s", command, re.IGNORECASE):
        reasons.append(("command contains an encoded PowerShell payload", 20))
    return reasons


class RunKeyModified(EventRule):
    meta = RuleMeta(
        rule_id="KG-PERSIST-001",
        name="Registry Run key value set",
        description="A value was written under a Run/RunOnce autostart key.",
        category="persistence",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        rationale="Run keys start the configured command at every logon, a common persistence mechanism.",
        required_evidence=("Sysmon 13 (registry value set) for a Run/RunOnce key",),
        false_positives=(
            "Applications registering their own autostart (OneDrive, Teams, chat and sync clients)",
            "Installers adding RunOnce entries to finish setup after reboot",
        ),
        mitre=(T1547_001,),
    )
    categories = frozenset({"registry_value_set"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        data = event.data or {}
        target = data.get("TargetObject") or ""
        if not _RUN_KEY.search(target):
            return []
        details = data.get("Details")
        adjustments = _command_reasons(details)
        observations = [
            self.observed(event, f"{self.process_label(event)} set {target} = {details!r}."),
            *[self.inferred(f"Risk factor: {reason}.") for reason, _ in adjustments],
        ]
        entities = self.process_entities(event, ctx)
        exe = executable_from_command(details)
        if exe:
            entities.append(self.file_entity(event.host_id, exe))
        return [
            Finding(
                title=f"Run key set by {event.image or 'unknown process'}",
                subject=self.subject(event.host_id, target),
                event_ids=[event.id],
                observations=observations,
                entities=entities,
                severity=Severity.HIGH if adjustments else None,
                confidence=Confidence.MEDIUM if adjustments else None,
                adjustments=adjustments,
                uncertainty=["Whether the referenced program is malicious is not assessed; only its location and launcher."],
                process_guid=event.process_guid,
                process_id=event.process_id,
                image=event.image,
            )
        ]


class StartupFolderFile(EventRule):
    meta = RuleMeta(
        rule_id="KG-PERSIST-002",
        name="File created in a Startup folder",
        description="A file was created in a user or all-users Startup folder.",
        category="persistence",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        rationale="Items in Startup folders run at logon.",
        required_evidence=("Sysmon 11 (file created) in a Startup folder (requires matching Sysmon config)",),
        false_positives=("Applications adding their own shortcut to Startup during installation",),
        mitre=(T1547_001,),
    )
    categories = frozenset({"file_create"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        target = (event.data or {}).get("TargetFilename") or ""
        if not is_startup_folder(target) or basename(target) == "desktop.ini":
            return []
        return [
            Finding(
                title=f"Startup folder item created: {basename(target)}",
                subject=self.subject(event.host_id, normalize_path(target)),
                event_ids=[event.id],
                observations=[
                    self.observed(event, f"{self.process_label(event)} created {target}."),
                    self.inferred("Files in Startup folders run automatically at user logon."),
                ],
                entities=[*self.process_entities(event, ctx), self.file_entity(event.host_id, normalize_path(target))],
                process_guid=event.process_guid,
                process_id=event.process_id,
                image=event.image,
            )
        ]


class SuspiciousServiceInstall(EventRule):
    meta = RuleMeta(
        rule_id="KG-PERSIST-003",
        name="Service installed with a suspicious binary path",
        description=(
            "A service was installed whose binary is in a user-writable location, runs through a "
            "script host, or uses a UNC path. Ordinary service installs are not alerted."
        ),
        category="persistence",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        rationale=(
            "Services run at boot, usually as LocalSystem. Legitimate services are installed into "
            "protected directories; script-host or user-writable service binaries are rare."
        ),
        required_evidence=("System 7045 or Security 4697 (service installed)",),
        false_positives=(
            "Vendor tools that install a temporary service from %TEMP% (some driver/firmware updaters)",
            "Remote administration tools that create a service via cmd.exe",
        ),
        mitre=(T1543_003,),
    )
    categories = frozenset({"service_install"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        data = event.data or {}
        command = data.get("ImagePath") or data.get("ServiceFileName")
        if not command:
            return []
        reasons = _command_reasons(command)
        if command.lstrip('"').startswith("\\\\"):
            reasons.append(("service binary is loaded from a network (UNC) path", 20))
        if "%comspec%" in command.lower():
            reasons.append(("service command uses %COMSPEC%", 20))
        if not reasons:
            return []
        name = data.get("ServiceName") or "unknown service"
        exe = executable_from_command(command)
        return [
            Finding(
                title=f"Suspicious service installed: {name}",
                subject=self.subject(event.host_id, name, normalize_path(command)),
                event_ids=[event.id],
                observations=[
                    self.observed(
                        event,
                        f"Service {name!r} installed with binary path {command!r}"
                        + (f", start type {data.get('StartType')}" if data.get("StartType") else "")
                        + (f", account {data.get('AccountName')}" if data.get("AccountName") else "")
                        + ".",
                    ),
                    *[self.inferred(f"Risk factor: {reason}.") for reason, _ in reasons],
                ],
                entities=[self.file_entity(event.host_id, exe)] if exe else [],
                adjustments=reasons,
                uncertainty=(
                    ["Event 7045 does not identify the process that installed the service."]
                    if event.source_event_id == 7045
                    else []
                ),
            )
        ]


# (pattern, title, mitre, base severity, value check)
_HIJACK_POINTS: list[tuple[re.Pattern[str], str, MitreMapping, Severity]] = [
    (
        re.compile(r"\\image file execution options\\[^\\]+\\debugger$", re.IGNORECASE),
        "Image File Execution Options debugger set",
        MitreMapping("T1546.012", "Image File Execution Options Injection", "Persistence"),
        Severity.HIGH,
    ),
    (
        re.compile(r"\\silentprocessexit\\[^\\]+\\monitorprocess$", re.IGNORECASE),
        "SilentProcessExit monitor process set",
        MitreMapping("T1546.012", "Image File Execution Options Injection", "Persistence"),
        Severity.HIGH,
    ),
    (
        re.compile(r"\\winlogon\\(shell|userinit|notify)$", re.IGNORECASE),
        "Winlogon logon command modified",
        MitreMapping("T1547.004", "Winlogon Helper DLL", "Persistence"),
        Severity.HIGH,
    ),
    (
        re.compile(r"\\appinit_dlls$", re.IGNORECASE),
        "AppInit_DLLs modified",
        MitreMapping("T1546.010", "AppInit DLLs", "Persistence"),
        Severity.HIGH,
    ),
    (
        re.compile(r"\\environment\\userinitmprlogonscript$", re.IGNORECASE),
        "Logon script (UserInitMprLogonScript) set",
        MitreMapping("T1037.001", "Logon Script (Windows)", "Persistence"),
        Severity.MEDIUM,
    ),
    (
        re.compile(r"^hku\\[^\\]+\\software\\classes\\clsid\\[^\\]+\\inprocserver32\\", re.IGNORECASE),
        "Per-user COM server registered (possible COM hijack)",
        MitreMapping("T1546.015", "Component Object Model Hijacking", "Persistence", "consistent_with"),
        Severity.MEDIUM,
    ),
]

# Values Windows itself uses; writing these back is not a hijack.
_WINLOGON_DEFAULTS = {"explorer.exe", "c:\\windows\\system32\\userinit.exe,", "c:\\windows\\system32\\userinit.exe"}


class RegistryHijackPoint(EventRule):
    meta = RuleMeta(
        rule_id="KG-PERSIST-004",
        name="Execution hijack registry value modified",
        description="IFEO debugger, SilentProcessExit, Winlogon, AppInit_DLLs, logon script or per-user COM server values set.",
        category="persistence",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        rationale=(
            "These values make Windows launch or load attacker-chosen code when another program or logon "
            "runs, and are rarely changed by ordinary software."
        ),
        required_evidence=("Sysmon 13 (registry value set) under the listed keys",),
        false_positives=(
            "Debuggers and developer tools registering IFEO debuggers (e.g. for crash analysis)",
            "Accessibility or shell tools registering per-user COM servers",
            "Enterprise logon scripts",
        ),
    )
    categories = frozenset({"registry_value_set"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        data = event.data or {}
        target = data.get("TargetObject") or ""
        details = (data.get("Details") or "").strip()
        for pattern, title, mitre, severity in _HIJACK_POINTS:
            if not pattern.search(target):
                continue
            if "winlogon" in title.lower() and details.lower() in _WINLOGON_DEFAULTS:
                return []
            if "AppInit" in title and details in ("", "(Empty)"):
                return []
            adjustments = _command_reasons(details)
            return [
                Finding(
                    title=f"{title} by {event.image or 'unknown process'}",
                    subject=self.subject(event.host_id, target),
                    event_ids=[event.id],
                    observations=[
                        self.observed(event, f"{self.process_label(event)} set {target} = {details!r}."),
                        *[self.inferred(f"Risk factor: {reason}.") for reason, _ in adjustments],
                    ],
                    entities=self.process_entities(event, ctx),
                    severity=severity,
                    confidence=Confidence.LOW if mitre.relationship == "consistent_with" else None,
                    adjustments=adjustments,
                    mitre=(mitre,),
                    process_guid=event.process_guid,
                    process_id=event.process_id,
                    image=event.image,
                )
            ]
        return []


class WmiEventSubscription(EventRule):
    meta = RuleMeta(
        rule_id="KG-PERSIST-005",
        name="WMI event subscription created",
        description="A WMI event consumer or filter-to-consumer binding was registered.",
        category="persistence",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        rationale=(
            "Permanent WMI subscriptions run code in response to system events without files in "
            "autostart locations. Command-line and script consumers are the risky types."
        ),
        required_evidence=("Sysmon 20 (consumer) or 21 (binding)",),
        false_positives=("Management agents (SCCM, monitoring tools) registering their own consumers",),
        mitre=(MitreMapping("T1546.003", "Windows Management Instrumentation Event Subscription", "Persistence"),),
    )
    categories = frozenset({"wmi"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        if event.source_event_id not in (20, 21):
            return []
        data = event.data or {}
        consumer_type = (data.get("Type") or "").lower()
        risky = consumer_type in ("command line", "script")
        name = data.get("Name") or data.get("Consumer") or "unnamed"
        return [
            Finding(
                title=f"WMI event subscription: {name}",
                subject=self.subject(event.host_id, name),
                event_ids=[event.id],
                observations=[
                    self.observed(
                        event,
                        f"WMI {data.get('EventType') or 'subscription'} {name!r} "
                        + (f"of type {data.get('Type')} " if data.get("Type") else "")
                        + (f"destination {data.get('Destination')!r} " if data.get("Destination") else "")
                        + f"by {data.get('User') or 'unknown user'}.",
                    )
                ],
                severity=Severity.HIGH if risky else None,
                adjustments=[("consumer executes a command or script", 15)] if risky else [],
            )
        ]
