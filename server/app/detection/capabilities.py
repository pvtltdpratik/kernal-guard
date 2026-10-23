"""Capability matrix: what KernelGuard can and cannot observe.

``design_visibility`` is what the sensor *can* show when installed and
configured as shipped. The API combines it with live sensor health to
report effective visibility on this host (e.g. everything Sysmon-based is
``not_observable`` while Sysmon is not installed).

Visibility levels:
- observable          the technique's key action produces a collected event
- partially_observable side effects are visible; the action itself is not,
                      or only some variants are
- not_observable      no collected telemetry shows it
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Visibility = Literal["observable", "partially_observable", "not_observable"]


@dataclass(frozen=True)
class Capability:
    technique_id: str
    technique: str
    design_visibility: Visibility
    sensors: tuple[str, ...]  # sensors that must be healthy for design visibility
    evidence: str
    gaps: str
    rules: tuple[str, ...] = ()


CAPABILITIES: tuple[Capability, ...] = (
    # --- Input capture / spyware -------------------------------------------
    Capability(
        "T1056.001", "Keylogging via SetWindowsHookEx with a hook DLL", "partially_observable", ("sysmon",),
        "Sysmon 7: the hook DLL appears loaded into many GUI processes (when unsigned or user-writable).",
        "The SetWindowsHookEx call is not logged; signed hook DLLs in protected paths are not alerted.",
        ("KG-SPY-001", "KG-SPY-002"),
    ),
    Capability(
        "T1056.001", "Keylogging via low-level hook (WH_KEYBOARD_LL)", "not_observable", (),
        "None. Low-level hooks run in the installing process and load no DLL elsewhere.",
        "Requires API/ETW telemetry (e.g. Microsoft-Windows-Win32k) not collected today.",
    ),
    Capability(
        "T1056.001", "Keylogging via GetAsyncKeyState / GetKeyboardState polling", "not_observable", (),
        "None.", "Polling APIs produce no events; would need user-mode API instrumentation.",
    ),
    Capability(
        "T1056.001", "Keylogging via Raw Input (RegisterRawInputDevices)", "not_observable", (),
        "None.", "No event is generated for raw input registration.",
    ),
    Capability(
        "T1056.001", "Keyboard filter driver", "partially_observable", ("sysmon",),
        "Sysmon 6: driver load with signature status (unsigned drivers alerted).",
        "The driver's role in the keyboard stack is not visible; signed malicious drivers are not distinguished.",
        ("KG-DRV-001",),
    ),
    Capability(
        "T1113", "Screen capture", "not_observable", (),
        "None.", "GDI/DXGI capture APIs are not instrumented.",
    ),
    Capability(
        "T1115", "Clipboard data", "not_observable", (),
        "Deliberately not collected (Sysmon 24 disabled for privacy).", "By design.",
    ),
    Capability(
        "T1123", "Audio capture", "not_observable", (), "None.", "Microphone access is not instrumented.",
    ),
    # --- Injection / credential access -----------------------------------
    Capability(
        "T1055.002", "Injection via CreateRemoteThread", "observable", ("sysmon",),
        "Sysmon 8 with source, target and start address/module.", "Thread purpose and payload are not visible.",
        ("KG-INJ-001",),
    ),
    Capability(
        "T1055.004", "APC injection / thread hijacking", "partially_observable", ("sysmon",),
        "Sysmon 10 call traces containing UNKNOWN() (as configured) may reveal the injector.",
        "QueueUserAPC/SetThreadContext are not logged directly.",
        ("KG-INJ-002",),
    ),
    Capability(
        "T1055.012", "Process hollowing / herpaderping", "partially_observable", ("sysmon",),
        "Sysmon 25 (process tampering).", "Not alerted by a dedicated rule yet; events are stored for investigation.",
    ),
    Capability(
        "T1003.001", "LSASS memory access", "observable", ("sysmon",),
        "Sysmon 10 targeting lsass.exe with access mask and call trace.",
        "Whether memory was read or dumped is not observed; PPL-protected LSASS changes outcomes.",
        ("KG-CRED-001",),
    ),
    # --- Persistence -----------------------------------------------------
    Capability(
        "T1547.001", "Registry Run keys", "observable", ("sysmon",),
        "Sysmon 13 under Run/RunOnce keys.", "Keys outside the configured filter are not logged.",
        ("KG-PERSIST-001",),
    ),
    Capability(
        "T1547.001", "Startup folder", "observable", ("sysmon",),
        "Sysmon 11 file creation in Startup folders.", "", ("KG-PERSIST-002",),
    ),
    Capability(
        "T1543.003", "Windows service creation", "observable", ("system",),
        "System 7045 (always), Security 4697 (with audit policy).",
        "Only suspicious binary paths are alerted; the installing process is not identified by 7045.",
        ("KG-PERSIST-003",),
    ),
    Capability(
        "T1546.012", "IFEO / SilentProcessExit", "observable", ("sysmon",),
        "Sysmon 13 under the configured keys.", "", ("KG-PERSIST-004",),
    ),
    Capability(
        "T1546.003", "WMI event subscription", "observable", ("sysmon",),
        "Sysmon 19/20/21.", "", ("KG-PERSIST-005",),
    ),
    Capability(
        "T1053.005", "Scheduled task", "partially_observable", ("sysmon",),
        "Sysmon 11 file creation under System32\\Tasks.",
        "Task XML is not parsed; Security 4698 and TaskScheduler/Operational are not collected yet. No rule.",
    ),
    # --- Execution / C2 / defence evasion --------------------------------
    Capability(
        "T1204.002", "Execution from user-writable locations", "observable", ("sysmon",),
        "Sysmon 1 (or Security 4688) image paths.", "Code-signing status of the image is not in the event.",
        ("KG-EXEC-001", "KG-FILE-001", "KG-FILE-002"),
    ),
    Capability(
        "T1218", "System binary proxy execution with network activity", "observable", ("sysmon",),
        "Sysmon 3 for mshta/rundll32/regsvr32/certutil/bitsadmin/PowerShell.",
        "Proxy execution without network activity is not alerted.",
        ("KG-NET-002",),
    ),
    Capability(
        "T1041", "Exfiltration over C2 channel", "partially_observable", ("sysmon",),
        "Sysmon 3 connection metadata and Sysmon 22 DNS queries.", "No byte counts or content; no reputation data.",
        ("KG-NET-001", "KG-NET-002"),
    ),
    Capability(
        "T1070.001", "Clear Windows event logs", "observable", ("system", "security"),
        "System 104, Security 1102.", "Stored for investigation; no dedicated alert rule yet.",
    ),
    Capability(
        "T1014", "Kernel rootkit / DKOM", "not_observable", (),
        "None.", "Requires kernel integrity tooling; out of scope for the current sensors.",
    ),
    Capability(
        "T1068", "Bring-your-own vulnerable driver", "partially_observable", ("sysmon",),
        "Sysmon 6 records hash and signer of every driver load.",
        "No vulnerable-driver hash list is configured, so signed vulnerable drivers are not alerted.",
    ),
)


def effective_visibility(capability: Capability, unhealthy: dict[str, str]) -> tuple[Visibility, str | None]:
    """``unhealthy`` maps sensor name -> reason it is not providing telemetry."""
    if capability.design_visibility == "not_observable":
        return "not_observable", None
    missing = [s for s in capability.sensors if s in unhealthy]
    if not missing:
        return capability.design_visibility, None
    detail = "; ".join(f"{s}: {unhealthy[s]}" for s in missing)
    if len(missing) < len(capability.sensors):  # e.g. log clearing: system OR security suffices
        return capability.design_visibility, f"Reduced coverage ({detail})."
    return "not_observable", f"No telemetry on this host ({detail})."
