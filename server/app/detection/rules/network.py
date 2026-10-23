"""Category 4: unusual combinations of process and network activity."""

from __future__ import annotations

import ipaddress

from app.db.models import Event
from app.detection.context import DetectionContext
from app.detection.paths import basename, is_user_writable, normalize_path
from app.detection.rules.base import EventRule
from app.detection.types import Confidence, Finding, MitreMapping, RuleMeta, Severity

_LOLBIN_MITRE = {
    "powershell.exe": MitreMapping("T1059.001", "PowerShell", "Execution", "consistent_with"),
    "pwsh.exe": MitreMapping("T1059.001", "PowerShell", "Execution", "consistent_with"),
    "mshta.exe": MitreMapping("T1218.005", "Mshta", "Defense Evasion", "consistent_with"),
    "rundll32.exe": MitreMapping("T1218.011", "Rundll32", "Defense Evasion", "consistent_with"),
    "regsvr32.exe": MitreMapping("T1218.010", "Regsvr32", "Defense Evasion", "consistent_with"),
    "certutil.exe": MitreMapping("T1105", "Ingress Tool Transfer", "Command and Control", "consistent_with"),
    "bitsadmin.exe": MitreMapping("T1197", "BITS Jobs", "Defense Evasion", "consistent_with"),
    "wscript.exe": MitreMapping("T1059.005", "Visual Basic", "Execution", "consistent_with"),
    "cscript.exe": MitreMapping("T1059.005", "Visual Basic", "Execution", "consistent_with"),
}
# msiexec is deliberately absent: it routinely downloads during legitimate installs.
_NETWORK_LOLBINS = frozenset(_LOLBIN_MITRE)


def public_destination(event: Event) -> str | None:
    """Destination IP if the connection is outbound to a public address."""
    data = event.data or {}
    if (data.get("Initiated") or "").lower() != "true":
        return None
    try:
        address = ipaddress.ip_address(data.get("DestinationIp") or "")
    except ValueError:
        return None
    if not address.is_global:
        return None
    return str(address)


def _destination_text(event: Event, ip: str) -> str:
    data = event.data or {}
    host = data.get("DestinationHostname")
    host_text = f" ({host})" if host and host != "-" else ""
    return f"{ip}{host_text}:{data.get('DestinationPort')}/{data.get('Protocol') or 'tcp'}"


class UserWritableProcessNetwork(EventRule):
    meta = RuleMeta(
        rule_id="KG-NET-001",
        name="Process from user-writable location connected to the internet",
        description="An outbound connection to a public address from a process running out of Temp, Public or similar.",
        category="network",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        rationale="Droppers and remote-access implants often run from user-writable locations and contact external servers.",
        required_evidence=("Sysmon 3 (network connection) with the process image path",),
        false_positives=(
            "Installers and updaters downloading components from %TEMP%",
            "Portable applications checking for updates",
        ),
    )
    categories = frozenset({"network_connection"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        if not event.image or not is_user_writable(event.image):
            return []
        ip = public_destination(event)
        if ip is None:
            return []
        return [
            Finding(
                title=f"Internet connection from user-writable process {event.image}",
                subject=self.subject(event.host_id, event.process_guid or normalize_path(event.image)),
                event_ids=[event.id],
                observations=[
                    self.observed(event, f"{self.process_label(event)} connected to {_destination_text(event, ip)}."),
                    self.inferred("The process runs from a user-writable location and communicates with a public address."),
                ],
                entities=self.process_entities(event, ctx),
                uncertainty=["Connection content and volume are not observed; destination reputation is not checked."],
                process_guid=event.process_guid,
                process_id=event.process_id,
                image=event.image,
            )
        ]


class LolbinNetworkConnection(EventRule):
    meta = RuleMeta(
        rule_id="KG-NET-002",
        name="Script host or system binary connected to the internet",
        description="PowerShell, mshta, rundll32, regsvr32, certutil, bitsadmin or a script host made an outbound public connection.",
        category="network",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        rationale=(
            "These built-in binaries can download and run code while appearing as trusted Windows "
            "components; direct internet connections from them are uncommon on most desktops."
        ),
        required_evidence=("Sysmon 3 (network connection)",),
        false_positives=(
            "PowerShell module installation (PowerShell Gallery) and admin scripts",
            "Windows components using BITS for updates",
            "rundll32 hosting legitimate network-capable DLLs (e.g. some control panel items)",
        ),
    )
    categories = frozenset({"network_connection"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        name = basename(event.image)
        if name not in _NETWORK_LOLBINS:
            return []
        ip = public_destination(event)
        if ip is None:
            return []
        mitre = _LOLBIN_MITRE.get(name)
        return [
            Finding(
                title=f"{name} connected to the internet",
                subject=self.subject(event.host_id, event.process_guid or name),
                event_ids=[event.id],
                observations=[self.observed(event, f"{self.process_label(event)} connected to {_destination_text(event, ip)}.")],
                entities=self.process_entities(event, ctx),
                mitre=(mitre,) if mitre else (),
                uncertainty=["The command line of the process determines intent; review it in process investigation."],
                process_guid=event.process_guid,
                process_id=event.process_id,
                image=event.image,
            )
        ]
