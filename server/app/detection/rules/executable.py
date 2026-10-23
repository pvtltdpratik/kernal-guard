"""Category 1: suspicious executable or driver activity."""

from __future__ import annotations

from app.db.models import Event
from app.detection.context import DetectionContext
from app.detection.paths import is_user_writable, normalize_path
from app.detection.rules.base import EventRule
from app.detection.types import Confidence, Finding, RuleMeta, Severity


class ProcessFromUserWritablePath(EventRule):
    meta = RuleMeta(
        rule_id="KG-EXEC-001",
        name="Process started from a user-writable location",
        description="A process image ran from Temp, Users\\Public, the ProgramData root, the Recycle Bin or similar.",
        category="executable",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        rationale=(
            "Malware commonly stages and runs from locations any user can write to. Installed software "
            "normally runs from Program Files or per-vendor AppData folders."
        ),
        required_evidence=("Sysmon 1 (process creation) or Security 4688",),
        false_positives=(
            "Installers and self-extracting archives unpacking to %TEMP%",
            "Software updaters that run a downloaded stub from %TEMP%",
            "Portable tools copied to Users\\Public",
        ),
    )
    categories = frozenset({"process_creation"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        if not event.image or not is_user_writable(event.image):
            return []
        observations = [
            self.observed(event, f"Process {self.process_label(event)} started from {event.image}."),
            self.inferred("This path is writable by standard users; legitimately installed software rarely runs from it."),
        ]
        if event.parent_image:
            observations.insert(1, self.observed(event, f"Parent process: {event.parent_image}."))
        uncertainty = ["Process-creation events do not report the image's code-signing status."]
        if not event.sha256:
            uncertainty.append("No file hash was recorded for this image.")
        return [
            Finding(
                title=f"Process started from user-writable path: {event.image}",
                subject=self.subject(event.host_id, normalize_path(event.image)),
                event_ids=[event.id],
                observations=observations,
                entities=[*self.process_entities(event, ctx), self.file_entity(event.host_id, normalize_path(event.image))],
                uncertainty=uncertainty,
                process_guid=event.process_guid,
                process_id=event.process_id,
                image=event.image,
            )
        ]


class UnsignedDriverLoad(EventRule):
    meta = RuleMeta(
        rule_id="KG-DRV-001",
        name="Unsigned or invalidly signed driver loaded",
        description="A kernel driver loaded without a valid signature.",
        category="executable",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        rationale=(
            "64-bit Windows requires signed drivers unless test signing or other enforcement has been "
            "weakened. An unsigned or invalid signature on a loaded driver means the code runs with "
            "kernel privileges without a trusted publisher."
        ),
        required_evidence=("Sysmon 6 (driver loaded) with Signed/SignatureStatus fields",),
        false_positives=(
            "Development machines with test signing enabled",
            "Legacy hardware drivers with expired or revoked certificates",
            "Signature status reported as non-Valid because revocation checking is disabled",
        ),
    )
    categories = frozenset({"driver_load"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        status = event.signature_status
        if event.signed is not False and (status is None or status == "Valid"):
            return []
        driver = (event.data or {}).get("ImageLoaded") or "unknown driver"
        observations = [
            self.observed(
                event,
                f"Driver {driver} loaded; Signed={event.signed}, SignatureStatus={status or 'not reported'}"
                + (f", Signature={event.signature}" if event.signature else "")
                + ".",
            ),
            self.inferred("Unsigned kernel code bypasses the normal driver trust model."),
        ]
        return [
            Finding(
                title=f"Unsigned or invalidly signed driver loaded: {driver}",
                subject=self.subject(event.host_id, event.sha256 or normalize_path(driver)),
                event_ids=[event.id],
                observations=observations,
                entities=[self.file_entity(event.host_id, normalize_path(driver))],
                uncertainty=[
                    "Signed vulnerable drivers (BYOVD) are NOT detected: no vulnerable-driver hash list is configured.",
                    "Driver load events do not identify which process requested the load.",
                ],
            )
        ]
