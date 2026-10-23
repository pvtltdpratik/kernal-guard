"""Category 5: suspicious file creation and execution from unusual locations."""

from __future__ import annotations

import re
from datetime import timedelta

from app.db.models import Event
from app.detection.context import DetectionContext
from app.detection.paths import (
    EXECUTABLE_EXTENSIONS,
    basename,
    extension,
    is_executable_or_script,
    is_user_writable,
    normalize_path,
)
from app.detection.rules.base import EventRule
from app.detection.types import Confidence, Finding, RuleMeta, Severity

_POWERSHELL_POLICY_TEST = re.compile(r"\\appdata\\local\\temp\\__psscriptpolicytest_[a-z0-9]{8}\.[a-z0-9]{3}\.psm?1$", re.IGNORECASE)


class ExecutableDroppedInUserWritablePath(EventRule):
    meta = RuleMeta(
        rule_id="KG-FILE-001",
        name="Executable or script written to a user-writable location",
        description="A file with an executable or script extension was created in Temp, Public or similar.",
        category="file",
        severity=Severity.INFORMATIONAL,
        confidence=Confidence.LOW,
        rationale="Staging payloads in user-writable locations is common. On its own this is context, not a threat indicator.",
        required_evidence=("Sysmon 11 (file created) for executable/script extensions",),
        false_positives=("Browsers, installers and updaters writing to %TEMP% (very common)",),
        version=2,
    )
    categories = frozenset({"file_create"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        target = (event.data or {}).get("TargetFilename") or ""
        if not (is_executable_or_script(target) and is_user_writable(target)):
            return []
        # v2 (measured 2026-10-24): every PowerShell start writes and deletes
        # %TEMP%\__PSScriptPolicyTest_<random>.ps1|psm1 to probe AppLocker
        # policy. Only that exact pattern, written by PowerShell itself, is excluded.
        if _POWERSHELL_POLICY_TEST.search(target) and basename(event.image) in ("powershell.exe", "pwsh.exe"):
            return []
        path = normalize_path(target)
        return [
            Finding(
                title=f"Executable written to user-writable path: {target}",
                subject=self.subject(event.host_id, path),
                event_ids=[event.id],
                observations=[self.observed(event, f"{self.process_label(event)} created {target}.")],
                entities=[*self.process_entities(event, ctx), self.file_entity(event.host_id, path)],
                process_guid=event.process_guid,
                process_id=event.process_id,
                image=event.image,
            )
        ]


class DroppedThenExecuted(EventRule):
    meta = RuleMeta(
        rule_id="KG-FILE-002",
        name="Newly written executable was run",
        description="A process started from an executable that another process wrote shortly before.",
        category="file",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        rationale=(
            "Write-then-execute links a dropper to its payload. Correlation works in both directions, "
            "so events arriving out of order are still matched."
        ),
        required_evidence=("Sysmon 11 (file created) and Sysmon 1 (process creation) for the same path",),
        false_positives=("Installers and updaters that download and run a component", "Developers building and running their own binaries"),
        thresholds={"window_minutes": 24 * 60},
    )
    categories = frozenset({"file_create", "process_creation"})

    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]:
        window = timedelta(minutes=float(self.threshold(ctx, "window_minutes")))
        if event.category == "process_creation":
            path = normalize_path(event.image)
            if extension(path) not in EXECUTABLE_EXTENSIONS:
                return []
            drops = ctx.events_with_data_value(
                event.host_id, "file_create", "TargetFilename", path, event.timestamp - window, event.timestamp
            )
            return [self._finding(drops[-1], event, ctx)] if drops else []

        target = normalize_path((event.data or {}).get("TargetFilename"))
        if extension(target) not in EXECUTABLE_EXTENSIONS:
            return []
        # Out-of-order delivery: the execution may already be stored.
        runs = ctx.process_creations_of_image(event.host_id, target, event.timestamp, event.timestamp + window)
        return [self._finding(event, runs[0], ctx)] if runs else []

    def _finding(self, drop: Event, run: Event, ctx: DetectionContext) -> Finding:
        path = normalize_path(run.image)
        writable = is_user_writable(path)
        delay = run.timestamp - drop.timestamp
        return Finding(
            title=f"Dropped executable was run: {run.image}",
            subject=self.subject(run.host_id, path, run.process_guid),
            event_ids=[drop.id, run.id],
            observations=[
                self.observed(drop, f"{self.process_label(drop)} wrote {(drop.data or {}).get('TargetFilename')}."),
                self.observed(run, f"{delay.total_seconds():.0f}s later, it was started as {self.process_label(run)}."),
            ],
            entities=[
                *self.process_entities(drop, ctx),
                *self.process_entities(run, ctx),
                self.file_entity(run.host_id, path),
            ],
            severity=None if writable else Severity.LOW,
            adjustments=[("executed file is in a user-writable location", 10)] if writable else [],
            uncertainty=["Path equality is used; a file replaced between write and execution would not be distinguished."],
            process_guid=run.process_guid,
            process_id=run.process_id,
            image=run.image,
        )
