"""Registry of detection rules. Add new rules here."""

from __future__ import annotations

from app.detection.rules.base import CorrelationRule, EventRule
from app.detection.rules.executable import ProcessFromUserWritablePath, UnsignedDriverLoad
from app.detection.rules.files import DroppedThenExecuted, ExecutableDroppedInUserWritablePath
from app.detection.rules.injection import AccessFromUnbackedCode, LsassMemoryAccess, RemoteThreadCreated
from app.detection.rules.network import LolbinNetworkConnection, UserWritableProcessNetwork
from app.detection.rules.persistence import (
    RegistryHijackPoint,
    RunKeyModified,
    StartupFolderFile,
    SuspiciousServiceInstall,
    WmiEventSubscription,
)
from app.detection.rules.spyware import CorrelatedSpywareBehaviour, SameDllLoadedIntoManyProcesses

EVENT_RULES: list[EventRule] = [
    ProcessFromUserWritablePath(),
    UnsignedDriverLoad(),
    RunKeyModified(),
    StartupFolderFile(),
    SuspiciousServiceInstall(),
    RegistryHijackPoint(),
    WmiEventSubscription(),
    RemoteThreadCreated(),
    LsassMemoryAccess(),
    AccessFromUnbackedCode(),
    UserWritableProcessNetwork(),
    LolbinNetworkConnection(),
    ExecutableDroppedInUserWritablePath(),
    DroppedThenExecuted(),
    SameDllLoadedIntoManyProcesses(),
]

CORRELATION_RULES: list[CorrelationRule] = [CorrelatedSpywareBehaviour()]

RULES_BY_ID: dict[str, EventRule | CorrelationRule] = {
    rule.meta.rule_id: rule for rule in [*EVENT_RULES, *CORRELATION_RULES]
}

assert len(RULES_BY_ID) == len(EVENT_RULES) + len(CORRELATION_RULES), "duplicate rule IDs"
