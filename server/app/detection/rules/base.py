"""Rule interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from app.db.models import Alert, Event, Incident
from app.detection.context import DetectionContext
from app.detection.processes import guid_key
from app.detection.types import Finding, Observation, RuleMeta


class EventRule(ABC):
    """Evaluates one stored event (with read access to context)."""

    meta: ClassVar[RuleMeta]
    categories: ClassVar[frozenset[str]]

    def threshold(self, ctx: DetectionContext, name: str) -> float | int:
        return ctx.config.threshold(self.meta.rule_id, name, self.meta.thresholds[name])

    @abstractmethod
    def evaluate(self, event: Event, ctx: DetectionContext) -> list[Finding]: ...

    # Helpers shared by rules -------------------------------------------

    def subject(self, *parts: object) -> str:
        return "|".join([self.meta.rule_id, *(str(p).lower() for p in parts if p is not None)])

    @staticmethod
    def observed(event: Event, text: str) -> Observation:
        return Observation(kind="observed", text=text, event_id=event.id)

    @staticmethod
    def inferred(text: str) -> Observation:
        return Observation(kind="inferred", text=text)

    @staticmethod
    def process_entities(event: Event, ctx: DetectionContext) -> list[str]:
        """Correlation entities for the acting process and its parent."""
        entities: list[str] = []
        process = ctx.process(event)
        if process is not None:
            entities.append(f"process:{process.key}")
            if process.parent_process_guid:
                entities.append(f"process:{guid_key(event.host_id, process.parent_process_guid)}")
        elif event.process_guid:
            entities.append(f"process:{guid_key(event.host_id, event.process_guid)}")
        return entities

    @staticmethod
    def file_entity(host_id: str, path: str) -> str:
        return f"file:{host_id}:{path.lower()}"

    @staticmethod
    def process_label(event: Event) -> str:
        pid = f" (PID {event.process_id})" if event.process_id is not None else ""
        return f"{event.image or 'unknown process'}{pid}"


class CorrelationRule(ABC):
    """Evaluates the alerts of an incident after correlation."""

    meta: ClassVar[RuleMeta]

    def threshold(self, ctx: DetectionContext, name: str) -> float | int:
        return ctx.config.threshold(self.meta.rule_id, name, self.meta.thresholds[name])

    @abstractmethod
    def evaluate(self, incident: Incident, alerts: list[Alert], ctx: DetectionContext) -> list[Finding]: ...
