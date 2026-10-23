"""Core detection types shared by rules, scoring and the API."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_rank(cls, rank: int) -> Severity:
        return next(s for s, r in _SEVERITY_RANK.items() if r == rank)


_SEVERITY_RANK = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# How strongly the evidence supports a technique mapping:
# observed        - the event *is* the technique (e.g. a Run key was written)
# consistent_with - the evidence fits the technique but other explanations exist
MitreRelationship = Literal["observed", "consistent_with"]


@dataclass(frozen=True)
class MitreMapping:
    technique_id: str
    name: str
    tactic: str
    relationship: MitreRelationship = "observed"


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    name: str
    description: str
    category: str  # executable | persistence | injection | network | file | spyware
    severity: Severity
    confidence: Confidence
    rationale: str
    required_evidence: tuple[str, ...]
    false_positives: tuple[str, ...]
    mitre: tuple[MitreMapping, ...] = ()
    thresholds: dict[str, float | int] = field(default_factory=dict)
    version: int = 1


@dataclass(frozen=True)
class Observation:
    """One statement supporting a finding.

    ``kind="observed"`` statements must cite the event they come from;
    ``kind="inferred"`` statements are the rule's interpretation.
    """

    kind: Literal["observed", "inferred"]
    text: str
    event_id: str | None = None


@dataclass
class Finding:
    """A rule's output for one subject. Becomes (or updates) an alert."""

    title: str
    subject: str  # stable identity used for alert deduplication
    event_ids: list[str]
    observations: list[Observation]
    entities: list[str] = field(default_factory=list)  # correlation keys, e.g. process:{guid}
    uncertainty: list[str] = field(default_factory=list)
    severity: Severity | None = None  # override rule default with justification below
    confidence: Confidence | None = None
    adjustments: list[tuple[str, int]] = field(default_factory=list)  # (reason, points)
    mitre: tuple[MitreMapping, ...] | None = None  # override rule default when sub-case specific
    process_guid: str | None = None
    process_id: int | None = None
    image: str | None = None
