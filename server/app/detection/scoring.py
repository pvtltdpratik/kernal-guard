"""Explainable risk scoring.

Alert score (0-100):
    (severity points + adjustment points) x confidence multiplier, capped at 100.

Incident score (0-100):
    Only *active* alerts count (false positives contribute 0). Each rule
    counts once, at its highest-scoring alert, so repeated events or several
    alerts from the same rule are not treated as independent evidence.
    score = top rule score + 20% of each further distinct rule's score, capped.

Every term is returned in a breakdown list so the UI can show exactly how
a number was produced.
"""

from __future__ import annotations

from typing import Any

from app.db.models import Alert
from app.detection.types import Confidence, Severity

SEVERITY_POINTS = {
    Severity.INFORMATIONAL: 10,
    Severity.LOW: 25,
    Severity.MEDIUM: 50,
    Severity.HIGH: 75,
    Severity.CRITICAL: 90,
}
CONFIDENCE_MULTIPLIER = {Confidence.LOW: 0.6, Confidence.MEDIUM: 0.8, Confidence.HIGH: 1.0}
ADDITIONAL_RULE_WEIGHT = 0.2
INACTIVE_STATUSES = {"false_positive"}


def score_alert(
    severity: Severity, confidence: Confidence, adjustments: list[tuple[str, int]]
) -> tuple[int, list[dict[str, Any]]]:
    breakdown: list[dict[str, Any]] = [
        {"factor": "severity", "value": severity.value, "points": SEVERITY_POINTS[severity]}
    ]
    points = SEVERITY_POINTS[severity]
    for reason, delta in adjustments:
        breakdown.append({"factor": "adjustment", "reason": reason, "points": delta})
        points += delta
    multiplier = CONFIDENCE_MULTIPLIER[confidence]
    breakdown.append({"factor": "confidence", "value": confidence.value, "multiplier": multiplier})
    score = max(0, min(100, round(points * multiplier)))
    breakdown.append({"factor": "total", "points": score, "capped": points * multiplier > 100})
    return score, breakdown


def score_incident(alerts: list[Alert]) -> tuple[int, Severity, list[dict[str, Any]]]:
    breakdown: list[dict[str, Any]] = []
    best_per_rule: dict[str, Alert] = {}
    for alert in alerts:
        if alert.status in INACTIVE_STATUSES:
            breakdown.append(
                {"alert_id": alert.id, "rule_id": alert.rule_id, "score": alert.risk_score,
                 "weight": 0, "contribution": 0, "reason": f"excluded: marked {alert.status}"}
            )
            continue
        current = best_per_rule.get(alert.rule_id)
        if current is None or alert.risk_score > current.risk_score:
            if current is not None:
                breakdown.append(_duplicate_rule_entry(current))
            best_per_rule[alert.rule_id] = alert
        else:
            breakdown.append(_duplicate_rule_entry(alert))

    ranked = sorted(best_per_rule.values(), key=lambda a: (-a.risk_score, a.rule_id))
    total = 0.0
    severity = Severity.INFORMATIONAL
    for index, alert in enumerate(ranked):
        weight = 1.0 if index == 0 else ADDITIONAL_RULE_WEIGHT
        contribution = alert.risk_score * weight
        total += contribution
        severity = max(severity, Severity(alert.severity), key=lambda s: s.rank)
        breakdown.insert(
            index,
            {"alert_id": alert.id, "rule_id": alert.rule_id, "score": alert.risk_score, "weight": weight,
             "contribution": round(contribution, 1),
             "reason": "highest-scoring rule" if index == 0 else "additional distinct rule"},
        )
    score = min(100, round(total))
    return score, severity, breakdown


def _duplicate_rule_entry(alert: Alert) -> dict[str, Any]:
    return {"alert_id": alert.id, "rule_id": alert.rule_id, "score": alert.risk_score, "weight": 0,
            "contribution": 0, "reason": "same rule already counted (not independent evidence)"}
