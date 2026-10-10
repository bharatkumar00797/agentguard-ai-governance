"""Risk scoring: combine findings into a 0-100 score.

The highest finding dominates, and additional findings add diminishing weight, so ten
low-severity hits do not outrank one critical secret leak.
"""

from __future__ import annotations

from agentguard.models import SEVERITY_POINTS, Finding


def risk_score(findings: list[Finding], *, base: int = 0) -> int:
    points = sorted((SEVERITY_POINTS[f.severity] for f in findings), reverse=True)
    if not points:
        return max(0, min(100, base))
    score = float(points[0])
    for p in points[1:]:
        score += p * 0.25 * (100 - score) / 100
    return max(0, min(100, round(score + base)))


def risk_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
