"""Core data models shared by the policy engine, detectors and guard."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_POINTS: dict[Severity, int] = {
    Severity.LOW: 10,
    Severity.MEDIUM: 25,
    Severity.HIGH: 50,
    Severity.CRITICAL: 90,
}


class Verdict(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


VERDICT_ORDER: dict[Verdict, int] = {
    Verdict.ALLOW: 0,
    Verdict.REDACT: 1,
    Verdict.REQUIRE_APPROVAL: 2,
    Verdict.DENY: 3,
}


def strictest(*verdicts: Verdict) -> Verdict:
    """Return the most restrictive verdict (deny > approval > redact > allow)."""
    return max(verdicts, key=lambda v: VERDICT_ORDER[v], default=Verdict.ALLOW)


class Finding(BaseModel):
    """A single issue raised by a detector or a policy rule."""

    model_config = ConfigDict(frozen=True)

    source: str
    code: str
    severity: Severity
    message: str
    span: tuple[int, int] | None = None


class ToolCall(BaseModel):
    """A tool invocation an agent proposes to make."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent: str = Field(default="default", min_length=1, max_length=64)
    cost: float = Field(default=0.0, ge=0)


class Decision(BaseModel):
    """The outcome of evaluating a text or tool call."""

    kind: str  # "input" | "output" | "tool_call"
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    findings: list[Finding] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    redacted_text: str | None = None
    redacted_arguments: dict[str, Any] | None = None
    rule: str | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict in (Verdict.ALLOW, Verdict.REDACT)
