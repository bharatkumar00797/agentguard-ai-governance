"""Request and response schemas for the HTTP API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agentguard.agent import Step
from agentguard.guard import Approval
from agentguard.models import Decision, ToolCall
from agentguard.policy import Policy

POLICY_NAME = r"^[a-z0-9-]{1,64}$"


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyRef(_In):
    """Either a packaged policy name or (trusted callers only) an inline policy document."""

    policy: str | None = Field(default=None, pattern=POLICY_NAME)
    custom_policy: Policy | None = None


class TextIn(PolicyRef):
    text: str = Field(min_length=1, max_length=20_000)
    agent: str = Field(default="api", min_length=1, max_length=64)


class ScanIn(PolicyRef):
    text: str = Field(min_length=1, max_length=20_000)
    mode: Literal["input", "output"] = "input"


class ToolCallIn(PolicyRef):
    call: ToolCall


class DecisionOut(BaseModel):
    decision: Decision
    policy: str
    approval_id: str | None = None


class ResolveIn(_In):
    reviewer: str = Field(default="reviewer", min_length=1, max_length=64)
    note: str = Field(default="", max_length=500)


class ApprovalListOut(BaseModel):
    approvals: list[Approval]


class AuditOut(BaseModel):
    total: int
    head: str
    records: list[dict[str, Any]]


class VerifyOut(BaseModel):
    ok: bool
    records: int
    error: str | None = None
    bad_index: int | None = None
    head: str


class PolicySummary(BaseModel):
    name: str
    description: str
    default_action: str
    rules: int


class PolicyListOut(BaseModel):
    policies: list[PolicySummary]


class ScenarioSummary(BaseModel):
    id: str
    title: str
    description: str
    policy: str
    expect: dict[str, int]


class ScenarioListOut(BaseModel):
    scenarios: list[ScenarioSummary]


class ScenarioRunOut(BaseModel):
    scenario: str
    policy: str
    provider: str
    meets_expectations: bool
    steps: list[Step]
    final: str | None
    blocked: int
    approvals: int
    executed: int
    audit_head: str


class HealthOut(BaseModel):
    status: Literal["ok"] = "ok"
    version: str


class ConfigOut(BaseModel):
    version: str
    access_mode: str
    auth_required: bool
    authenticated: bool
    custom_policies_allowed: bool
    provider: str
    policies: list[str]
    scenarios: list[str]
    audit_signed: bool
    audit_persistent: bool
