"""Declarative policy model (YAML / JSON) and the tool-call policy engine.

A policy is a list of tool rules evaluated first-match-wins (tool names support ``*`` globs),
plus a default action and text-scanning settings. Rules can deny, allow, require human
approval, constrain arguments, and apply rate limits and spend budgets.
"""

from __future__ import annotations

import fnmatch
import json
import re
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentguard.limits import BudgetTracker, RateLimiter
from agentguard.models import Finding, Severity, ToolCall, Verdict

Action = Literal["allow", "deny", "require_approval"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ArgConstraint(_Strict):
    """Constraints for a single tool argument."""

    required: bool = False
    type: Literal["string", "number", "integer", "boolean", "array", "object"] | None = None
    enum: list[Any] | None = None
    min: float | None = None
    max: float | None = None
    max_length: int | None = Field(default=None, ge=0)
    pattern: str | None = None
    deny_patterns: list[str] = Field(default_factory=list)
    allowed_prefixes: list[str] | None = None
    allowed_domains: list[str] | None = None

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, v: str | None) -> str | None:
        if v is not None:
            re.compile(v)
        return v

    @field_validator("deny_patterns")
    @classmethod
    def _all_compile(cls, v: list[str]) -> list[str]:
        for p in v:
            re.compile(p)
        return v


class RateLimit(_Strict):
    max_calls: int = Field(ge=1)
    per_seconds: float = Field(gt=0)


class ToolRule(_Strict):
    name: str = Field(min_length=1)
    tools: list[str] = Field(min_length=1)
    agents: list[str] | None = None
    action: Action = "allow"
    reason: str = ""
    args: dict[str, ArgConstraint] = Field(default_factory=dict)
    allow_extra_args: bool = True
    rate_limit: RateLimit | None = None
    budget: float | None = Field(default=None, ge=0)
    approval_when: dict[str, ArgConstraint] = Field(default_factory=dict)

    def matches(self, call: ToolCall) -> bool:
        if self.agents is not None and not any(
            fnmatch.fnmatchcase(call.agent, a) for a in self.agents
        ):
            return False
        return any(fnmatch.fnmatchcase(call.tool, t) for t in self.tools)


class TextPolicy(_Strict):
    block_prompt_injection: bool = True
    block_jailbreak: bool = True
    redact_sensitive_data: bool = True
    block_secrets_in_output: bool = True
    scan_tool_arguments: bool = True
    max_input_chars: int = Field(default=20_000, ge=1)


class Thresholds(_Strict):
    approval: int = Field(default=60, ge=0, le=100)
    deny: int = Field(default=85, ge=0, le=100)


class Policy(_Strict):
    name: str = Field(min_length=1)
    version: str = "1"
    description: str = ""
    default_action: Action = "deny"
    text: TextPolicy = Field(default_factory=TextPolicy)
    risk_thresholds: Thresholds = Field(default_factory=Thresholds)
    tools: list[ToolRule] = Field(default_factory=list)


def load_policy(source: str | Path) -> Policy:
    """Load a policy from a YAML/JSON file or the name of a packaged policy."""
    path = Path(source)
    if path.suffix.lower() in {".yaml", ".yml", ".json"} and path.exists():
        raw = path.read_text(encoding="utf-8")
        suffix = path.suffix.lower()
    else:
        name = str(source)
        if not re.fullmatch(r"[a-z0-9-]+", name):
            raise FileNotFoundError(f"policy not found: {source}")
        ref = resources.files("agentguard") / "policies" / f"{name}.yaml"
        if not ref.is_file():
            raise FileNotFoundError(f"policy not found: {source}")
        raw = ref.read_text(encoding="utf-8")
        suffix = ".yaml"
    data = json.loads(raw) if suffix == ".json" else yaml.safe_load(raw)
    return Policy.model_validate(data)


def packaged_policies() -> list[str]:
    root = resources.files("agentguard") / "policies"
    return sorted(p.name[:-5] for p in root.iterdir() if p.name.endswith(".yaml"))


_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,),
    "number": (int, float),
    "integer": (int,),
    "boolean": (bool,),
    "array": (list,),
    "object": (dict,),
}


def _domain_of(value: str) -> str | None:
    m = re.match(r"^[a-z][a-z0-9+.-]*://(?:[^@/]*@)?([^/:?#]+)", value.strip(), re.IGNORECASE)
    if m:
        return m.group(1).lower().rstrip(".")
    if "@" in value:
        return value.rsplit("@", 1)[1].strip().lower().rstrip(".")
    return None


def check_argument(name: str, value: Any, c: ArgConstraint) -> list[str]:
    """Return human-readable violations of one argument against its constraint."""
    errors: list[str] = []
    if c.type is not None:
        ok = isinstance(value, _TYPES[c.type])
        if c.type in ("number", "integer") and isinstance(value, bool):
            ok = False
        if not ok:
            return [f"argument '{name}' must be of type {c.type}"]
    if c.enum is not None and value not in c.enum:
        errors.append(f"argument '{name}' must be one of {c.enum}")
    if isinstance(value, int | float) and not isinstance(value, bool):
        if c.min is not None and value < c.min:
            errors.append(f"argument '{name}' is below the minimum {c.min:g}")
        if c.max is not None and value > c.max:
            errors.append(f"argument '{name}' exceeds the maximum {c.max:g}")
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    if c.max_length is not None and len(text) > c.max_length:
        errors.append(f"argument '{name}' is longer than {c.max_length} characters")
    if c.pattern is not None and isinstance(value, str) and not re.fullmatch(c.pattern, value):
        errors.append(f"argument '{name}' does not match the required pattern")
    for p in c.deny_patterns:
        if re.search(p, text, re.IGNORECASE):
            errors.append(f"argument '{name}' matches a forbidden pattern ({p})")
    if c.allowed_prefixes is not None and isinstance(value, str):
        norm = value.replace("\\", "/")
        if ".." in norm.split("/") or not any(norm.startswith(p) for p in c.allowed_prefixes):
            errors.append(f"argument '{name}' is outside the allowed locations")
    if c.allowed_domains is not None and isinstance(value, str):
        dom = _domain_of(value)
        if dom is None or not any(dom == d or dom.endswith("." + d) for d in c.allowed_domains):
            errors.append(f"argument '{name}' targets a domain that is not allowlisted")
    return errors


class PolicyResult(BaseModel):
    verdict: Verdict
    rule: str | None
    reasons: list[str]
    findings: list[Finding]


class PolicyEngine:
    """Evaluates proposed tool calls against a :class:`Policy`. Stateful for limits."""

    def __init__(
        self,
        policy: Policy,
        rate_limiter: RateLimiter | None = None,
        budgets: BudgetTracker | None = None,
    ) -> None:
        self.policy = policy
        self.rate_limiter = rate_limiter or RateLimiter()
        self.budgets = budgets or BudgetTracker()

    def match(self, call: ToolCall) -> ToolRule | None:
        return next((r for r in self.policy.tools if r.matches(call)), None)

    def evaluate(self, call: ToolCall, *, consume: bool = True) -> PolicyResult:
        rule = self.match(call)
        if rule is None:
            verdict = Verdict(self.policy.default_action)
            reason = f"no rule matches tool '{call.tool}'; default action is {verdict.value}"
            sev = Severity.HIGH if verdict is Verdict.DENY else Severity.LOW
            return PolicyResult(
                verdict=verdict,
                rule=None,
                reasons=[reason],
                findings=[Finding(source="policy", code="no_rule", severity=sev, message=reason)],
            )

        def deny(code: str, reasons: list[str], sev: Severity = Severity.HIGH) -> PolicyResult:
            return PolicyResult(
                verdict=Verdict.DENY,
                rule=rule.name,
                reasons=reasons,
                findings=[
                    Finding(source="policy", code=code, severity=sev, message=r) for r in reasons
                ],
            )

        if rule.action == "deny":
            return deny("tool_denied", [rule.reason or f"tool '{call.tool}' is denied by policy"])

        errors: list[str] = []
        for arg, c in rule.args.items():
            if arg not in call.arguments:
                if c.required:
                    errors.append(f"missing required argument '{arg}'")
                continue
            errors.extend(check_argument(arg, call.arguments[arg], c))
        if not rule.allow_extra_args:
            extra = sorted(set(call.arguments) - set(rule.args))
            if extra:
                errors.append(f"unexpected arguments: {', '.join(extra)}")
        if errors:
            return deny("argument_violation", errors)

        key = f"{call.agent}:{rule.name}"
        if rule.rate_limit and not self.rate_limiter.check(
            key, rule.rate_limit.max_calls, rule.rate_limit.per_seconds, consume=consume
        ):
            return deny(
                "rate_limited",
                [
                    f"rate limit exceeded: {rule.rate_limit.max_calls} calls per "
                    f"{rule.rate_limit.per_seconds:g}s"
                ],
                Severity.MEDIUM,
            )
        if rule.budget is not None:
            if consume:
                ok = self.budgets.try_spend(key, call.cost, rule.budget)
            else:
                ok = self.budgets.spent(key) + call.cost <= rule.budget + 1e-9
            if not ok:
                return deny(
                    "budget_exceeded",
                    [f"budget exceeded: {call.cost:g} would pass the limit of {rule.budget:g}"],
                )

        if rule.action == "require_approval":
            reason = rule.reason or f"tool '{call.tool}' needs human approval"
            return PolicyResult(
                verdict=Verdict.REQUIRE_APPROVAL,
                rule=rule.name,
                reasons=[reason],
                findings=[
                    Finding(
                        source="policy",
                        code="approval_required",
                        severity=Severity.MEDIUM,
                        message=reason,
                    )
                ],
            )
        triggers = [
            f"approval needed: {msg}"
            for arg, c in rule.approval_when.items()
            if arg in call.arguments
            for msg in check_argument(arg, call.arguments[arg], c)
        ]
        if triggers:
            return PolicyResult(
                verdict=Verdict.REQUIRE_APPROVAL,
                rule=rule.name,
                reasons=triggers,
                findings=[
                    Finding(
                        source="policy",
                        code="approval_required",
                        severity=Severity.MEDIUM,
                        message=t,
                    )
                    for t in triggers
                ],
            )
        return PolicyResult(
            verdict=Verdict.ALLOW,
            rule=rule.name,
            reasons=[rule.reason or f"allowed by rule '{rule.name}'"],
            findings=[],
        )
