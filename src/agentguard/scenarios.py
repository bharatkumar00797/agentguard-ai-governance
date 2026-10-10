"""Packaged demo scenarios: a task, simulated tools, a scripted (mock) agent and expectations."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from agentguard.agent import RunResult, ToolFn, run_agent
from agentguard.audit import AuditLog
from agentguard.guard import Guard
from agentguard.policy import load_policy
from agentguard.providers import Provider, provider_from_env


class Expect(BaseModel):
    model_config = ConfigDict(extra="forbid")
    blocked: int = 0
    approvals: int = 0
    executed: int = 0


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-z0-9-]+$")
    title: str
    description: str = ""
    policy: str = "default"
    task: str
    tools: dict[str, str] = Field(default_factory=dict)
    script: list[str] = Field(default_factory=list)
    auto_approve: list[str] = Field(default_factory=list)
    expect: Expect = Field(default_factory=Expect)


def _root() -> Any:
    return resources.files("agentguard") / "scenarios"


def list_scenarios() -> list[Scenario]:
    items = [
        Scenario.model_validate(yaml.safe_load(p.read_text(encoding="utf-8")))
        for p in _root().iterdir()
        if p.name.endswith(".yaml")
    ]
    return sorted(items, key=lambda s: s.id)


def load_scenario(ref: str) -> Scenario:
    path = Path(ref)
    if path.suffix in {".yaml", ".yml"} and path.exists():
        return Scenario.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    if not re.fullmatch(r"[a-z0-9-]+", ref) or not (_root() / f"{ref}.yaml").is_file():
        raise FileNotFoundError(f"scenario not found: {ref}")
    return Scenario.model_validate(
        yaml.safe_load((_root() / f"{ref}.yaml").read_text(encoding="utf-8"))
    )


def _canned(output: str) -> ToolFn:
    def tool(_args: dict[str, Any]) -> str:
        return output

    return tool


def run_scenario(
    scenario: Scenario,
    *,
    audit: AuditLog | None = None,
    provider: Provider | None = None,
    policy_override: str | None = None,
) -> tuple[RunResult, Guard]:
    guard = Guard(load_policy(policy_override or scenario.policy), audit=audit)
    tools: dict[str, ToolFn] = {name: _canned(out) for name, out in scenario.tools.items()}
    result = run_agent(
        scenario.task,
        guard=guard,
        provider=provider or provider_from_env(scenario.script),
        tools=tools,
        agent=scenario.id,
        auto_approve=lambda call: call.tool in scenario.auto_approve,
    )
    return result, guard


def meets_expectations(scenario: Scenario, result: RunResult) -> bool:
    e = scenario.expect
    return (result.blocked, result.approvals, result.executed) == (
        e.blocked,
        e.approvals,
        e.executed,
    )
