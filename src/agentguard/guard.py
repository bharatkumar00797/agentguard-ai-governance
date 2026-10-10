"""The guard: one choke point that evaluates LLM inputs, outputs and proposed tool calls.

Flow for a tool call: policy rule match -> argument constraints -> rate limit / budget ->
argument content scan (injection, secrets) -> risk score -> threshold escalation ->
audit record. The strictest verdict from any stage wins.
"""

from __future__ import annotations

import json
import secrets
import threading
from typing import Any, Literal

from pydantic import BaseModel

from agentguard.audit import AuditLog
from agentguard.detectors import (
    JailbreakDetector,
    PromptInjectionDetector,
    SensitiveDataDetector,
)
from agentguard.models import Decision, Finding, Severity, ToolCall, Verdict, strictest
from agentguard.policy import Policy, PolicyEngine
from agentguard.risk import risk_score

_SECRET_CODES = {"private_key", "aws_key", "github_token", "api_key", "jwt", "password_assignment"}
_BLOCKING = (Severity.HIGH, Severity.CRITICAL)


class Approval(BaseModel):
    id: str
    call: ToolCall
    decision: Decision
    status: Literal["pending", "approved", "rejected"] = "pending"
    reviewer: str | None = None
    note: str | None = None


def _redact_value(value: Any, sd: SensitiveDataDetector) -> Any:
    if isinstance(value, str):
        return sd.redact(value)
    if isinstance(value, list):
        return [_redact_value(v, sd) for v in value]
    if isinstance(value, dict):
        return {k: _redact_value(v, sd) for k, v in value.items()}
    return value


class Guard:
    def __init__(self, policy: Policy, audit: AuditLog | None = None) -> None:
        self.policy = policy
        self.engine = PolicyEngine(policy)
        self.audit = audit or AuditLog()
        self.injection = PromptInjectionDetector()
        self.jailbreak = JailbreakDetector()
        self.sensitive = SensitiveDataDetector()
        self._approvals: dict[str, Approval] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ text
    def _scan_text(self, text: str, *, output: bool) -> tuple[Verdict, list[Finding], list[str]]:
        tp = self.policy.text
        findings: list[Finding] = []
        reasons: list[str] = []
        verdict = Verdict.ALLOW
        inj = self.injection.scan(text)
        jb = self.jailbreak.scan(text)
        sd = self.sensitive.scan(text)
        findings += inj + jb + sd
        if tp.block_prompt_injection and any(f.severity in _BLOCKING for f in inj):
            verdict = Verdict.DENY
            reasons.append("prompt injection detected")
        if tp.block_jailbreak and any(f.severity in _BLOCKING for f in jb):
            verdict = Verdict.DENY
            reasons.append("jailbreak attempt detected")
        if sd:
            if output and tp.block_secrets_in_output and any(f.code in _SECRET_CODES for f in sd):
                verdict = Verdict.DENY
                reasons.append("model output would leak a secret")
            elif tp.redact_sensitive_data and verdict is not Verdict.DENY:
                verdict = Verdict.REDACT
                reasons.append(f"redacted {len(sd)} sensitive value(s)")
        return verdict, findings, reasons

    def _finish(self, decision: Decision, event: str, extra: dict[str, Any]) -> Decision:
        self.audit.append(
            event,
            {
                **extra,
                "verdict": decision.verdict.value,
                "risk_score": decision.risk_score,
                "rule": decision.rule,
                "reasons": decision.reasons,
                "findings": [f.code for f in decision.findings],
            },
        )
        return decision

    def _escalate(self, verdict: Verdict, score: int, reasons: list[str]) -> Verdict:
        th = self.policy.risk_thresholds
        if score >= th.deny and verdict is not Verdict.DENY:
            reasons.append(f"risk score {score} >= deny threshold {th.deny}")
            return Verdict.DENY
        if score >= th.approval and verdict in (Verdict.ALLOW, Verdict.REDACT):
            reasons.append(f"risk score {score} >= approval threshold {th.approval}")
            return Verdict.REQUIRE_APPROVAL
        return verdict

    def check_input(self, text: str, *, agent: str = "default") -> Decision:
        """Screen a prompt / untrusted content before it reaches the model."""
        return self._check_text(text, agent=agent, output=False)

    def check_output(self, text: str, *, agent: str = "default") -> Decision:
        """Screen a model reply before it is shown to a user or fed to tools."""
        return self._check_text(text, agent=agent, output=True)

    def _check_text(self, text: str, *, agent: str, output: bool) -> Decision:
        kind = "output" if output else "input"
        if len(text) > self.policy.text.max_input_chars:
            d = Decision(
                kind=kind,
                verdict=Verdict.DENY,
                risk_score=50,
                reasons=[f"text longer than {self.policy.text.max_input_chars} characters"],
                findings=[
                    Finding(
                        source="policy",
                        code="too_long",
                        severity=Severity.HIGH,
                        message="text too long",
                    )
                ],
            )
            return self._finish(d, f"{kind}_check", {"agent": agent, "chars": len(text)})
        verdict, findings, reasons = self._scan_text(text, output=output)
        score = risk_score(findings)
        if verdict is Verdict.ALLOW and score >= self.policy.risk_thresholds.deny:
            verdict = Verdict.DENY
            reasons.append(f"risk score {score} >= deny threshold")
        d = Decision(
            kind=kind,
            verdict=verdict,
            risk_score=score,
            findings=findings,
            reasons=reasons or ["no issues found"],
            redacted_text=self.sensitive.redact(text) if verdict is Verdict.REDACT else None,
        )
        return self._finish(d, f"{kind}_check", {"agent": agent, "chars": len(text)})

    # ------------------------------------------------------------- tool calls
    def check_tool_call(self, call: ToolCall | dict[str, Any]) -> Decision:
        if not isinstance(call, ToolCall):
            call = ToolCall.model_validate(call)
        result = self.engine.evaluate(call)
        findings = list(result.findings)
        reasons = list(result.reasons)
        verdict = result.verdict
        redacted: dict[str, Any] | None = None

        rule = self.engine.match(call)
        # Arguments already pinned by a strict allowlist (domain, enum, pattern) are trusted
        # values, e.g. an approved recipient address, and are not redacted.
        pinned = {
            k
            for k, c in (rule.args.items() if rule else ())
            if c.allowed_domains is not None or c.enum is not None or c.pattern is not None
        }
        scanned = {k: v for k, v in call.arguments.items() if k not in pinned}
        if self.policy.text.scan_tool_arguments and scanned:
            blob = json.dumps(scanned, ensure_ascii=False, default=str)
            inj = self.injection.scan(blob) + self.jailbreak.scan(blob)
            sd = self.sensitive.scan(blob)
            findings += inj + sd
            if any(f.code in _SECRET_CODES for f in sd):
                verdict = Verdict.DENY
                reasons.append("tool arguments contain a secret (possible exfiltration)")
            elif sd and verdict is Verdict.ALLOW and self.policy.text.redact_sensitive_data:
                verdict = Verdict.REDACT
                redacted = {**call.arguments, **_redact_value(scanned, self.sensitive)}
                reasons.append(f"redacted {len(sd)} sensitive value(s) in arguments")
            if any(f.severity in _BLOCKING for f in inj):
                verdict = strictest(verdict, Verdict.REQUIRE_APPROVAL)
                reasons.append("tool arguments carry injection-like instructions")

        score = risk_score(findings)
        verdict = self._escalate(verdict, score, reasons)
        d = Decision(
            kind="tool_call",
            verdict=verdict,
            risk_score=score,
            findings=findings,
            reasons=reasons,
            rule=result.rule,
            redacted_arguments=redacted,
        )
        approval_id = None
        if verdict is Verdict.REQUIRE_APPROVAL:
            approval_id = self._queue(call, d)
        audited = {"agent": call.agent, "tool": call.tool, "cost": call.cost}
        if approval_id:
            audited["approval_id"] = approval_id
        return self._finish(d, "tool_call", audited)

    # -------------------------------------------------------------- approvals
    def _queue(self, call: ToolCall, decision: Decision) -> str:
        aid = "apr_" + secrets.token_hex(6)
        with self._lock:
            self._approvals[aid] = Approval(id=aid, call=call, decision=decision)
        return aid

    def approvals(self, status: str | None = None) -> list[Approval]:
        with self._lock:
            items = list(self._approvals.values())
        return [a for a in items if status is None or a.status == status]

    def resolve(
        self, approval_id: str, *, approved: bool, reviewer: str, note: str = ""
    ) -> Approval:
        with self._lock:
            a = self._approvals.get(approval_id)
            if a is None:
                raise KeyError(approval_id)
            if a.status != "pending":
                raise ValueError(f"approval {approval_id} is already {a.status}")
            a.status = "approved" if approved else "rejected"
            a.reviewer = reviewer
            a.note = note or None
        self.audit.append(
            "approval_resolved",
            {"approval_id": approval_id, "status": a.status, "reviewer": reviewer, "note": note},
        )
        return a
