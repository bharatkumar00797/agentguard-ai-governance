"""Deterministic security detectors for LLM inputs, outputs and tool arguments.

They are intentionally pattern based: fast, explainable, offline and testable. They are a
first line of defence, not a guarantee; the policy engine is what actually enforces limits.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Protocol

from agentguard.models import Finding, Severity


class Detector(Protocol):
    name: str

    def scan(self, text: str) -> list[Finding]: ...


@dataclass(frozen=True)
class Pattern:
    code: str
    severity: Severity
    message: str
    regex: re.Pattern[str]


def _p(code: str, sev: Severity, msg: str, rx: str) -> Pattern:
    return Pattern(code, sev, msg, re.compile(rx, re.IGNORECASE))


_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def normalize(text: str) -> str:
    """NFKC-normalise, drop zero-width characters and collapse whitespace.

    Used before pattern matching so homoglyph / invisible-character tricks do not hide
    an attack phrase.
    """
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return re.sub(r"\s+", " ", text)


class _PatternDetector:
    name = "pattern"
    patterns: tuple[Pattern, ...] = ()

    def scan(self, text: str) -> list[Finding]:
        clean = normalize(text)
        found: list[Finding] = []
        for pat in self.patterns:
            m = pat.regex.search(clean)
            if m:
                found.append(
                    Finding(
                        source=self.name,
                        code=pat.code,
                        severity=pat.severity,
                        message=pat.message,
                        span=(m.start(), m.end()),
                    )
                )
        return found


class PromptInjectionDetector(_PatternDetector):
    name = "prompt_injection"
    patterns = (
        _p(
            "override_instructions",
            Severity.HIGH,
            "Attempts to override previous instructions",
            r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|all|earlier|"
            r"system)\b.{0,20}\b(instructions?|rules?|prompts?|directions?)",
        ),
        _p(
            "role_hijack",
            Severity.HIGH,
            "Tries to redefine the assistant's role or authority",
            r"\b(you are now|from now on you|act as (an? )?(admin|root|system|developer))",
        ),
        _p(
            "fake_system_message",
            Severity.HIGH,
            "Contains a forged system / tool message delimiter",
            r"(<\|?\s*(system|im_start|im_end)\s*\|?>|\[\s*system\s*\]|^\s*system\s*:|"
            r"###\s*(system|instruction))",
        ),
        _p(
            "prompt_exfiltration",
            Severity.MEDIUM,
            "Asks to reveal the system prompt or hidden instructions",
            r"\b(reveal|print|show|repeat|leak)\b.{0,30}\b(system prompt|hidden instructions?|"
            r"initial prompt|your instructions)",
        ),
        _p(
            "tool_coercion",
            Severity.HIGH,
            "Instructs the agent to call tools or send data somewhere",
            r"\b(send|forward|upload|post|exfiltrate|email)\b.{0,40}\b(to|at)\b.{0,40}"
            r"(https?://|[\w.+-]+@[\w-]+\.\w+)",
        ),
    )


class JailbreakDetector(_PatternDetector):
    name = "jailbreak"
    patterns = (
        _p(
            "dan_persona",
            Severity.HIGH,
            "Known jailbreak persona (DAN / developer mode)",
            r"\b(DAN|do anything now|developer mode|jailbreak(ed)? mode|god mode)\b",
        ),
        _p(
            "no_restrictions",
            Severity.HIGH,
            "Asks the model to drop its safety rules",
            r"\b(without|no|ignore|bypass)\b.{0,20}\b(restrictions|filters|guardrails|"
            r"safety|censorship|limitations)\b",
        ),
        _p(
            "hypothetical_wrapper",
            Severity.MEDIUM,
            "Hypothetical / role-play framing used to bypass policy",
            r"\b(pretend|imagine|hypothetically|role-?play)\b.{0,40}\b(no rules|evil|unfiltered|"
            r"unrestricted)\b",
        ),
        _p(
            "obfuscated_payload",
            Severity.MEDIUM,
            "Asks to decode / execute an obfuscated payload",
            r"\b(decode|base64|rot13)\b.{0,30}\b(and|then)\b.{0,20}\b(run|execute|follow|obey)\b",
        ),
    )


@dataclass(frozen=True)
class SensitiveKind:
    code: str
    label: str
    severity: Severity
    regex: re.Pattern[str]


SENSITIVE_KINDS: tuple[SensitiveKind, ...] = (
    SensitiveKind(
        "private_key",
        "PRIVATE_KEY",
        Severity.CRITICAL,
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"
        ),
    ),
    SensitiveKind(
        "aws_key", "AWS_KEY", Severity.CRITICAL, re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
    ),
    SensitiveKind(
        "github_token",
        "GITHUB_TOKEN",
        Severity.CRITICAL,
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    ),
    SensitiveKind(
        "api_key", "API_KEY", Severity.CRITICAL, re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
    ),
    SensitiveKind(
        "jwt",
        "JWT",
        Severity.HIGH,
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    SensitiveKind(
        "password_assignment",
        "PASSWORD",
        Severity.HIGH,
        re.compile(r"(?i)\b(password|passwd|pwd|secret)\s*[:=]\s*\S{4,}"),
    ),
    SensitiveKind(
        "email",
        "EMAIL",
        Severity.MEDIUM,
        re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+\b"),
    ),
    SensitiveKind("credit_card", "CARD", Severity.HIGH, re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    SensitiveKind("us_ssn", "SSN", Severity.HIGH, re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    SensitiveKind("indian_pan", "PAN", Severity.HIGH, re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")),
    SensitiveKind(
        "phone",
        "PHONE",
        Severity.MEDIUM,
        re.compile(
            r"(?<![\w-])(\+?\d{1,3}[ -]?)?"
            r"(\(?\d{3,5}\)?[ -]?\d{3,4}[ -]?\d{4}|\d{5}[ -]?\d{5})(?![\w-])"
        ),
    ),
)


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class SensitiveDataDetector:
    """Finds PII and secrets and can redact them with typed placeholders."""

    name = "sensitive_data"

    def __init__(self, kinds: tuple[SensitiveKind, ...] = SENSITIVE_KINDS) -> None:
        self.kinds = kinds

    def _matches(self, text: str) -> list[tuple[int, int, SensitiveKind]]:
        taken: list[tuple[int, int, SensitiveKind]] = []
        for kind in self.kinds:  # ordered from most to least specific
            for m in kind.regex.finditer(text):
                start, end = m.span()
                if kind.code == "credit_card" and not luhn_valid(m.group()):
                    continue
                if any(start < e and end > s for s, e, _ in taken):
                    continue
                taken.append((start, end, kind))
        return sorted(taken, key=lambda t: t[0])

    def scan(self, text: str) -> list[Finding]:
        return [
            Finding(
                source=self.name,
                code=kind.code,
                severity=kind.severity,
                message=f"Possible {kind.label.lower().replace('_', ' ')} detected",
                span=(s, e),
            )
            for s, e, kind in self._matches(text)
        ]

    def redact(self, text: str) -> str:
        out: list[str] = []
        last = 0
        for s, e, kind in self._matches(text):
            out.append(text[last:s])
            out.append(f"[REDACTED:{kind.label}]")
            last = e
        out.append(text[last:])
        return "".join(out)


def default_detectors() -> dict[str, Detector]:
    return {
        "prompt_injection": PromptInjectionDetector(),
        "jailbreak": JailbreakDetector(),
        "sensitive_data": SensitiveDataDetector(),
    }
