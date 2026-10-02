from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding, Severity


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str


RULES = (
    Rule(
        "PI-001",
        "prompt_injection",
        Severity.HIGH,
        re.compile(
            r"\b(ignore|disregard|forget)\s+(all|any|the)\s+(previous|prior|above)\s+instructions\b",
            re.I,
        ),
        "Instruction hierarchy override attempt.",
    ),
    Rule(
        "PI-002",
        "prompt_injection",
        Severity.HIGH,
        re.compile(r"\b(system|developer)\s+message\b.*\b(reveal|print|show|leak)\b", re.I | re.S),
        "Attempt to extract privileged instructions.",
    ),
    Rule(
        "JB-001",
        "jailbreak",
        Severity.HIGH,
        re.compile(r"\b(jailbreak|DAN|do anything now)\b", re.I),
        "Known jailbreak framing.",
    ),
    Rule(
        "JB-002",
        "jailbreak",
        Severity.MEDIUM,
        re.compile(
            r"\b(roleplay|pretend)\b.*\b(no rules|without restrictions|unrestricted)\b", re.I | re.S
        ),
        "Role-play used to bypass restrictions.",
    ),
    Rule(
        "SEC-001",
        "secret",
        Severity.CRITICAL,
        re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b"),
        "API-style secret detected.",
    ),
    Rule(
        "SEC-002",
        "secret",
        Severity.CRITICAL,
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "AWS access-key identifier detected.",
    ),
    Rule(
        "SEC-003",
        "secret",
        Severity.HIGH,
        re.compile(r"\b(?:password|passwd|secret)\s*[:=]\s*[^\s,;]{4,}", re.I),
        "Credential assignment detected.",
    ),
    Rule(
        "PII-001",
        "pii",
        Severity.MEDIUM,
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
        "Email address detected.",
    ),
    Rule(
        "PII-002",
        "pii",
        Severity.MEDIUM,
        re.compile(r"\b(?:\+?92|0)3\d{2}[- ]?\d{7}\b"),
        "Pakistan mobile number detected.",
    ),
    Rule(
        "PII-003",
        "pii",
        Severity.MEDIUM,
        re.compile(r"\b\d{5}-\d{7}-\d\b"),
        "CNIC-like identifier detected.",
    ),
)


def detect(text: str) -> list[Finding]:
    findings = []
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            findings.append(
                Finding(
                    rule.rule_id,
                    rule.category,
                    rule.severity,
                    rule.message,
                    match.start(),
                    match.end(),
                )
            )
    findings.sort(key=lambda f: (f.start if f.start is not None else -1, f.rule_id))
    return findings
