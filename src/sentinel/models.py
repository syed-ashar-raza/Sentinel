from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: Severity
    message: str
    start: int | None = None
    end: int | None = None


@dataclass(frozen=True)
class SecurityResult:
    decision: Decision
    findings: list[Finding] = field(default_factory=list)
    sanitized_text: str | None = None
    request_id: str | None = None


@dataclass(frozen=True)
class ToolPolicy:
    allowed_tools: frozenset[str] = frozenset()
    blocked_tools: frozenset[str] = frozenset()
    max_argument_bytes: int = 16_384


@dataclass(frozen=True)
class Policy:
    block_severity: Severity = Severity.HIGH
    redact_pii: bool = True
    max_input_chars: int = 20_000
    max_output_chars: int = 20_000
    tool_policy: ToolPolicy = field(default_factory=ToolPolicy)


@dataclass(frozen=True)
class SecurityCase:
    case_id: str
    text: str
    expected_decision: Decision
    expected_categories: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    passed: int
    failed: int
    pass_rate: float
    category_recall: dict[str, float]
    false_positive_rate: float
    gate_passed: bool
    failures: list[dict[str, Any]]
