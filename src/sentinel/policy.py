from __future__ import annotations

from .detectors import detect
from .models import Decision, Policy, SecurityResult, Severity

_ORDER = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_BLOCKING_CATEGORIES = {
    "prompt_injection",
    "jailbreak",
    "secret",
}


def _redact_pii(text: str, findings) -> str:
    result = text
    spans = sorted(
        [
            (f.start, f.end)
            for f in findings
            if f.category == "pii" and f.start is not None and f.end is not None
        ],
        reverse=True,
    )

    for start, end in spans:
        result = result[:start] + "[REDACTED]" + result[end:]

    return result


def enforce(
    text: str,
    policy: Policy | None = None,
    *,
    request_id: str | None = None,
) -> SecurityResult:
    policy = policy or Policy()

    if len(text) > policy.max_input_chars:
        return SecurityResult(Decision.BLOCK, request_id=request_id)

    findings = detect(text)

    # Security threats take precedence over PII redaction.
    if any(f.category in _BLOCKING_CATEGORIES for f in findings):
        return SecurityResult(
            Decision.BLOCK,
            findings,
            text,
            request_id,
        )

    highest = max(
        (_ORDER[f.severity] for f in findings),
        default=0,
    )

    if highest >= _ORDER[policy.block_severity]:
        return SecurityResult(
            Decision.BLOCK,
            findings,
            text,
            request_id,
        )

    if policy.redact_pii and any(f.category == "pii" for f in findings):
        return SecurityResult(
            Decision.REDACT,
            findings,
            _redact_pii(text, findings),
            request_id,
        )

    return SecurityResult(
        Decision.ALLOW,
        findings,
        text,
        request_id,
    )


def enforce_output(
    text: str,
    policy: Policy | None = None,
    *,
    request_id: str | None = None,
) -> SecurityResult:
    policy = policy or Policy()

    if len(text) > policy.max_output_chars:
        return SecurityResult(Decision.BLOCK, request_id=request_id)

    return enforce(text, policy, request_id=request_id)


def check_tool(
    tool_name: str,
    arguments: str,
    policy: Policy | None = None,
) -> SecurityResult:
    policy = policy or Policy()
    tp = policy.tool_policy

    # Explicit deny always wins.
    if tool_name in tp.blocked_tools:
        return SecurityResult(Decision.BLOCK)

    # Empty allowlist means default-deny.
    if tool_name not in tp.allowed_tools:
        return SecurityResult(Decision.BLOCK)

    if len(arguments.encode("utf-8")) > tp.max_argument_bytes:
        return SecurityResult(Decision.BLOCK)

    return SecurityResult(
        Decision.ALLOW,
        sanitized_text=arguments,
    )
