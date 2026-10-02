from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .models import Decision, EvaluationReport, Policy, SecurityCase
from .policy import enforce


def load_cases(path: str | Path) -> list[SecurityCase]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return [
        SecurityCase(
            x["case_id"],
            x["text"],
            Decision(x["expected_decision"]),
            tuple(x.get("expected_categories", [])),
        )
        for x in payload
    ]


def evaluate(cases: list[SecurityCase], policy: Policy | None = None) -> EvaluationReport:
    policy = policy or Policy()
    passed = 0
    failures = []
    expected = defaultdict(int)
    detected = defaultdict(int)
    benign = 0
    false_positive = 0

    for case in cases:
        result = enforce(case.text, policy)
        actual = {f.category for f in result.findings}
        wanted = set(case.expected_categories)
        for category in wanted:
            expected[category] += 1
            detected[category] += category in actual
        if not wanted and case.expected_decision == Decision.ALLOW:
            benign += 1
            false_positive += result.decision != Decision.ALLOW
        ok = result.decision == case.expected_decision and wanted.issubset(actual)
        if ok:
            passed += 1
        else:
            failures.append(
                {
                    "case_id": case.case_id,
                    "expected_decision": case.expected_decision,
                    "actual_decision": result.decision,
                    "expected_categories": sorted(wanted),
                    "actual_categories": sorted(actual),
                }
            )

    recall = {c: round(detected[c] / n, 4) for c, n in expected.items()}
    fp_rate = round(false_positive / benign, 4) if benign else 0.0
    return EvaluationReport(
        len(cases),
        passed,
        len(cases) - passed,
        round(passed / len(cases), 4) if cases else 1.0,
        recall,
        fp_rate,
        not failures and fp_rate == 0.0,
        failures,
    )


def write_report(report: EvaluationReport, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(
            {
                "cases": report.cases,
                "passed": report.passed,
                "failed": report.failed,
                "pass_rate": report.pass_rate,
                "category_recall": report.category_recall,
                "false_positive_rate": report.false_positive_rate,
                "gate_passed": report.gate_passed,
                "failures": report.failures,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
