from __future__ import annotations

import argparse
import json

import uvicorn

from .evaluation import evaluate, load_cases, write_report
from .policy import enforce


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel AI security and guardrails platform"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan text")
    scan.add_argument("text")

    ev = sub.add_parser("evaluate", help="Run security evaluation")
    ev.add_argument("dataset")
    ev.add_argument("--output", default="sentinel-report.json")

    serve = sub.add_parser("serve", help="Start API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args()

    if args.command == "scan":
        r = enforce(args.text)
        print(
            json.dumps(
                {
                    "decision": r.decision,
                    "findings": [
                        {
                            "rule_id": f.rule_id,
                            "category": f.category,
                            "severity": f.severity,
                            "message": f.message,
                        }
                        for f in r.findings
                    ],
                    "sanitized_text": r.sanitized_text,
                },
                indent=2,
            )
        )
    elif args.command == "evaluate":
        report = evaluate(load_cases(args.dataset))
        write_report(report, args.output)
        status = "PASSED" if report.gate_passed else "FAILED"
        print(f"SENTINEL SECURITY GATE: {status}")
        print(
            f"Cases: {report.cases} | "
            f"Passed: {report.passed} | "
            f"Failed: {report.failed}"
        )
        print(f"Pass rate: {report.pass_rate:.1%}")
        print(f"False-positive rate: {report.false_positive_rate:.1%}")
        print(f"Report: {args.output}")
        if not report.gate_passed:
            raise SystemExit(1)
    else:
        uvicorn.run(
            "sentinel.api:app",
            host=args.host,
            port=args.port,
            reload=False,
        )
