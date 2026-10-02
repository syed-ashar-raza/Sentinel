# Sentinel

### AI Security & Guardrails Platform

Production-oriented deterministic security controls for AI applications.

## Security pipeline

```text
Input / Output
      |
      v
Threat Detectors
  | injection
  | jailbreak
  | secrets
  | PII
      |
      v
Policy Engine
  | severity
  | limits
  | redaction
      |
      +--> BLOCK
      +--> REDACT
      +--> ALLOW
```

## Controls

- Prompt-injection detection
- Jailbreak-pattern detection
- Secret/credential detection
- Email, Pakistan mobile, and CNIC-like PII detection
- Severity-based blocking
- PII redaction
- Input/output limits
- Tool allowlists/blocklists
- Tool argument limits
- Request IDs
- FastAPI API
- CLI
- Deterministic security evaluation
- False-positive measurement
- CI security regression gate
- Docker
- Python 3.14
- pytest and Ruff

## Quick start

```text
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest -q
sentinel evaluate examples/security_cases.json --output sentinel-report.json
```

Run API:

```text
sentinel serve
```

Endpoints:

- `GET /health`
- `POST /v1/scan`
- `POST /v1/tool/check`

## Evaluation

The checked-in fixture contains 10 cases covering benign input, prompt injection, jailbreak patterns, secrets, PII, and mixed threats.

The security gate requires zero failed cases and zero false positives among the benign cases.

These are deterministic local engineering-test results, not production traffic statistics.

## Architecture

```text
src/sentinel/
├── api.py
├── cli.py
├── detectors.py
├── evaluation.py
├── models.py
└── policy.py
```

## Scope

Sentinel is a focused policy and evaluation layer. It is not a complete AI-security program, WAF, sandbox, identity provider, or general-purpose semantic security model.

See `docs/security-model.md`.

## License

Apache-2.0
