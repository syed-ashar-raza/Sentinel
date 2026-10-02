from __future__ import annotations

import uuid

from fastapi import FastAPI
from pydantic import BaseModel, Field

from . import __version__
from .models import Decision, Policy, Severity
from .policy import check_tool, enforce, enforce_output


class ScanRequest(BaseModel):
    text: str = Field(min_length=0)
    direction: str = Field(default="input", pattern="^(input|output)$")


class ToolRequest(BaseModel):
    tool_name: str
    arguments: str = ""


class FindingResponse(BaseModel):
    rule_id: str
    category: str
    severity: Severity
    message: str


class ScanResponse(BaseModel):
    request_id: str
    decision: Decision
    findings: list[FindingResponse]
    sanitized_text: str | None


app = FastAPI(title="Sentinel AI Security Platform", version=__version__)
policy = Policy()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel", "version": __version__}


@app.post("/v1/scan", response_model=ScanResponse)
def scan(request: ScanRequest) -> ScanResponse:
    request_id = str(uuid.uuid4())
    result = (
        enforce_output(request.text, policy, request_id=request_id)
        if request.direction == "output"
        else enforce(request.text, policy, request_id=request_id)
    )
    return ScanResponse(
        request_id=request_id,
        decision=result.decision,
        findings=[
            FindingResponse(
                rule_id=f.rule_id, category=f.category, severity=f.severity, message=f.message
            )
            for f in result.findings
        ],
        sanitized_text=result.sanitized_text,
    )


@app.post("/v1/tool/check")
def tool_check(request: ToolRequest) -> dict:
    result = check_tool(request.tool_name, request.arguments, policy)
    return {
        "decision": result.decision,
        "allowed": result.decision == Decision.ALLOW,
        "tool": request.tool_name,
    }
