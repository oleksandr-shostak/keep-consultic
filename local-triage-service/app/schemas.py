import ast
import json
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, root_validator


Severity = Literal["info", "warning", "high", "critical"]
Scope = Literal["alert", "incident"]
TriageMode = Literal["single", "batch"]
TriageRunStatus = Literal["success", "failed"]


class AlertInput(BaseModel):
    id: str | None = None
    fingerprint: str = Field(min_length=1)
    name: str | None = None
    status: str | None = None
    severity: str | None = None
    source: list[str] | str = Field(default_factory=list)
    provider_id: str | None = None
    message: str | None = None
    description: str | None = None

    @root_validator
    def normalize_source(cls, values):
        source = values.get("source")
        if isinstance(source, str):
            source_s = source.strip()
            if not source_s:
                values["source"] = []
                return values
            try:
                parsed = json.loads(source_s)
            except Exception:
                try:
                    parsed = ast.literal_eval(source_s)
                except Exception:
                    parsed = [source_s]
            if isinstance(parsed, list):
                values["source"] = [str(x) for x in parsed if str(x).strip()]
            else:
                values["source"] = [str(parsed)]
        return values


class KBExampleCreate(BaseModel):
    tenant_id: str = Field(min_length=1)
    scope: Scope
    proposed_severity: Severity
    reason: str = Field(min_length=3)
    alert_text: str = Field(min_length=3)
    created_by: str = Field(min_length=1)
    current_severity: str | None = None
    alert_id: str | None = None
    incident_id: str | None = None
    fingerprint: str | None = None
    source: list[str] = Field(default_factory=list)
    provider_id: str | None = None
    incident_alerts: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @root_validator
    def validate_target(cls, values):
        scope = values.get("scope")
        alert_id = values.get("alert_id")
        fingerprint = values.get("fingerprint")
        incident_id = values.get("incident_id")
        if scope == "alert" and not (alert_id or fingerprint):
            raise ValueError("For scope=alert either alert_id or fingerprint is required")
        if scope == "incident" and not incident_id:
            raise ValueError("For scope=incident incident_id is required")
        return values


class KBExampleUpdate(BaseModel):
    proposed_severity: Severity | None = None
    reason: str | None = None
    alert_text: str | None = None
    current_severity: str | None = None
    source: list[str] | None = None
    provider_id: str | None = None
    incident_alerts: list[dict[str, Any]] | None = None
    metadata: dict[str, Any] | None = None


class KBExampleOut(BaseModel):
    id: UUID
    tenant_id: str
    scope: Scope
    proposed_severity: Severity
    reason: str
    alert_text: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    current_severity: str | None = None
    alert_id: str | None = None
    incident_id: str | None = None
    fingerprint: str | None = None
    source: list[str] = Field(default_factory=list)
    provider_id: str | None = None
    incident_alerts: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class KBExamplesListResponse(BaseModel):
    items: list[KBExampleOut]
    count: int


class TriageRequest(BaseModel):
    tenant_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    mode: TriageMode = "single"
    alerts: list[AlertInput] | str
    top_k: int | None = None
    system_prompt: str | None = None

    @root_validator
    def normalize_alerts(cls, values):
        alerts = values.get("alerts")
        if isinstance(alerts, str):
            alerts_s = alerts.strip()
            if not alerts_s:
                values["alerts"] = []
            else:
                parsed = None
                for parser in (json.loads, ast.literal_eval):
                    try:
                        parsed = parser(alerts_s)
                        break
                    except Exception:
                        continue
                if parsed is None:
                    raise ValueError("alerts must be a list or a JSON/list string")
                if not isinstance(parsed, list):
                    raise ValueError("alerts payload must resolve to a list")
                values["alerts"] = parsed
        return values


class TriageResponse(BaseModel):
    incident_id: str
    recommended_severity: Severity
    reason: str
    validated_fingerprints: list[str]
    matched_rules: list[str] = Field(default_factory=list)


class TriageRunSummary(BaseModel):
    id: UUID
    tenant_id: str
    incident_id: str
    mode: TriageMode
    status: TriageRunStatus
    recommended_severity: Severity | None = None
    reason: str | None = None
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime


class TriageRunDetail(TriageRunSummary):
    request_payload: dict[str, Any] = Field(default_factory=dict)
    retrieval_trace: list[dict[str, Any]] = Field(default_factory=list)
    llm_trace: list[dict[str, Any]] = Field(default_factory=list)
    response_payload: dict[str, Any] | None = None


class TriageRunsListResponse(BaseModel):
    items: list[TriageRunSummary]
    count: int
