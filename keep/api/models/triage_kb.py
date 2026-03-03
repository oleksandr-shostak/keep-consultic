from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, root_validator, validator


class TriageKBExampleScope(str, Enum):
    ALERT = "alert"
    INCIDENT = "incident"


class TriageKBSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class TriageKBExampleCreateRequest(BaseModel):
    scope: TriageKBExampleScope
    proposed_severity: TriageKBSeverity
    reason: str
    alert_text: str
    current_severity: str | None = None
    alert_id: str | None = None
    incident_id: str | None = None
    fingerprint: str | None = None
    source: list[str] = Field(default_factory=list)
    provider_id: str | None = None
    incident_alerts: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @validator("reason", "alert_text")
    def validate_required_text(cls, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) < 3:
            raise ValueError("must be at least 3 characters long")
        if len(cleaned) > 20000:
            raise ValueError("must be less than 20000 characters")
        return cleaned

    @root_validator
    def validate_scope_target(cls, values: dict[str, Any]) -> dict[str, Any]:
        scope = values.get("scope")
        if scope == TriageKBExampleScope.ALERT:
            if not values.get("alert_id") and not values.get("fingerprint"):
                raise ValueError(
                    "For scope=alert either alert_id or fingerprint is required"
                )
        if scope == TriageKBExampleScope.INCIDENT:
            if not values.get("incident_id"):
                raise ValueError("For scope=incident incident_id is required")
        return values


class TriageKBExampleUpdateRequest(BaseModel):
    proposed_severity: TriageKBSeverity | None = None
    reason: str | None = None
    alert_text: str | None = None
    current_severity: str | None = None
    source: list[str] | None = None
    provider_id: str | None = None
    incident_alerts: list[dict[str, Any]] | None = None
    metadata: dict[str, Any] | None = None

    @validator("reason")
    def validate_reason(cls, value: str | None) -> str | None:
        if value is None:
            return value
        cleaned = value.strip()
        if len(cleaned) < 3:
            raise ValueError("reason must be at least 3 characters long")
        if len(cleaned) > 20000:
            raise ValueError("reason must be less than 20000 characters")
        return cleaned

    @validator("alert_text")
    def validate_alert_text(cls, value: str | None) -> str | None:
        if value is None:
            return value
        cleaned = value.strip()
        if len(cleaned) < 3:
            raise ValueError("alert_text must be at least 3 characters long")
        if len(cleaned) > 20000:
            raise ValueError("alert_text must be less than 20000 characters")
        return cleaned


class TriageKBExampleResponse(BaseModel):
    id: str
    tenant_id: str
    scope: TriageKBExampleScope
    proposed_severity: TriageKBSeverity
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


class TriageKBExamplesListResponse(BaseModel):
    items: list[TriageKBExampleResponse]
    count: int


class TriageKBExampleDeleteResponse(BaseModel):
    status: str
    id: str


class TriageRunMode(str, Enum):
    SINGLE = "single"
    BATCH = "batch"


class TriageRunStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"


class TriageRunSummaryResponse(BaseModel):
    id: str
    tenant_id: str
    incident_id: str
    mode: TriageRunMode
    status: TriageRunStatus
    recommended_severity: TriageKBSeverity | None = None
    reason: str | None = None
    error_message: str | None = None
    created_at: datetime
    completed_at: datetime


class TriageRunDetailResponse(TriageRunSummaryResponse):
    request_payload: dict[str, Any] = Field(default_factory=dict)
    retrieval_trace: list[dict[str, Any]] = Field(default_factory=list)
    llm_trace: list[dict[str, Any]] = Field(default_factory=list)
    response_payload: dict[str, Any] | None = None


class TriageRunsListResponse(BaseModel):
    items: list[TriageRunSummaryResponse]
    count: int
