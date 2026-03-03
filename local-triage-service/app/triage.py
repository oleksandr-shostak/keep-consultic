import logging
from dataclasses import dataclass, field
from typing import Any

from app.config import Settings
from app.ollama_client import OllamaClient
from app.repository import KBCandidate, KnowledgeBaseRepository
from app.schemas import AlertInput, TriageRequest, TriageResponse


SYSTEM_PROMPT = """
You are IncidentsTriageLocal.
You must decide severity using ONLY provided knowledge base examples.
Never use external assumptions.

Rules:
- If no strong relevant KB match exists, return warning.
- Return one of: info, warning, high, critical.
- Escalate to high/critical ONLY when supported by matched KB examples.
- For info: only when matched KB examples clearly support info.
- matched_rule_ids must include only IDs that exist in the provided kb_candidates.
- Output strict JSON.
""".strip()


TRIAGE_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "recommended_severity": {
            "type": "string",
            "enum": ["info", "warning", "high", "critical"],
        },
        "reason": {"type": "string"},
        "matched_rule_ids": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["recommended_severity", "reason", "matched_rule_ids"],
}


SEVERITY_RANK = {
    "info": 0,
    "warning": 1,
    "high": 2,
    "critical": 3,
}

logger = logging.getLogger("local-triage-service")


@dataclass
class AlertDecision:
    fingerprint: str
    severity: str
    reason: str
    matched_rules: list[str]
    trace: dict[str, Any] = field(default_factory=dict)


class TriageEngine:
    def __init__(
        self,
        settings: Settings,
        repo: KnowledgeBaseRepository,
        ollama: OllamaClient,
    ):
        self.settings = settings
        self.repo = repo
        self.ollama = ollama

    @staticmethod
    def _alert_text(alert: AlertInput) -> str:
        return "\n".join(
            [
                f"name: {alert.name or ''}",
                f"status: {alert.status or ''}",
                f"severity: {alert.severity or ''}",
                f"fingerprint: {alert.fingerprint}",
                f"provider_id: {alert.provider_id or ''}",
                f"source: {alert.source or []}",
                f"message: {alert.message or ''}",
                f"description: {alert.description or ''}",
            ]
        )

    @staticmethod
    def _normalize_decision(raw: dict[str, Any], candidate_ids: set[str]) -> tuple[str, str, list[str]]:
        severity = str(raw.get("recommended_severity", "warning")).lower().strip()
        reason = str(raw.get("reason", "No reason provided")).strip() or "No reason provided"
        matched_ids = [str(x) for x in (raw.get("matched_rule_ids") or [])]
        matched_ids = [x for x in matched_ids if x in candidate_ids]

        if severity not in SEVERITY_RANK:
            return "warning", "Invalid severity from model; fallback to warning", []

        # Conservative guard: no escalation without KB evidence.
        if severity in {"high", "critical", "info"} and not matched_ids:
            return "warning", "No matched KB rules; fallback to warning", []

        return severity, reason, matched_ids

    def _ask_model(
        self,
        payload: dict[str, Any],
        candidates: list[KBCandidate],
        system_prompt: str | None = None,
    ) -> tuple[str, str, list[str], dict[str, Any]]:
        kb_payload = [
            {
                "id": str(c.id),
                "proposed_severity": c.proposed_severity,
                "reason": c.reason,
                "similarity": round(c.similarity, 4),
                "alert_text": c.alert_text[:1200],
            }
            for c in candidates
        ]
        model_response = self.ollama.chat_json(
            system_prompt=(system_prompt.strip() if system_prompt else SYSTEM_PROMPT),
            user_payload={
                **payload,
                "kb_candidates": kb_payload,
            },
            schema=TRIAGE_OUTPUT_SCHEMA,
            return_debug=True,
        )
        raw = model_response.get("parsed") or {}
        severity, reason, matched_rule_ids = self._normalize_decision(
            raw, {str(c.id) for c in candidates}
        )
        if matched_rule_ids:
            severity_by_id = {str(c.id): c.proposed_severity for c in candidates}
            max_matched = max(
                (severity_by_id.get(rule_id, "warning") for rule_id in matched_rule_ids),
                key=lambda s: SEVERITY_RANK.get(s, 1),
            )
            if SEVERITY_RANK.get(severity, 1) < SEVERITY_RANK.get(max_matched, 1):
                severity = max_matched
                reason = (
                    f"Severity aligned with highest matched KB example ({max_matched}). "
                    f"{reason}"
                )
        return severity, reason, matched_rule_ids, {
            "system_prompt": system_prompt.strip() if system_prompt else SYSTEM_PROMPT,
            "user_payload": payload,
            "kb_candidates": kb_payload,
            "raw_content": model_response.get("raw_content"),
            "raw_response": model_response.get("raw_response"),
            "request_payload": model_response.get("request_payload"),
            "normalized_response": {
                "recommended_severity": severity,
                "reason": reason,
                "matched_rule_ids": matched_rule_ids,
            },
        }

    @staticmethod
    def _serialize_candidate(candidate: KBCandidate) -> dict[str, Any]:
        return {
            "id": str(candidate.id),
            "proposed_severity": candidate.proposed_severity,
            "reason": candidate.reason,
            "similarity": round(candidate.similarity, 4),
            "metadata": candidate.metadata,
        }

    def _triage_single_alert(
        self,
        tenant_id: str,
        alert: AlertInput,
        top_k: int,
        system_prompt: str | None = None,
    ) -> AlertDecision:
        text = self._alert_text(alert)
        embedding = self.ollama.embed(text)
        candidates = self.repo.search(
            tenant_id=tenant_id,
            embedding=embedding,
            top_k=top_k,
            similarity_threshold=self.settings.similarity_threshold,
        )
        retrieval_trace = {
            "mode": "single",
            "alert_fingerprint": alert.fingerprint,
            "top_k": top_k,
            "similarity_threshold": self.settings.similarity_threshold,
            "candidates": [self._serialize_candidate(c) for c in candidates],
        }
        if not candidates:
            return AlertDecision(
                fingerprint=alert.fingerprint,
                severity="warning",
                reason="No relevant KB examples found",
                matched_rules=[],
                trace={"retrieval": retrieval_trace},
            )

        severity, reason, matched_rule_ids, llm_trace = self._ask_model(
            payload={
                "mode": "single",
                "alert": {
                    "fingerprint": alert.fingerprint,
                    "name": alert.name,
                    "message": alert.message,
                    "description": alert.description,
                    "status": alert.status,
                    "severity": alert.severity,
                    "source": alert.source,
                    "provider_id": alert.provider_id,
                },
            },
            candidates=candidates,
            system_prompt=system_prompt,
        )

        return AlertDecision(
            fingerprint=alert.fingerprint,
            severity=severity,
            reason=reason,
            matched_rules=matched_rule_ids,
            trace={
                "retrieval": retrieval_trace,
                "llm": llm_trace,
            },
        )

    @staticmethod
    def _aggregate_alert_decisions(incident_id: str, decisions: list[AlertDecision]) -> TriageResponse:
        if not decisions:
            return TriageResponse(
                incident_id=incident_id,
                recommended_severity="warning",
                reason="No alerts to analyze",
                validated_fingerprints=[],
                matched_rules=[],
            )

        severities = [d.severity for d in decisions]
        max_rank = max(SEVERITY_RANK[s] for s in severities)
        if max_rank == SEVERITY_RANK["info"]:
            final_severity = "info"
        else:
            final_severity = next(k for k, v in SEVERITY_RANK.items() if v == max_rank)

        highest = next(d for d in decisions if SEVERITY_RANK[d.severity] == max_rank)
        matched_rules = sorted({mr for d in decisions for mr in d.matched_rules})

        return TriageResponse(
            incident_id=incident_id,
            recommended_severity=final_severity,
            reason=highest.reason,
            validated_fingerprints=[d.fingerprint for d in decisions],
            matched_rules=matched_rules,
        )

    def triage(self, request: TriageRequest) -> TriageResponse:
        top_k = request.top_k or self.settings.top_k
        request_payload = {
            "tenant_id": request.tenant_id,
            "incident_id": request.incident_id,
            "mode": request.mode,
            "top_k": top_k,
            "system_prompt": request.system_prompt,
            "alerts": [
                {
                    "id": alert.id,
                    "fingerprint": alert.fingerprint,
                    "name": alert.name,
                    "status": alert.status,
                    "severity": alert.severity,
                    "source": alert.source,
                    "provider_id": alert.provider_id,
                    "message": alert.message,
                    "description": alert.description,
                }
                for alert in request.alerts
            ],
        }
        retrieval_trace: list[dict[str, Any]] = []
        llm_trace: list[dict[str, Any]] = []

        try:
            if request.mode == "single":
                decisions = [
                    self._triage_single_alert(
                        request.tenant_id,
                        alert,
                        top_k,
                        system_prompt=request.system_prompt,
                    )
                    for alert in request.alerts
                ]
                for decision in decisions:
                    if decision.trace.get("retrieval"):
                        retrieval_trace.append(decision.trace["retrieval"])
                    if decision.trace.get("llm"):
                        llm_trace.append(decision.trace["llm"])
                response = self._aggregate_alert_decisions(request.incident_id, decisions)
            else:
                # batch mode
                combined_text = "\n\n---\n\n".join(
                    self._alert_text(a) for a in request.alerts
                )
                embedding = self.ollama.embed(combined_text)
                candidates = self.repo.search(
                    tenant_id=request.tenant_id,
                    embedding=embedding,
                    top_k=top_k,
                    similarity_threshold=self.settings.similarity_threshold,
                )

                retrieval_trace.append(
                    {
                        "mode": "batch",
                        "incident_id": request.incident_id,
                        "top_k": top_k,
                        "similarity_threshold": self.settings.similarity_threshold,
                        "candidates": [
                            self._serialize_candidate(candidate)
                            for candidate in candidates
                        ],
                    }
                )

                if not candidates:
                    response = TriageResponse(
                        incident_id=request.incident_id,
                        recommended_severity="warning",
                        reason="No relevant KB examples found",
                        validated_fingerprints=[a.fingerprint for a in request.alerts],
                        matched_rules=[],
                    )
                else:
                    severity, reason, matched_rule_ids, batch_llm_trace = self._ask_model(
                        payload={
                            "mode": "batch",
                            "incident_id": request.incident_id,
                            "alerts": [
                                {
                                    "fingerprint": a.fingerprint,
                                    "name": a.name,
                                    "message": a.message,
                                    "description": a.description,
                                    "status": a.status,
                                    "severity": a.severity,
                                    "source": a.source,
                                    "provider_id": a.provider_id,
                                }
                                for a in request.alerts
                            ],
                        },
                        candidates=candidates,
                        system_prompt=request.system_prompt,
                    )
                    llm_trace.append(batch_llm_trace)
                    response = TriageResponse(
                        incident_id=request.incident_id,
                        recommended_severity=severity,
                        reason=reason,
                        validated_fingerprints=[a.fingerprint for a in request.alerts],
                        matched_rules=matched_rule_ids,
                    )

            self.repo.create_triage_run(
                tenant_id=request.tenant_id,
                incident_id=request.incident_id,
                mode=request.mode,
                status="success",
                request_payload=request_payload,
                retrieval_trace=retrieval_trace,
                llm_trace=llm_trace,
                response_payload=response.dict(),
            )
            return response
        except Exception as exc:
            logger.exception(
                "Triage failed",
                extra={
                    "tenant_id": request.tenant_id,
                    "incident_id": request.incident_id,
                    "mode": request.mode,
                },
            )
            try:
                self.repo.create_triage_run(
                    tenant_id=request.tenant_id,
                    incident_id=request.incident_id,
                    mode=request.mode,
                    status="failed",
                    request_payload=request_payload,
                    retrieval_trace=retrieval_trace,
                    llm_trace=llm_trace,
                    response_payload=None,
                    error_message=str(exc),
                )
            except Exception:
                logger.exception(
                    "Failed to persist triage failure log",
                    extra={
                        "tenant_id": request.tenant_id,
                        "incident_id": request.incident_id,
                        "mode": request.mode,
                    },
                )
            raise
