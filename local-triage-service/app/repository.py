import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from psycopg.rows import dict_row

from app.config import Settings
from app.db import get_conn
from app.schemas import KBExampleCreate, KBExampleUpdate


@dataclass
class KBExampleRecord:
    id: UUID
    tenant_id: str
    scope: str
    proposed_severity: str
    reason: str
    alert_text: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    current_severity: str | None
    alert_id: str | None
    incident_id: str | None
    fingerprint: str | None
    source: list[str]
    provider_id: str | None
    incident_alerts: list[dict[str, Any]]
    metadata: dict[str, Any]


@dataclass
class KBCandidate:
    id: UUID
    proposed_severity: str
    reason: str
    alert_text: str
    metadata: dict[str, Any]
    similarity: float


@dataclass
class TriageRunRecord:
    id: UUID
    tenant_id: str
    incident_id: str
    mode: str
    status: str
    request_payload: dict[str, Any]
    retrieval_trace: list[dict[str, Any]]
    llm_trace: list[dict[str, Any]]
    response_payload: dict[str, Any] | None
    error_message: str | None
    created_at: datetime
    completed_at: datetime


class KnowledgeBaseRepository:
    def __init__(self, settings: Settings):
        self.settings = settings

    @staticmethod
    def _vector_literal(embedding: list[float]) -> str:
        return "[" + ",".join(f"{x:.8f}" for x in embedding) + "]"

    @staticmethod
    def _dedupe_hash(payload: KBExampleCreate) -> str:
        base = {
            "tenant_id": payload.tenant_id,
            "scope": payload.scope,
            "alert_id": payload.alert_id,
            "incident_id": payload.incident_id,
            "fingerprint": payload.fingerprint,
            "proposed_severity": payload.proposed_severity,
            "reason": payload.reason.strip(),
            "alert_text": payload.alert_text.strip(),
        }
        return hashlib.sha256(json.dumps(base, sort_keys=True).encode("utf-8")).hexdigest()

    def create_or_get(self, payload: KBExampleCreate, embedding: list[float]) -> KBExampleRecord:
        dedupe_hash = self._dedupe_hash(payload)
        vec = self._vector_literal(embedding)
        now = datetime.now(timezone.utc)
        with get_conn(self.settings) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT * FROM kb_examples
                    WHERE tenant_id = %(tenant_id)s
                      AND dedupe_hash = %(dedupe_hash)s
                      AND deleted_at IS NULL
                    """,
                    {"tenant_id": payload.tenant_id, "dedupe_hash": dedupe_hash},
                )
                existing = cur.fetchone()
                if existing:
                    return self._to_record(existing)

                example_id = uuid4()
                cur.execute(
                    """
                    INSERT INTO kb_examples (
                        id, tenant_id, scope, alert_id, incident_id, fingerprint,
                        provider_id, source, current_severity, proposed_severity,
                        reason, alert_text, incident_alerts, metadata,
                        dedupe_hash, embedding, created_by, created_at, updated_at
                    ) VALUES (
                        %(id)s, %(tenant_id)s, %(scope)s, %(alert_id)s, %(incident_id)s, %(fingerprint)s,
                        %(provider_id)s, %(source)s::jsonb, %(current_severity)s, %(proposed_severity)s,
                        %(reason)s, %(alert_text)s, %(incident_alerts)s::jsonb, %(metadata)s::jsonb,
                        %(dedupe_hash)s, %(embedding)s::vector, %(created_by)s, %(created_at)s, %(updated_at)s
                    )
                    RETURNING *
                    """,
                    {
                        "id": example_id,
                        "tenant_id": payload.tenant_id,
                        "scope": payload.scope,
                        "alert_id": payload.alert_id,
                        "incident_id": payload.incident_id,
                        "fingerprint": payload.fingerprint,
                        "provider_id": payload.provider_id,
                        "source": json.dumps(payload.source),
                        "current_severity": payload.current_severity,
                        "proposed_severity": payload.proposed_severity,
                        "reason": payload.reason,
                        "alert_text": payload.alert_text,
                        "incident_alerts": json.dumps(payload.incident_alerts),
                        "metadata": json.dumps(payload.metadata),
                        "dedupe_hash": dedupe_hash,
                        "embedding": vec,
                        "created_by": payload.created_by,
                        "created_at": now,
                        "updated_at": now,
                    },
                )
                created = cur.fetchone()
                conn.commit()
                return self._to_record(created)

    def update(self, tenant_id: str, example_id: UUID, payload: KBExampleUpdate, embedding: list[float] | None) -> KBExampleRecord | None:
        fields = {}
        if payload.proposed_severity is not None:
            fields["proposed_severity"] = payload.proposed_severity
        if payload.reason is not None:
            fields["reason"] = payload.reason
        if payload.alert_text is not None:
            fields["alert_text"] = payload.alert_text
        if payload.current_severity is not None:
            fields["current_severity"] = payload.current_severity
        if payload.source is not None:
            fields["source"] = json.dumps(payload.source)
        if payload.provider_id is not None:
            fields["provider_id"] = payload.provider_id
        if payload.incident_alerts is not None:
            fields["incident_alerts"] = json.dumps(payload.incident_alerts)
        if payload.metadata is not None:
            fields["metadata"] = json.dumps(payload.metadata)
        if embedding is not None:
            fields["embedding"] = self._vector_literal(embedding)

        if not fields:
            return self.get_by_id(tenant_id, example_id)

        assignments = []
        params: dict[str, Any] = {"tenant_id": tenant_id, "id": str(example_id)}
        for idx, (key, value) in enumerate(fields.items()):
            param_key = f"v{idx}"
            if key in {"source", "incident_alerts", "metadata"}:
                assignments.append(f"{key} = %({param_key})s::jsonb")
            elif key == "embedding":
                assignments.append(f"{key} = %({param_key})s::vector")
            else:
                assignments.append(f"{key} = %({param_key})s")
            params[param_key] = value
        assignments.append("updated_at = NOW()")

        with get_conn(self.settings) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    f"""
                    UPDATE kb_examples
                    SET {', '.join(assignments)}
                    WHERE tenant_id = %(tenant_id)s AND id = %(id)s::uuid AND deleted_at IS NULL
                    RETURNING *
                    """,
                    params,
                )
                row = cur.fetchone()
                conn.commit()
                return self._to_record(row) if row else None

    def soft_delete(self, tenant_id: str, example_id: UUID) -> bool:
        with get_conn(self.settings) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE kb_examples
                    SET deleted_at = NOW(), updated_at = NOW()
                    WHERE tenant_id = %(tenant_id)s AND id = %(id)s::uuid AND deleted_at IS NULL
                    """,
                    {"tenant_id": tenant_id, "id": str(example_id)},
                )
                affected = cur.rowcount
                conn.commit()
                return affected > 0

    def list_examples(self, tenant_id: str, scope: str | None = None, limit: int = 50) -> list[KBExampleRecord]:
        with get_conn(self.settings) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                if scope:
                    cur.execute(
                        """
                        SELECT * FROM kb_examples
                        WHERE tenant_id = %(tenant_id)s AND scope = %(scope)s AND deleted_at IS NULL
                        ORDER BY updated_at DESC
                        LIMIT %(limit)s
                        """,
                        {"tenant_id": tenant_id, "scope": scope, "limit": limit},
                    )
                else:
                    cur.execute(
                        """
                        SELECT * FROM kb_examples
                        WHERE tenant_id = %(tenant_id)s AND deleted_at IS NULL
                        ORDER BY updated_at DESC
                        LIMIT %(limit)s
                        """,
                        {"tenant_id": tenant_id, "limit": limit},
                    )
                rows = cur.fetchall()
                return [self._to_record(r) for r in rows]

    def get_by_id(self, tenant_id: str, example_id: UUID) -> KBExampleRecord | None:
        with get_conn(self.settings) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT * FROM kb_examples
                    WHERE tenant_id = %(tenant_id)s AND id = %(id)s::uuid AND deleted_at IS NULL
                    """,
                    {"tenant_id": tenant_id, "id": str(example_id)},
                )
                row = cur.fetchone()
                return self._to_record(row) if row else None

    def search(
        self,
        tenant_id: str,
        embedding: list[float],
        top_k: int,
        similarity_threshold: float,
    ) -> list[KBCandidate]:
        vec = self._vector_literal(embedding)
        with get_conn(self.settings) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT
                        id,
                        proposed_severity,
                        reason,
                        alert_text,
                        metadata,
                        1 - (embedding <=> %(embedding)s::vector) AS similarity
                    FROM kb_examples
                    WHERE tenant_id = %(tenant_id)s
                      AND deleted_at IS NULL
                    ORDER BY embedding <=> %(embedding)s::vector
                    LIMIT %(top_k)s
                    """,
                    {
                        "tenant_id": tenant_id,
                        "embedding": vec,
                        "top_k": top_k,
                    },
                )
                rows = cur.fetchall()

        candidates: list[KBCandidate] = []
        for row in rows:
            similarity = float(row["similarity"])
            if similarity < similarity_threshold:
                continue
            candidates.append(
                KBCandidate(
                    id=row["id"],
                    proposed_severity=row["proposed_severity"],
                    reason=row["reason"],
                    alert_text=row["alert_text"],
                    metadata=row["metadata"] or {},
                    similarity=similarity,
                )
            )
        return candidates

    def create_triage_run(
        self,
        *,
        tenant_id: str,
        incident_id: str,
        mode: str,
        status: str,
        request_payload: dict[str, Any],
        retrieval_trace: list[dict[str, Any]],
        llm_trace: list[dict[str, Any]],
        response_payload: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> TriageRunRecord:
        run_id = uuid4()
        now = datetime.now(timezone.utc)
        with get_conn(self.settings) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO triage_runs (
                        id, tenant_id, incident_id, mode, status, request_payload,
                        retrieval_trace, llm_trace, response_payload, error_message,
                        created_at, completed_at
                    ) VALUES (
                        %(id)s, %(tenant_id)s, %(incident_id)s, %(mode)s, %(status)s, %(request_payload)s::jsonb,
                        %(retrieval_trace)s::jsonb, %(llm_trace)s::jsonb, %(response_payload)s::jsonb, %(error_message)s,
                        %(created_at)s, %(completed_at)s
                    )
                    RETURNING *
                    """,
                    {
                        "id": run_id,
                        "tenant_id": tenant_id,
                        "incident_id": incident_id,
                        "mode": mode,
                        "status": status,
                        "request_payload": json.dumps(request_payload or {}),
                        "retrieval_trace": json.dumps(retrieval_trace or []),
                        "llm_trace": json.dumps(llm_trace or []),
                        "response_payload": (
                            json.dumps(response_payload)
                            if response_payload is not None
                            else None
                        ),
                        "error_message": error_message,
                        "created_at": now,
                        "completed_at": now,
                    },
                )
                row = cur.fetchone()
                conn.commit()
                return self._to_triage_run(row)

    def list_triage_runs(
        self,
        *,
        tenant_id: str,
        limit: int = 100,
        incident_id: str | None = None,
        mode: str | None = None,
    ) -> list[TriageRunRecord]:
        with get_conn(self.settings) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                conditions = ["tenant_id = %(tenant_id)s"]
                params: dict[str, Any] = {"tenant_id": tenant_id, "limit": limit}
                if incident_id:
                    conditions.append("incident_id = %(incident_id)s")
                    params["incident_id"] = incident_id
                if mode:
                    conditions.append("mode = %(mode)s")
                    params["mode"] = mode
                where_clause = " AND ".join(conditions)
                cur.execute(
                    f"""
                    SELECT * FROM triage_runs
                    WHERE {where_clause}
                    ORDER BY created_at DESC
                    LIMIT %(limit)s
                    """,
                    params,
                )
                rows = cur.fetchall()
                return [self._to_triage_run(row) for row in rows]

    def get_triage_run(self, *, tenant_id: str, run_id: UUID) -> TriageRunRecord | None:
        with get_conn(self.settings) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT * FROM triage_runs
                    WHERE tenant_id = %(tenant_id)s AND id = %(id)s::uuid
                    """,
                    {"tenant_id": tenant_id, "id": str(run_id)},
                )
                row = cur.fetchone()
                return self._to_triage_run(row) if row else None

    @staticmethod
    def _to_record(row: dict[str, Any]) -> KBExampleRecord:
        return KBExampleRecord(
            id=row["id"],
            tenant_id=row["tenant_id"],
            scope=row["scope"],
            proposed_severity=row["proposed_severity"],
            reason=row["reason"],
            alert_text=row["alert_text"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            current_severity=row.get("current_severity"),
            alert_id=row.get("alert_id"),
            incident_id=row.get("incident_id"),
            fingerprint=row.get("fingerprint"),
            source=row.get("source") or [],
            provider_id=row.get("provider_id"),
            incident_alerts=row.get("incident_alerts") or [],
            metadata=row.get("metadata") or {},
        )

    @staticmethod
    def _to_triage_run(row: dict[str, Any]) -> TriageRunRecord:
        return TriageRunRecord(
            id=row["id"],
            tenant_id=row["tenant_id"],
            incident_id=row["incident_id"],
            mode=row["mode"],
            status=row["status"],
            request_payload=row.get("request_payload") or {},
            retrieval_trace=row.get("retrieval_trace") or [],
            llm_trace=row.get("llm_trace") or [],
            response_payload=row.get("response_payload"),
            error_message=row.get("error_message"),
            created_at=row["created_at"],
            completed_at=row["completed_at"],
        )
