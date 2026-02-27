import io
import json
import logging
import os
from datetime import datetime, timezone
from uuid import UUID

from arq import Retry
from openai import OpenAI
from sqlmodel import select

from keep.api.core.config import config
from keep.api.core.db import get_session_sync
from keep.api.models.db.alert_severity_proposal import (
    AlertSeverityProposal,
    AlertSeverityProposalStatus,
)

logger = logging.getLogger(__name__)

MAX_SYNC_RETRIES = int(
    config("KEEP_ALERT_PROPOSAL_SYNC_RETRIES", cast=int, default=5)
)


def _get_openai_client() -> OpenAI:
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("OPEN_AI_API_KEY")
    organization_id = os.environ.get("OPEN_AI_ORGANIZATION_ID")

    if not api_key:
        raise RuntimeError(
            "OpenAI API key is not configured (OPENAI_API_KEY / OPEN_AI_API_KEY)."
        )

    return OpenAI(api_key=api_key, organization=organization_id)


def _build_training_document(proposal: AlertSeverityProposal) -> dict:
    alert_text_parts = [
        proposal.alert_name or "",
        proposal.alert_message or "",
        proposal.alert_description or "",
    ]
    alert_text = "\n\n".join(part.strip() for part in alert_text_parts if part and part.strip())
    return {
        "tenant_id": proposal.tenant_id,
        "alert_id": str(proposal.alert_id),
        "fingerprint": proposal.alert_fingerprint,
        "source": proposal.source or [],
        "provider_id": proposal.provider_id,
        "provider_type": proposal.provider_type,
        "current_severity": proposal.current_severity,
        "proposed_severity": proposal.proposed_severity,
        "reason": proposal.reason,
        "alert_name": proposal.alert_name,
        "alert_message": proposal.alert_message,
        "alert_description": proposal.alert_description,
        "alert_text": alert_text,
        "created_by": proposal.created_by,
        "created_at": proposal.created_at.isoformat(),
        "proposal_id": str(proposal.id),
    }


def _get_retry_delay_seconds(job_try: int) -> int:
    return min(300, 2 ** min(job_try, 8))


def _resolve_target_vector_store_id(
    explicit_vector_store_id: str | None,
    proposal_vector_store_id: str | None,
) -> str | None:
    for candidate in (
        explicit_vector_store_id,
        proposal_vector_store_id,
        os.environ.get("KEEP_ALERT_PROPOSAL_VECTOR_STORE_ID"),
        os.environ.get("OPENAI_INCIDENTS_TRIAGE_VECTOR_STORE_ID"),
    ):
        if candidate and str(candidate).strip():
            return str(candidate).strip()
    return None


def _safe_vector_store_file_delete(
    client: OpenAI, vector_store_id: str, candidate_id: str
) -> None:
    delete_method = client.vector_stores.files.delete
    errors: list[Exception] = []
    call_variants = [
        {"vector_store_id": vector_store_id, "file_id": candidate_id},
        {"vector_store_id": vector_store_id, "vector_store_file_id": candidate_id},
    ]
    for kwargs in call_variants:
        try:
            delete_method(**kwargs)
            return
        except TypeError:
            continue
        except Exception as exc:
            errors.append(exc)
            break

    try:
        delete_method(vector_store_id, candidate_id)
        return
    except Exception as exc:
        errors.append(exc)
        raise errors[-1] if errors else exc


def _delete_proposal_openai_artifacts(
    client: OpenAI, proposal: AlertSeverityProposal, vector_store_id: str | None
) -> None:
    if vector_store_id:
        for candidate in (
            proposal.openai_vector_file_id,
            proposal.openai_file_id,
        ):
            if not candidate:
                continue
            try:
                _safe_vector_store_file_delete(client, vector_store_id, candidate)
                break
            except Exception:
                logger.warning(
                    "Failed deleting file from vector store",
                    extra={
                        "tenant_id": proposal.tenant_id,
                        "proposal_id": str(proposal.id),
                        "vector_store_id": vector_store_id,
                        "candidate_file_id": candidate,
                    },
                )

    if proposal.openai_file_id:
        try:
            client.files.delete(proposal.openai_file_id)
        except Exception:
            logger.warning(
                "Failed deleting uploaded OpenAI file",
                extra={
                    "tenant_id": proposal.tenant_id,
                    "proposal_id": str(proposal.id),
                    "openai_file_id": proposal.openai_file_id,
                },
            )


def _update_status(
    session,
    proposal: AlertSeverityProposal,
    status: AlertSeverityProposalStatus,
    reason: str,
):
    proposal.sync_status = status.value
    proposal.sync_status_reason = reason[:1000] if reason else None
    session.add(proposal)
    session.commit()


def sync_alert_severity_proposal_to_vector_store(
    ctx: dict,
    tenant_id: str,
    proposal_id: str,
    vector_store_id: str | None = None,
):
    try:
        proposal_uuid = UUID(proposal_id)
    except ValueError:
        logger.error(
            "Invalid proposal id for vector sync",
            extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
        )
        return

    session = get_session_sync()
    try:
        proposal = session.exec(
            select(AlertSeverityProposal)
            .where(AlertSeverityProposal.tenant_id == tenant_id)
            .where(AlertSeverityProposal.id == proposal_uuid)
        ).first()

        if not proposal:
            logger.warning(
                "Alert severity proposal not found for vector sync",
                extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
            )
            return

        if proposal.sync_status == AlertSeverityProposalStatus.SYNCED.value:
            logger.info(
                "Alert severity proposal already synced, skipping",
                extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
            )
            return

        if proposal.is_deleted:
            logger.info(
                "Proposal marked deleted; skipping sync-to-vector-store upload",
                extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
            )
            return

        proposal.sync_attempts = (proposal.sync_attempts or 0) + 1
        _update_status(
            session,
            proposal,
            AlertSeverityProposalStatus.PENDING,
            f"Sync attempt {proposal.sync_attempts} is in progress.",
        )

        target_vector_store_id = _resolve_target_vector_store_id(
            vector_store_id,
            proposal.vector_store_id,
        )
        if not target_vector_store_id:
            raise RuntimeError(
                "Vector store id is not configured. "
                "Set KEEP_ALERT_PROPOSAL_VECTOR_STORE_ID or OPENAI_INCIDENTS_TRIAGE_VECTOR_STORE_ID."
            )

        client = _get_openai_client()
        # Replace mode: if a file was already synced for this proposal, delete it first.
        if proposal.openai_file_id or proposal.openai_vector_file_id:
            _delete_proposal_openai_artifacts(
                client,
                proposal,
                target_vector_store_id,
            )

        payload = _build_training_document(proposal)
        payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        payload_buffer = io.BytesIO(payload_bytes)
        payload_buffer.name = f"keep-alert-proposal-{proposal.id}.json"

        uploaded_file = client.files.create(file=payload_buffer, purpose="assistants")

        vector_file = client.vector_stores.files.create(
            vector_store_id=target_vector_store_id,
            file_id=uploaded_file.id,
        )
        vector_file_status = getattr(vector_file, "status", None)

        proposal.openai_file_id = uploaded_file.id
        proposal.openai_vector_file_id = getattr(vector_file, "id", None)
        proposal.vector_store_id = target_vector_store_id
        proposal.sync_status = AlertSeverityProposalStatus.SYNCED.value
        proposal.sync_status_reason = (
            "Synced to vector store"
            + (f" (status: {vector_file_status})" if vector_file_status else "")
        )
        proposal.last_synced_at = datetime.now(tz=timezone.utc)
        session.add(proposal)
        session.commit()
        logger.info(
            "Synced alert severity proposal to vector store",
            extra={
                "tenant_id": tenant_id,
                "proposal_id": proposal_id,
                "vector_store_id": target_vector_store_id,
                "openai_file_id": uploaded_file.id,
                "openai_vector_file_id": proposal.openai_vector_file_id,
            },
        )
    except Exception as exc:
        logger.exception(
            "Failed syncing alert severity proposal to vector store",
            extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
        )
        proposal = session.exec(
            select(AlertSeverityProposal)
            .where(AlertSeverityProposal.tenant_id == tenant_id)
            .where(AlertSeverityProposal.id == proposal_uuid)
        ).first()
        if proposal:
            current_try = int(ctx.get("job_try", proposal.sync_attempts or 1)) if ctx else (proposal.sync_attempts or 1)
            should_retry = bool(ctx) and current_try < MAX_SYNC_RETRIES
            _update_status(
                session,
                proposal,
                AlertSeverityProposalStatus.PENDING
                if should_retry
                else AlertSeverityProposalStatus.FAILED,
                str(exc),
            )
            if should_retry:
                raise Retry(defer=_get_retry_delay_seconds(current_try))
    finally:
        session.close()


async def async_sync_alert_severity_proposal(*args, **kwargs):
    return sync_alert_severity_proposal_to_vector_store(*args, **kwargs)


def delete_alert_severity_proposal_from_vector_store(
    ctx: dict,
    tenant_id: str,
    proposal_id: str,
    vector_store_id: str | None = None,
):
    try:
        proposal_uuid = UUID(proposal_id)
    except ValueError:
        logger.error(
            "Invalid proposal id for vector delete",
            extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
        )
        return

    session = get_session_sync()
    try:
        proposal = session.exec(
            select(AlertSeverityProposal)
            .where(AlertSeverityProposal.tenant_id == tenant_id)
            .where(AlertSeverityProposal.id == proposal_uuid)
        ).first()
        if not proposal:
            logger.warning(
                "Alert severity proposal not found for vector delete",
                extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
            )
            return

        proposal.sync_attempts = (proposal.sync_attempts or 0) + 1
        _update_status(
            session,
            proposal,
            AlertSeverityProposalStatus.PENDING,
            f"Delete sync attempt {proposal.sync_attempts} is in progress.",
        )

        target_vector_store_id = _resolve_target_vector_store_id(
            vector_store_id,
            proposal.vector_store_id,
        )
        if not target_vector_store_id:
            raise RuntimeError(
                "Vector store id is not configured. "
                "Set KEEP_ALERT_PROPOSAL_VECTOR_STORE_ID or OPENAI_INCIDENTS_TRIAGE_VECTOR_STORE_ID."
            )
        client = _get_openai_client()

        if proposal.openai_file_id or proposal.openai_vector_file_id:
            _delete_proposal_openai_artifacts(
                client,
                proposal,
                target_vector_store_id,
            )

        proposal.openai_file_id = None
        proposal.openai_vector_file_id = None
        proposal.last_synced_at = datetime.now(tz=timezone.utc)
        proposal.vector_store_id = target_vector_store_id
        _update_status(
            session,
            proposal,
            AlertSeverityProposalStatus.SYNCED,
            "Deleted from vector store.",
        )
        session.refresh(proposal)
        logger.info(
            "Deleted alert severity proposal from vector store",
            extra={
                "tenant_id": tenant_id,
                "proposal_id": proposal_id,
                "vector_store_id": target_vector_store_id,
            },
        )
    except Exception as exc:
        logger.exception(
            "Failed deleting alert severity proposal from vector store",
            extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
        )
        proposal = session.exec(
            select(AlertSeverityProposal)
            .where(AlertSeverityProposal.tenant_id == tenant_id)
            .where(AlertSeverityProposal.id == proposal_uuid)
        ).first()
        if proposal:
            current_try = (
                int(ctx.get("job_try", proposal.sync_attempts or 1))
                if ctx
                else (proposal.sync_attempts or 1)
            )
            should_retry = bool(ctx) and current_try < MAX_SYNC_RETRIES
            _update_status(
                session,
                proposal,
                AlertSeverityProposalStatus.PENDING
                if should_retry
                else AlertSeverityProposalStatus.FAILED,
                str(exc),
            )
            if should_retry:
                raise Retry(defer=_get_retry_delay_seconds(current_try))
    finally:
        session.close()


async def async_delete_alert_severity_proposal(*args, **kwargs):
    return delete_alert_severity_proposal_from_vector_store(*args, **kwargs)
