import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from arq import Retry
from sqlmodel import select

from keep.api.core.config import config
from keep.api.core.db import get_session_sync
from keep.api.models.db.incident_severity_proposal import (
    IncidentSeverityProposal,
    IncidentSeverityProposalStatus,
)
from keep.api.tasks.local_kb_sync_client import (
    LocalKBSyncError,
    get_local_kb_sync_client,
)

logger = logging.getLogger(__name__)

MAX_SYNC_RETRIES = int(
    config("KEEP_INCIDENT_PROPOSAL_SYNC_RETRIES", cast=int, default=5)
)


def _get_retry_delay_seconds(job_try: int) -> int:
    return min(300, 2 ** min(job_try, 8))


def _is_uuid(value: str | None) -> bool:
    if not value:
        return False
    try:
        UUID(str(value))
        return True
    except Exception:
        return False


def _build_alert_text(proposal: IncidentSeverityProposal) -> str:
    return "\n\n---\n\n".join(
        [
            "\n".join(
                [
                    f"name: {alert.get('name') or ''}",
                    f"status: {alert.get('status') or ''}",
                    f"severity: {alert.get('severity') or ''}",
                    f"fingerprint: {alert.get('fingerprint') or ''}",
                    f"source: {alert.get('source') or []}",
                    f"provider_id: {alert.get('provider_id') or ''}",
                    f"message: {alert.get('message') or ''}",
                    f"description: {alert.get('description') or ''}",
                ]
            ).strip()
            for alert in (proposal.alerts_snapshot or [])
        ]
    ).strip()


def _build_kb_create_payload(proposal: IncidentSeverityProposal) -> dict:
    return {
        "tenant_id": proposal.tenant_id,
        "scope": "incident",
        "proposed_severity": proposal.proposed_severity,
        "reason": proposal.reason,
        "alert_text": _build_alert_text(proposal),
        "created_by": proposal.created_by,
        "current_severity": proposal.current_severity,
        "incident_id": str(proposal.incident_id),
        "incident_alerts": proposal.alerts_snapshot or [],
        "metadata": {
            "proposal_id": str(proposal.id),
            "incident_name": proposal.incident_name,
            "incident_status": proposal.incident_status,
            "alerts_count": proposal.alerts_count,
            "created_at": proposal.created_at.isoformat(),
        },
    }


def _build_kb_update_payload(proposal: IncidentSeverityProposal) -> dict:
    return {
        "proposed_severity": proposal.proposed_severity,
        "reason": proposal.reason,
        "alert_text": _build_alert_text(proposal),
        "current_severity": proposal.current_severity,
        "incident_alerts": proposal.alerts_snapshot or [],
        "metadata": {
            "proposal_id": str(proposal.id),
            "incident_name": proposal.incident_name,
            "incident_status": proposal.incident_status,
            "alerts_count": proposal.alerts_count,
            "updated_at": datetime.now(tz=timezone.utc).isoformat(),
        },
    }


def _update_status(
    session,
    proposal: IncidentSeverityProposal,
    status: IncidentSeverityProposalStatus,
    reason: str,
):
    proposal.sync_status = status.value
    proposal.sync_status_reason = reason[:1000] if reason else None
    session.add(proposal)
    session.commit()


def _extract_example_id(example: dict[str, Any]) -> str | None:
    raw_id = example.get("id")
    if raw_id is None:
        return None
    example_id = str(raw_id)
    return example_id if _is_uuid(example_id) else None


def _matches_proposal_metadata(
    example: dict[str, Any], proposal: IncidentSeverityProposal
) -> bool:
    metadata = example.get("metadata") or {}
    if not isinstance(metadata, dict):
        return False
    proposal_id = metadata.get("proposal_id")
    return proposal_id is not None and str(proposal_id) == str(proposal.id)


def _matches_incident_example(
    example: dict[str, Any], proposal: IncidentSeverityProposal
) -> bool:
    if _matches_proposal_metadata(example, proposal):
        return True
    incident_id = example.get("incident_id")
    return incident_id is not None and str(incident_id) == str(proposal.incident_id)


def _list_matching_incident_example_ids(
    client, proposal: IncidentSeverityProposal
) -> set[str]:
    list_examples = getattr(client, "list_examples", None)
    if not callable(list_examples):
        return set()
    try:
        response = list_examples(
            tenant_id=proposal.tenant_id,
            scope="incident",
            limit=500,
        )
    except LocalKBSyncError:
        logger.warning(
            "Failed listing local KB examples while reconciling incident proposal",
            extra={"tenant_id": proposal.tenant_id, "proposal_id": str(proposal.id)},
        )
        return set()

    items = response.get("items") if isinstance(response, dict) else []
    if not isinstance(items, list):
        return set()

    matching_ids: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        example_id = _extract_example_id(item)
        if not example_id:
            continue
        if _matches_incident_example(item, proposal):
            matching_ids.add(example_id)
    return matching_ids


def _delete_example_if_exists(client, tenant_id: str, example_id: str):
    if not _is_uuid(example_id):
        return
    try:
        client.delete_example(
            example_id=example_id,
            tenant_id=tenant_id,
        )
    except LocalKBSyncError as exc:
        if exc.status_code != 404:
            raise


def _reconcile_incident_examples(
    client,
    proposal: IncidentSeverityProposal,
    preferred_example_id: str | None,
) -> str | None:
    matching_ids = _list_matching_incident_example_ids(client, proposal)
    if _is_uuid(preferred_example_id):
        matching_ids.add(str(preferred_example_id))

    if not matching_ids:
        return str(preferred_example_id) if _is_uuid(preferred_example_id) else None

    # Deterministic canonical id prevents concurrent jobs from choosing different survivors.
    canonical_id = sorted(matching_ids)[0]

    try:
        client.update_example(
            example_id=canonical_id,
            tenant_id=proposal.tenant_id,
            body=_build_kb_update_payload(proposal),
        )
    except LocalKBSyncError as exc:
        if exc.status_code == 404:
            create_response = client.create_example(_build_kb_create_payload(proposal))
            canonical_id = str(create_response.get("id") or "")
            if not _is_uuid(canonical_id):
                raise RuntimeError(
                    "Local KB sync response missing canonical example id"
                ) from exc
        else:
            raise

    for example_id in sorted(matching_ids):
        if example_id == canonical_id:
            continue
        _delete_example_if_exists(client, proposal.tenant_id, example_id)

    return canonical_id


def sync_incident_severity_proposal_to_vector_store(
    ctx: dict,
    tenant_id: str,
    proposal_id: str,
    vector_store_id: str | None = None,
):
    try:
        proposal_uuid = UUID(proposal_id)
    except ValueError:
        logger.error(
            "Invalid incident proposal id for local KB sync",
            extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
        )
        return

    session = get_session_sync()
    try:
        proposal = session.exec(
            select(IncidentSeverityProposal)
            .where(IncidentSeverityProposal.tenant_id == tenant_id)
            .where(IncidentSeverityProposal.id == proposal_uuid)
        ).first()

        if not proposal:
            logger.warning(
                "Incident severity proposal not found for local KB sync",
                extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
            )
            return

        if proposal.is_deleted:
            logger.info(
                "Incident proposal marked deleted; skipping upload sync",
                extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
            )
            return

        start_dedupe_hash = proposal.dedupe_hash
        proposal.sync_attempts = (proposal.sync_attempts or 0) + 1
        _update_status(
            session,
            proposal,
            IncidentSeverityProposalStatus.PENDING,
            f"Sync attempt {proposal.sync_attempts} is in progress.",
        )

        client = get_local_kb_sync_client()
        response: dict
        if _is_uuid(proposal.openai_vector_file_id):
            try:
                response = client.update_example(
                    example_id=str(proposal.openai_vector_file_id),
                    tenant_id=proposal.tenant_id,
                    body=_build_kb_update_payload(proposal),
                )
            except LocalKBSyncError as exc:
                if exc.status_code == 404:
                    response = client.create_example(_build_kb_create_payload(proposal))
                else:
                    raise
        else:
            response = client.create_example(_build_kb_create_payload(proposal))

        kb_example_id = response.get("id")
        if not kb_example_id:
            raise RuntimeError("Local KB sync response missing example id")
        canonical_example_id = _reconcile_incident_examples(
            client=client,
            proposal=proposal,
            preferred_example_id=str(kb_example_id),
        )
        if not _is_uuid(canonical_example_id):
            raise RuntimeError("Failed to resolve canonical local KB example id")

        session.refresh(proposal)
        if proposal.is_deleted or proposal.dedupe_hash != start_dedupe_hash:
            logger.warning(
                "Incident proposal changed during sync; scheduling retry with latest data",
                extra={
                    "tenant_id": tenant_id,
                    "proposal_id": proposal_id,
                    "start_dedupe_hash": start_dedupe_hash,
                    "current_dedupe_hash": proposal.dedupe_hash,
                    "is_deleted": proposal.is_deleted,
                },
            )
            if ctx:
                raise RuntimeError(
                    "Incident proposal changed during sync; retry with latest state"
                )
            return

        proposal.openai_file_id = None
        proposal.openai_vector_file_id = str(canonical_example_id)
        proposal.vector_store_id = vector_store_id or proposal.vector_store_id
        proposal.sync_status = IncidentSeverityProposalStatus.SYNCED.value
        proposal.sync_status_reason = "Synced to local KB."
        proposal.last_synced_at = datetime.now(tz=timezone.utc)
        session.add(proposal)
        session.commit()

        logger.info(
            "Synced incident severity proposal to local KB",
            extra={
                "tenant_id": tenant_id,
                "proposal_id": proposal_id,
                "kb_example_id": proposal.openai_vector_file_id,
            },
        )
    except Exception as exc:
        logger.exception(
            "Failed syncing incident severity proposal to local KB",
            extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
        )
        proposal = session.exec(
            select(IncidentSeverityProposal)
            .where(IncidentSeverityProposal.tenant_id == tenant_id)
            .where(IncidentSeverityProposal.id == proposal_uuid)
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
                IncidentSeverityProposalStatus.PENDING
                if should_retry
                else IncidentSeverityProposalStatus.FAILED,
                str(exc),
            )
            if should_retry:
                raise Retry(defer=_get_retry_delay_seconds(current_try))
    finally:
        session.close()


async def async_sync_incident_severity_proposal(*args, **kwargs):
    return sync_incident_severity_proposal_to_vector_store(*args, **kwargs)


def delete_incident_severity_proposal_from_vector_store(
    ctx: dict,
    tenant_id: str,
    proposal_id: str,
    vector_store_id: str | None = None,
):
    try:
        proposal_uuid = UUID(proposal_id)
    except ValueError:
        logger.error(
            "Invalid incident proposal id for local KB delete",
            extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
        )
        return

    session = get_session_sync()
    try:
        proposal = session.exec(
            select(IncidentSeverityProposal)
            .where(IncidentSeverityProposal.tenant_id == tenant_id)
            .where(IncidentSeverityProposal.id == proposal_uuid)
        ).first()
        if not proposal:
            logger.warning(
                "Incident severity proposal not found for local KB delete",
                extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
            )
            return

        proposal.sync_attempts = (proposal.sync_attempts or 0) + 1
        _update_status(
            session,
            proposal,
            IncidentSeverityProposalStatus.PENDING,
            f"Delete sync attempt {proposal.sync_attempts} is in progress.",
        )

        client = get_local_kb_sync_client()
        if _is_uuid(proposal.openai_vector_file_id):
            _delete_example_if_exists(
                client=client,
                tenant_id=proposal.tenant_id,
                example_id=str(proposal.openai_vector_file_id),
            )

        # Defensive cleanup for previously orphaned rows from older sync races.
        for example_id in sorted(_list_matching_incident_example_ids(client, proposal)):
            _delete_example_if_exists(
                client=client,
                tenant_id=proposal.tenant_id,
                example_id=example_id,
            )

        proposal.openai_file_id = None
        proposal.openai_vector_file_id = None
        proposal.last_synced_at = datetime.now(tz=timezone.utc)
        proposal.vector_store_id = vector_store_id or proposal.vector_store_id
        _update_status(
            session,
            proposal,
            IncidentSeverityProposalStatus.SYNCED,
            "Deleted from local KB.",
        )
        session.refresh(proposal)

        logger.info(
            "Deleted incident severity proposal from local KB",
            extra={
                "tenant_id": tenant_id,
                "proposal_id": proposal_id,
            },
        )
    except Exception as exc:
        logger.exception(
            "Failed deleting incident severity proposal from local KB",
            extra={"tenant_id": tenant_id, "proposal_id": proposal_id},
        )
        proposal = session.exec(
            select(IncidentSeverityProposal)
            .where(IncidentSeverityProposal.tenant_id == tenant_id)
            .where(IncidentSeverityProposal.id == proposal_uuid)
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
                IncidentSeverityProposalStatus.PENDING
                if should_retry
                else IncidentSeverityProposalStatus.FAILED,
                str(exc),
            )
            if should_retry:
                raise Retry(defer=_get_retry_delay_seconds(current_try))
    finally:
        session.close()


async def async_delete_incident_severity_proposal(*args, **kwargs):
    return delete_incident_severity_proposal_from_vector_store(*args, **kwargs)
