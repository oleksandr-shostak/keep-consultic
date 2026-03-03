from uuid import uuid4

import pytest
from arq import Retry
from sqlmodel import select

from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.db.incident_severity_proposal import (
    IncidentSeverityProposal,
    IncidentSeverityProposalStatus,
)
from keep.api.tasks.sync_incident_severity_proposal_task import (
    MAX_SYNC_RETRIES,
    delete_incident_severity_proposal_from_vector_store,
    sync_incident_severity_proposal_to_vector_store,
)


def _create_pending_proposal(db_session) -> IncidentSeverityProposal:
    proposal = IncidentSeverityProposal(
        tenant_id=SINGLE_TENANT_UUID,
        incident_id=uuid4(),
        current_severity="warning",
        proposed_severity="high",
        reason="Escalation needed based on grouped alerts.",
        incident_name="Incident KB test",
        incident_status="firing",
        incident_snapshot={
            "id": "inc-1",
            "name": "Incident KB test",
            "status": "firing",
            "severity": "warning",
        },
        alerts_count=2,
        alerts_snapshot=[
            {
                "fingerprint": "fp-1",
                "name": "Alert 1",
                "status": "firing",
                "severity": "warning",
                "message": "message 1",
                "description": "description 1",
            },
            {
                "fingerprint": "fp-2",
                "name": "Alert 2",
                "status": "firing",
                "severity": "warning",
                "message": "message 2",
                "description": "description 2",
            },
        ],
        created_by="tester@keep.dev",
        dedupe_hash="incident-dedupe-1",
        sync_status=IncidentSeverityProposalStatus.PENDING.value,
    )
    db_session.add(proposal)
    db_session.commit()
    db_session.refresh(proposal)
    return proposal


def test_sync_incident_severity_proposal_success(db_session, monkeypatch):
    proposal = _create_pending_proposal(db_session)

    class FakeKBClient:
        @staticmethod
        def create_example(payload):
            assert payload["scope"] == "incident"
            return {"id": "f7a6be16-4694-4311-b8cd-12580f1e62f2"}

        @staticmethod
        def update_example(example_id, tenant_id, body):
            assert example_id == "f7a6be16-4694-4311-b8cd-12580f1e62f2"
            assert tenant_id == SINGLE_TENANT_UUID
            return {"id": example_id}

        @staticmethod
        def delete_example(*args, **kwargs):
            return {"status": "deleted"}

    monkeypatch.setattr(
        "keep.api.tasks.sync_incident_severity_proposal_task.get_local_kb_sync_client",
        lambda: FakeKBClient(),
    )

    sync_incident_severity_proposal_to_vector_store(
        {},
        SINGLE_TENANT_UUID,
        str(proposal.id),
    )

    db_session.expire_all()
    updated = db_session.exec(
        select(IncidentSeverityProposal).where(IncidentSeverityProposal.id == proposal.id)
    ).first()
    assert updated is not None
    assert updated.sync_status == IncidentSeverityProposalStatus.SYNCED.value
    assert updated.openai_file_id is None
    assert updated.openai_vector_file_id == "f7a6be16-4694-4311-b8cd-12580f1e62f2"
    assert updated.last_synced_at is not None


def test_sync_incident_severity_proposal_retries_on_failure(db_session, monkeypatch):
    proposal = _create_pending_proposal(db_session)

    class FailingKBClient:
        @staticmethod
        def create_example(payload):
            raise RuntimeError("temporary local KB outage")

    monkeypatch.setattr(
        "keep.api.tasks.sync_incident_severity_proposal_task.get_local_kb_sync_client",
        lambda: FailingKBClient(),
    )

    with pytest.raises(Retry):
        sync_incident_severity_proposal_to_vector_store(
            {"job_try": 1},
            SINGLE_TENANT_UUID,
            str(proposal.id),
        )

    db_session.expire_all()
    updated = db_session.exec(
        select(IncidentSeverityProposal).where(IncidentSeverityProposal.id == proposal.id)
    ).first()
    assert updated is not None
    assert updated.sync_status == IncidentSeverityProposalStatus.PENDING.value
    assert "temporary local KB outage" in (updated.sync_status_reason or "")


def test_sync_incident_severity_proposal_marks_failed_after_max_retries(
    db_session, monkeypatch
):
    proposal = _create_pending_proposal(db_session)

    class FailingKBClient:
        @staticmethod
        def create_example(payload):
            raise RuntimeError("permanent local KB outage")

    monkeypatch.setattr(
        "keep.api.tasks.sync_incident_severity_proposal_task.get_local_kb_sync_client",
        lambda: FailingKBClient(),
    )

    sync_incident_severity_proposal_to_vector_store(
        {"job_try": MAX_SYNC_RETRIES},
        SINGLE_TENANT_UUID,
        str(proposal.id),
    )

    db_session.expire_all()
    updated = db_session.exec(
        select(IncidentSeverityProposal).where(IncidentSeverityProposal.id == proposal.id)
    ).first()
    assert updated is not None
    assert updated.sync_status == IncidentSeverityProposalStatus.FAILED.value
    assert "permanent local KB outage" in (updated.sync_status_reason or "")


def test_delete_incident_severity_proposal_from_vector_store_success(
    db_session, monkeypatch
):
    proposal = _create_pending_proposal(db_session)
    proposal.openai_vector_file_id = "1ce5305c-fd91-419f-b130-44f721d5549c"
    proposal.vector_store_id = "legacy-vector-store-id"
    proposal.is_deleted = True
    db_session.add(proposal)
    db_session.commit()

    class FakeKBClient:
        @staticmethod
        def delete_example(example_id, tenant_id):
            assert example_id == "1ce5305c-fd91-419f-b130-44f721d5549c"
            assert tenant_id == SINGLE_TENANT_UUID
            return {"status": "deleted"}

    monkeypatch.setattr(
        "keep.api.tasks.sync_incident_severity_proposal_task.get_local_kb_sync_client",
        lambda: FakeKBClient(),
    )

    delete_incident_severity_proposal_from_vector_store(
        {},
        SINGLE_TENANT_UUID,
        str(proposal.id),
        proposal.vector_store_id,
    )

    db_session.expire_all()
    updated = db_session.exec(
        select(IncidentSeverityProposal).where(IncidentSeverityProposal.id == proposal.id)
    ).first()
    assert updated is not None
    assert updated.sync_status == IncidentSeverityProposalStatus.SYNCED.value
    assert updated.openai_file_id is None
    assert updated.openai_vector_file_id is None


def test_sync_incident_severity_proposal_reconciles_duplicate_examples(
    db_session, monkeypatch
):
    proposal = _create_pending_proposal(db_session)
    canonical_id = "10000000-0000-0000-0000-000000000011"
    created_id = "f0000000-0000-0000-0000-000000000011"
    deleted_ids: list[str] = []
    updated_ids: list[str] = []

    class FakeKBClient:
        @staticmethod
        def create_example(payload):
            return {"id": created_id}

        @staticmethod
        def list_examples(tenant_id, scope, limit):
            assert tenant_id == SINGLE_TENANT_UUID
            assert scope == "incident"
            return {
                "items": [
                    {
                        "id": created_id,
                        "incident_id": str(proposal.incident_id),
                        "metadata": {"proposal_id": str(proposal.id)},
                    },
                    {
                        "id": canonical_id,
                        "incident_id": str(proposal.incident_id),
                        "metadata": {"proposal_id": str(proposal.id)},
                    },
                ]
            }

        @staticmethod
        def update_example(example_id, tenant_id, body):
            updated_ids.append(example_id)
            assert tenant_id == SINGLE_TENANT_UUID
            return {"id": example_id}

        @staticmethod
        def delete_example(example_id, tenant_id):
            assert tenant_id == SINGLE_TENANT_UUID
            deleted_ids.append(example_id)
            return {"status": "deleted"}

    monkeypatch.setattr(
        "keep.api.tasks.sync_incident_severity_proposal_task.get_local_kb_sync_client",
        lambda: FakeKBClient(),
    )

    sync_incident_severity_proposal_to_vector_store(
        {}, SINGLE_TENANT_UUID, str(proposal.id)
    )

    db_session.expire_all()
    updated = db_session.exec(
        select(IncidentSeverityProposal).where(IncidentSeverityProposal.id == proposal.id)
    ).first()
    assert updated is not None
    assert updated.sync_status == IncidentSeverityProposalStatus.SYNCED.value
    assert updated.openai_vector_file_id == canonical_id
    assert canonical_id in updated_ids
    assert created_id in deleted_ids


def test_delete_incident_severity_proposal_cleans_orphan_examples(
    db_session, monkeypatch
):
    proposal = _create_pending_proposal(db_session)
    proposal.openai_vector_file_id = "7ce5305c-fd91-419f-b130-44f721d5549c"
    proposal.is_deleted = True
    db_session.add(proposal)
    db_session.commit()
    deleted_ids: list[str] = []
    orphan_id = "8ce5305c-fd91-419f-b130-44f721d5549c"

    class FakeKBClient:
        @staticmethod
        def list_examples(tenant_id, scope, limit):
            assert tenant_id == SINGLE_TENANT_UUID
            assert scope == "incident"
            return {
                "items": [
                    {
                        "id": orphan_id,
                        "incident_id": str(proposal.incident_id),
                        "metadata": {"proposal_id": str(proposal.id)},
                    }
                ]
            }

        @staticmethod
        def delete_example(example_id, tenant_id):
            assert tenant_id == SINGLE_TENANT_UUID
            deleted_ids.append(example_id)
            return {"status": "deleted"}

    monkeypatch.setattr(
        "keep.api.tasks.sync_incident_severity_proposal_task.get_local_kb_sync_client",
        lambda: FakeKBClient(),
    )

    delete_incident_severity_proposal_from_vector_store(
        {},
        SINGLE_TENANT_UUID,
        str(proposal.id),
    )

    assert proposal.openai_vector_file_id in deleted_ids
    assert orphan_id in deleted_ids
