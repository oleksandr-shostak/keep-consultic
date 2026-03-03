from uuid import uuid4

import pytest
from arq import Retry
from sqlmodel import select

from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.db.alert_severity_proposal import (
    AlertSeverityProposal,
    AlertSeverityProposalStatus,
)
from keep.api.tasks.sync_alert_severity_proposal_task import (
    MAX_SYNC_RETRIES,
    delete_alert_severity_proposal_from_vector_store,
    sync_alert_severity_proposal_to_vector_store,
)


def _create_pending_proposal(db_session) -> AlertSeverityProposal:
    proposal = AlertSeverityProposal(
        tenant_id=SINGLE_TENANT_UUID,
        alert_id=uuid4(),
        alert_fingerprint="fp-test-1",
        source=["mailgun"],
        provider_id="provider-1",
        provider_type="mailgun",
        current_severity="warning",
        proposed_severity="high",
        reason="Escalation needed from user feedback.",
        alert_name="Test alert",
        alert_message="Message",
        alert_description="Description",
        created_by="tester@keep.dev",
        dedupe_hash="dedupe-1",
        sync_status=AlertSeverityProposalStatus.PENDING.value,
    )
    db_session.add(proposal)
    db_session.commit()
    db_session.refresh(proposal)
    return proposal


def test_sync_alert_severity_proposal_success(db_session, monkeypatch):
    proposal = _create_pending_proposal(db_session)

    class FakeKBClient:
        @staticmethod
        def create_example(payload):
            assert payload["scope"] == "alert"
            return {"id": "aab2d35e-3f52-4f98-b655-4c42036b0d7d"}

        @staticmethod
        def update_example(example_id, tenant_id, body):
            assert example_id == "aab2d35e-3f52-4f98-b655-4c42036b0d7d"
            assert tenant_id == SINGLE_TENANT_UUID
            return {"id": example_id}

        @staticmethod
        def delete_example(*args, **kwargs):
            return {"status": "deleted"}

    monkeypatch.setattr(
        "keep.api.tasks.sync_alert_severity_proposal_task.get_local_kb_sync_client",
        lambda: FakeKBClient(),
    )

    sync_alert_severity_proposal_to_vector_store({}, SINGLE_TENANT_UUID, str(proposal.id))

    db_session.expire_all()
    updated = db_session.exec(
        select(AlertSeverityProposal).where(AlertSeverityProposal.id == proposal.id)
    ).first()
    assert updated is not None
    assert updated.sync_status == AlertSeverityProposalStatus.SYNCED.value
    assert updated.openai_file_id is None
    assert updated.openai_vector_file_id == "aab2d35e-3f52-4f98-b655-4c42036b0d7d"
    assert updated.last_synced_at is not None


def test_sync_alert_severity_proposal_retries_on_failure(db_session, monkeypatch):
    proposal = _create_pending_proposal(db_session)

    class FailingKBClient:
        @staticmethod
        def create_example(payload):
            raise RuntimeError("temporary local KB outage")

    monkeypatch.setattr(
        "keep.api.tasks.sync_alert_severity_proposal_task.get_local_kb_sync_client",
        lambda: FailingKBClient(),
    )

    with pytest.raises(Retry):
        sync_alert_severity_proposal_to_vector_store(
            {"job_try": 1},
            SINGLE_TENANT_UUID,
            str(proposal.id),
        )

    db_session.expire_all()
    updated = db_session.exec(
        select(AlertSeverityProposal).where(AlertSeverityProposal.id == proposal.id)
    ).first()
    assert updated is not None
    assert updated.sync_status == AlertSeverityProposalStatus.PENDING.value
    assert "temporary local KB outage" in (updated.sync_status_reason or "")


def test_sync_alert_severity_proposal_marks_failed_after_max_retries(
    db_session, monkeypatch
):
    proposal = _create_pending_proposal(db_session)

    class FailingKBClient:
        @staticmethod
        def create_example(payload):
            raise RuntimeError("permanent local KB outage")

    monkeypatch.setattr(
        "keep.api.tasks.sync_alert_severity_proposal_task.get_local_kb_sync_client",
        lambda: FailingKBClient(),
    )

    sync_alert_severity_proposal_to_vector_store(
        {"job_try": MAX_SYNC_RETRIES},
        SINGLE_TENANT_UUID,
        str(proposal.id),
    )

    db_session.expire_all()
    updated = db_session.exec(
        select(AlertSeverityProposal).where(AlertSeverityProposal.id == proposal.id)
    ).first()
    assert updated is not None
    assert updated.sync_status == AlertSeverityProposalStatus.FAILED.value
    assert "permanent local KB outage" in (updated.sync_status_reason or "")


def test_delete_alert_severity_proposal_from_vector_store_success(db_session, monkeypatch):
    proposal = _create_pending_proposal(db_session)
    proposal.openai_vector_file_id = "6f4e09cb-f2a8-45ba-a5ed-b1d438c5bc91"
    proposal.vector_store_id = "legacy-vector-store-id"
    proposal.is_deleted = True
    db_session.add(proposal)
    db_session.commit()

    class FakeKBClient:
        @staticmethod
        def delete_example(example_id, tenant_id):
            assert example_id == "6f4e09cb-f2a8-45ba-a5ed-b1d438c5bc91"
            assert tenant_id == SINGLE_TENANT_UUID
            return {"status": "deleted"}

    monkeypatch.setattr(
        "keep.api.tasks.sync_alert_severity_proposal_task.get_local_kb_sync_client",
        lambda: FakeKBClient(),
    )

    delete_alert_severity_proposal_from_vector_store(
        {},
        SINGLE_TENANT_UUID,
        str(proposal.id),
        proposal.vector_store_id,
    )

    db_session.expire_all()
    updated = db_session.exec(
        select(AlertSeverityProposal).where(AlertSeverityProposal.id == proposal.id)
    ).first()
    assert updated is not None
    assert updated.sync_status == AlertSeverityProposalStatus.SYNCED.value
    assert updated.openai_file_id is None
    assert updated.openai_vector_file_id is None


def test_sync_alert_severity_proposal_reconciles_duplicate_examples(
    db_session, monkeypatch
):
    proposal = _create_pending_proposal(db_session)
    canonical_id = "10000000-0000-0000-0000-000000000001"
    created_id = "f0000000-0000-0000-0000-000000000001"
    deleted_ids: list[str] = []
    updated_ids: list[str] = []

    class FakeKBClient:
        @staticmethod
        def create_example(payload):
            return {"id": created_id}

        @staticmethod
        def list_examples(tenant_id, scope, limit):
            assert tenant_id == SINGLE_TENANT_UUID
            assert scope == "alert"
            return {
                "items": [
                    {
                        "id": created_id,
                        "alert_id": str(proposal.alert_id),
                        "metadata": {"proposal_id": str(proposal.id)},
                    },
                    {
                        "id": canonical_id,
                        "alert_id": str(proposal.alert_id),
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
        "keep.api.tasks.sync_alert_severity_proposal_task.get_local_kb_sync_client",
        lambda: FakeKBClient(),
    )

    sync_alert_severity_proposal_to_vector_store({}, SINGLE_TENANT_UUID, str(proposal.id))

    db_session.expire_all()
    updated = db_session.exec(
        select(AlertSeverityProposal).where(AlertSeverityProposal.id == proposal.id)
    ).first()
    assert updated is not None
    assert updated.sync_status == AlertSeverityProposalStatus.SYNCED.value
    assert updated.openai_vector_file_id == canonical_id
    assert canonical_id in updated_ids
    assert created_id in deleted_ids


def test_delete_alert_severity_proposal_cleans_orphan_examples(db_session, monkeypatch):
    proposal = _create_pending_proposal(db_session)
    proposal.openai_vector_file_id = "7f4e09cb-f2a8-45ba-a5ed-b1d438c5bc91"
    proposal.is_deleted = True
    db_session.add(proposal)
    db_session.commit()
    deleted_ids: list[str] = []
    orphan_id = "8f4e09cb-f2a8-45ba-a5ed-b1d438c5bc91"

    class FakeKBClient:
        @staticmethod
        def list_examples(tenant_id, scope, limit):
            assert tenant_id == SINGLE_TENANT_UUID
            assert scope == "alert"
            return {
                "items": [
                    {
                        "id": orphan_id,
                        "alert_id": str(proposal.alert_id),
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
        "keep.api.tasks.sync_alert_severity_proposal_task.get_local_kb_sync_client",
        lambda: FakeKBClient(),
    )

    delete_alert_severity_proposal_from_vector_store(
        {},
        SINGLE_TENANT_UUID,
        str(proposal.id),
    )

    assert proposal.openai_vector_file_id in deleted_ids
    assert orphan_id in deleted_ids
