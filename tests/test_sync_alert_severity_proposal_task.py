from types import SimpleNamespace
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
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class FakeFiles:
        @staticmethod
        def create(*args, **kwargs):
            return SimpleNamespace(id="file_123")

        @staticmethod
        def delete(*args, **kwargs):
            return SimpleNamespace(deleted=True)

    class FakeVectorStoreFiles:
        @staticmethod
        def create(*args, **kwargs):
            return SimpleNamespace(id="vsfile_123", status="completed")

        @staticmethod
        def delete(*args, **kwargs):
            return SimpleNamespace(deleted=True)

    class FakeVectorStores:
        files = FakeVectorStoreFiles()

    class FakeOpenAI:
        def __init__(self, *args, **kwargs):
            self.files = FakeFiles()
            self.vector_stores = FakeVectorStores()

    monkeypatch.setattr(
        "keep.api.tasks.sync_alert_severity_proposal_task.OpenAI", FakeOpenAI
    )

    sync_alert_severity_proposal_to_vector_store({}, SINGLE_TENANT_UUID, str(proposal.id))

    db_session.expire_all()
    updated = db_session.exec(
        select(AlertSeverityProposal).where(AlertSeverityProposal.id == proposal.id)
    ).first()
    assert updated is not None
    assert updated.sync_status == AlertSeverityProposalStatus.SYNCED.value
    assert updated.openai_file_id == "file_123"
    assert updated.openai_vector_file_id == "vsfile_123"
    assert updated.last_synced_at is not None


def test_sync_alert_severity_proposal_retries_on_failure(
    db_session, monkeypatch
):
    proposal = _create_pending_proposal(db_session)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class FailingOpenAI:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("temporary OpenAI outage")

    monkeypatch.setattr(
        "keep.api.tasks.sync_alert_severity_proposal_task.OpenAI", FailingOpenAI
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
    assert "temporary OpenAI outage" in (updated.sync_status_reason or "")


def test_sync_alert_severity_proposal_marks_failed_after_max_retries(
    db_session, monkeypatch
):
    proposal = _create_pending_proposal(db_session)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class FailingOpenAI:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("permanent OpenAI outage")

    monkeypatch.setattr(
        "keep.api.tasks.sync_alert_severity_proposal_task.OpenAI", FailingOpenAI
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
    assert "permanent OpenAI outage" in (updated.sync_status_reason or "")


def test_delete_alert_severity_proposal_from_vector_store_success(db_session, monkeypatch):
    proposal = _create_pending_proposal(db_session)
    proposal.openai_file_id = "file_123"
    proposal.openai_vector_file_id = "vsfile_123"
    proposal.vector_store_id = "vs_test_123"
    proposal.is_deleted = True
    db_session.add(proposal)
    db_session.commit()

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class FakeFiles:
        @staticmethod
        def delete(*args, **kwargs):
            return SimpleNamespace(deleted=True)

    class FakeVectorStoreFiles:
        @staticmethod
        def delete(*args, **kwargs):
            return SimpleNamespace(deleted=True)

    class FakeVectorStores:
        files = FakeVectorStoreFiles()

    class FakeOpenAI:
        def __init__(self, *args, **kwargs):
            self.files = FakeFiles()
            self.vector_stores = FakeVectorStores()

    monkeypatch.setattr(
        "keep.api.tasks.sync_alert_severity_proposal_task.OpenAI", FakeOpenAI
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
