import datetime
from uuid import uuid4

import pytest

from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.tasks.local_kb_sync_client import LocalKBSyncError
from tests.fixtures.client import client, test_app  # noqa


class _StubLocalKBClient:
    def __init__(self):
        self.created_payload = None
        self.updated_payload = None
        self.deleted_payload = None

    def list_examples(self, tenant_id: str, scope: str | None = None, limit: int = 500):
        return {
            "items": [
                {
                    "id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "scope": scope or "alert",
                    "proposed_severity": "warning",
                    "reason": "Example reason",
                    "alert_text": "Alert text",
                    "created_by": "tester@keep.dev",
                    "created_at": "2026-03-03T11:00:00Z",
                    "updated_at": "2026-03-03T11:00:00Z",
                    "current_severity": "info",
                    "alert_id": "a-1",
                    "incident_id": None,
                    "fingerprint": "fp-1",
                    "source": ["mailgun"],
                    "provider_id": "provider-1",
                    "incident_alerts": [],
                    "metadata": {"rule": "r-1"},
                }
            ],
            "count": 1,
        }

    def create_example(self, body: dict):
        self.created_payload = body
        return {
            "id": str(uuid4()),
            "tenant_id": body["tenant_id"],
            "scope": body["scope"],
            "proposed_severity": body["proposed_severity"],
            "reason": body["reason"],
            "alert_text": body["alert_text"],
            "created_by": body["created_by"],
            "created_at": "2026-03-03T11:00:00Z",
            "updated_at": "2026-03-03T11:00:00Z",
            "current_severity": body.get("current_severity"),
            "alert_id": body.get("alert_id"),
            "incident_id": body.get("incident_id"),
            "fingerprint": body.get("fingerprint"),
            "source": body.get("source", []),
            "provider_id": body.get("provider_id"),
            "incident_alerts": body.get("incident_alerts", []),
            "metadata": body.get("metadata", {}),
        }

    def update_example(self, example_id: str, tenant_id: str, body: dict):
        self.updated_payload = {
            "example_id": example_id,
            "tenant_id": tenant_id,
            "body": body,
        }
        return {
            "id": example_id,
            "tenant_id": tenant_id,
            "scope": "alert",
            "proposed_severity": body.get("proposed_severity", "warning"),
            "reason": body.get("reason", "Updated"),
            "alert_text": body.get("alert_text", "Alert text"),
            "created_by": "tester@keep.dev",
            "created_at": "2026-03-03T11:00:00Z",
            "updated_at": "2026-03-03T12:00:00Z",
            "current_severity": "warning",
            "alert_id": "a-1",
            "incident_id": None,
            "fingerprint": "fp-1",
            "source": ["mailgun"],
            "provider_id": "provider-1",
            "incident_alerts": [],
            "metadata": {"updated": True},
        }

    def delete_example(self, example_id: str, tenant_id: str):
        self.deleted_payload = {
            "example_id": example_id,
            "tenant_id": tenant_id,
        }
        return {
            "status": "deleted",
            "id": example_id,
        }

    def list_triage_runs(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
        incident_id: str | None = None,
        mode: str | None = None,
    ):
        return {
            "items": [
                {
                    "id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "incident_id": incident_id or "inc-1",
                    "mode": mode or "single",
                    "status": "success",
                    "recommended_severity": "warning",
                    "reason": "Matched warning example",
                    "error_message": None,
                    "created_at": "2026-03-03T11:10:00Z",
                    "completed_at": "2026-03-03T11:10:01Z",
                }
            ],
            "count": 1,
        }

    def get_triage_run(self, run_id: str, tenant_id: str):
        return {
            "id": run_id,
            "tenant_id": tenant_id,
            "incident_id": "inc-1",
            "mode": "single",
            "status": "success",
            "recommended_severity": "warning",
            "reason": "Matched warning example",
            "error_message": None,
            "created_at": "2026-03-03T11:10:00Z",
            "completed_at": "2026-03-03T11:10:01Z",
            "request_payload": {"mode": "single"},
            "retrieval_trace": [{"mode": "single", "candidates": []}],
            "llm_trace": [{"normalized_response": {"recommended_severity": "warning"}}],
            "response_payload": {
                "incident_id": "inc-1",
                "recommended_severity": "warning",
                "reason": "Matched warning example",
                "validated_fingerprints": ["fp-1"],
                "matched_rules": [],
            },
        }


@pytest.mark.parametrize("test_app", ["NO_AUTH"], indirect=True)
def test_triage_kb_examples_and_logs_api(client, test_app, monkeypatch):
    stub_client = _StubLocalKBClient()
    monkeypatch.setattr(
        "keep.api.routes.triage_kb.get_local_kb_sync_client",
        lambda: stub_client,
    )

    create_response = client.post(
        "/triage-kb/examples",
        json={
            "scope": "alert",
            "proposed_severity": "warning",
            "reason": "Customer impact is moderate and repeatable.",
            "alert_text": "Alert from monitoring service.",
            "fingerprint": "fp-1",
            "source": ["mailgun"],
            "provider_id": "provider-1",
        },
        headers={"x-api-key": "some-api-key"},
    )
    assert create_response.status_code == 200
    assert create_response.json()["scope"] == "alert"
    assert stub_client.created_payload["tenant_id"] == SINGLE_TENANT_UUID
    assert stub_client.created_payload["created_by"]

    list_response = client.get(
        "/triage-kb/examples?scope=alert&limit=10",
        headers={"x-api-key": "some-api-key"},
    )
    assert list_response.status_code == 200
    list_body = list_response.json()
    assert list_body["count"] == 1
    assert list_body["items"][0]["scope"] == "alert"

    example_id = str(uuid4())
    update_response = client.put(
        f"/triage-kb/examples/{example_id}",
        json={
            "proposed_severity": "critical",
            "reason": "Escalating after repeated production failures.",
        },
        headers={"x-api-key": "some-api-key"},
    )
    assert update_response.status_code == 200
    assert update_response.json()["id"] == example_id
    assert stub_client.updated_payload["tenant_id"] == SINGLE_TENANT_UUID

    delete_response = client.delete(
        f"/triage-kb/examples/{example_id}",
        headers={"x-api-key": "some-api-key"},
    )
    assert delete_response.status_code == 200
    assert delete_response.json()["status"] == "deleted"
    assert stub_client.deleted_payload["tenant_id"] == SINGLE_TENANT_UUID

    logs_response = client.get(
        "/triage-kb/logs?limit=5&incident_id=inc-1&mode=single",
        headers={"x-api-key": "some-api-key"},
    )
    assert logs_response.status_code == 200
    logs_body = logs_response.json()
    assert logs_body["count"] == 1
    assert logs_body["items"][0]["mode"] == "single"

    run_id = str(uuid4())
    log_detail_response = client.get(
        f"/triage-kb/logs/{run_id}",
        headers={"x-api-key": "some-api-key"},
    )
    assert log_detail_response.status_code == 200
    detail = log_detail_response.json()
    assert detail["id"] == run_id
    assert isinstance(detail["retrieval_trace"], list)
    assert isinstance(detail["llm_trace"], list)


@pytest.mark.parametrize("test_app", ["NO_AUTH"], indirect=True)
def test_triage_kb_maps_upstream_error(client, test_app, monkeypatch):
    class _ErrorClient:
        def list_examples(self, *args, **kwargs):
            raise LocalKBSyncError(
                message="failed",
                status_code=503,
                response_body="upstream unavailable",
            )

    monkeypatch.setattr(
        "keep.api.routes.triage_kb.get_local_kb_sync_client",
        lambda: _ErrorClient(),
    )

    response = client.get(
        "/triage-kb/examples",
        headers={"x-api-key": "some-api-key"},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "upstream unavailable"
