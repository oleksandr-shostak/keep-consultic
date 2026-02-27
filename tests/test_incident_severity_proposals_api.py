import time

import pytest
from sqlmodel import select

from keep.api.models.db.incident_severity_proposal import IncidentSeverityProposal
from keep.providers.providers_factory import ProvidersFactory
from tests.fixtures.client import client, test_app  # noqa


def _wait_for_first_alert(client, timeout_seconds: float = 5.0) -> dict:
    start = time.time()
    while time.time() - start < timeout_seconds:
        alerts = client.get("/alerts", headers={"x-api-key": "some-api-key"}).json()
        if alerts:
            return alerts[0]
        time.sleep(0.1)
    raise AssertionError("Timed out waiting for alert to be processed")


def _create_test_alert(client) -> dict:
    provider = ProvidersFactory.get_provider_class("datadog")
    alert_payload = provider.simulate_alert()
    post_event = client.post(
        "/alerts/event/datadog",
        json=alert_payload,
        headers={"x-api-key": "some-api-key"},
    )
    assert post_event.status_code == 202
    return _wait_for_first_alert(client)


def _create_test_incident_with_alert(client) -> dict:
    create_incident = client.post(
        "/incidents",
        json={
            "user_generated_name": "Incident KB test",
            "user_summary": "Incident for user proposed severity tests.",
            "severity": "warning",
        },
        headers={"x-api-key": "some-api-key"},
    )
    assert create_incident.status_code == 202
    incident = create_incident.json()
    alert = _create_test_alert(client)
    add_alert = client.post(
        f"/incidents/{incident['id']}/alerts",
        json=[alert["fingerprint"]],
        headers={"x-api-key": "some-api-key"},
    )
    assert add_alert.status_code == 202
    return incident


@pytest.mark.parametrize("test_app", ["NO_AUTH"], indirect=True)
def test_create_get_update_delete_incident_severity_proposal(
    db_session, client, test_app, monkeypatch
):
    monkeypatch.setattr(
        "keep.api.routes.incidents.sync_incident_severity_proposal_to_vector_store",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "keep.api.routes.incidents.delete_incident_severity_proposal_from_vector_store",
        lambda *args, **kwargs: None,
    )

    incident = _create_test_incident_with_alert(client)
    incident_id = incident["id"]

    create_response = client.post(
        f"/incidents/{incident_id}/propose-severity",
        json={
            "proposed_severity": "high",
            "reason": "Multiple alerts indicate broader impact than warning.",
        },
        headers={"x-api-key": "some-api-key"},
    )
    assert create_response.status_code == 200
    created = create_response.json()
    assert created["proposed_severity"] == "high"
    assert created["reason"] == "Multiple alerts indicate broader impact than warning."
    assert created["deduplicated"] is False
    assert created["alerts_count"] >= 1

    dedupe_response = client.post(
        f"/incidents/{incident_id}/propose-severity",
        json={
            "proposed_severity": "high",
            "reason": "Multiple alerts indicate broader impact than warning.",
        },
        headers={"x-api-key": "some-api-key"},
    )
    assert dedupe_response.status_code == 200
    dedupe_body = dedupe_response.json()
    assert dedupe_body["id"] == created["id"]
    assert dedupe_body["deduplicated"] is True

    get_response = client.get(
        f"/incidents/{incident_id}/propose-severity",
        headers={"x-api-key": "some-api-key"},
    )
    assert get_response.status_code == 200
    fetched = get_response.json()
    assert fetched["id"] == created["id"]
    assert fetched["proposed_severity"] == "high"

    update_response = client.put(
        f"/incidents/{incident_id}/propose-severity",
        json={
            "proposed_severity": "critical",
            "reason": "Escalated because incident now affects production workload.",
        },
        headers={"x-api-key": "some-api-key"},
    )
    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["id"] == created["id"]
    assert updated["proposed_severity"] == "critical"
    assert (
        updated["reason"]
        == "Escalated because incident now affects production workload."
    )
    assert updated["updated_at"] is not None

    delete_response = client.delete(
        f"/incidents/{incident_id}/propose-severity",
        headers={"x-api-key": "some-api-key"},
    )
    assert delete_response.status_code == 200
    deleted = delete_response.json()
    assert deleted["id"] == created["id"]
    assert deleted["deleted"] is True

    get_after_delete = client.get(
        f"/incidents/{incident_id}/propose-severity",
        headers={"x-api-key": "some-api-key"},
    )
    assert get_after_delete.status_code == 404

    proposal = db_session.exec(select(IncidentSeverityProposal)).first()
    assert proposal is not None
    assert proposal.is_deleted is True
    assert proposal.deleted_at is not None


@pytest.mark.parametrize("test_app", ["NO_AUTH"], indirect=True)
def test_incident_severity_proposal_idempotency_key(
    db_session, client, test_app, monkeypatch
):
    monkeypatch.setattr(
        "keep.api.routes.incidents.sync_incident_severity_proposal_to_vector_store",
        lambda *args, **kwargs: None,
    )

    incident = _create_test_incident_with_alert(client)
    incident_id = incident["id"]

    idempotency_key = "incident-proposal-key-1"
    response1 = client.post(
        f"/incidents/{incident_id}/propose-severity",
        json={"proposed_severity": "warning", "reason": "Initial classification."},
        headers={"x-api-key": "some-api-key", "Idempotency-Key": idempotency_key},
    )
    assert response1.status_code == 200
    body1 = response1.json()

    response2 = client.post(
        f"/incidents/{incident_id}/propose-severity",
        json={"proposed_severity": "high", "reason": "Different payload."},
        headers={"x-api-key": "some-api-key", "Idempotency-Key": idempotency_key},
    )
    assert response2.status_code == 200
    body2 = response2.json()

    assert body1["id"] == body2["id"]
    assert body2["proposed_severity"] == "warning"
    assert body2["deduplicated"] is True
    proposals = db_session.exec(select(IncidentSeverityProposal)).all()
    assert len(proposals) == 1


@pytest.mark.parametrize("test_app", ["NO_AUTH"], indirect=True)
def test_incident_severity_proposal_invalid_incident_id(client, test_app):
    for method in ("get", "post", "put", "delete"):
        kwargs = {"headers": {"x-api-key": "some-api-key"}}
        if method in ("post", "put"):
            kwargs["json"] = {"proposed_severity": "warning", "reason": "test"}
        response = getattr(client, method)(
            "/incidents/not-a-uuid/propose-severity",
            **kwargs,
        )
        assert response.status_code == 422
