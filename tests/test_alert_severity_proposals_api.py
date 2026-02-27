import time

import pytest
from sqlmodel import select

from keep.api.models.db.alert_severity_proposal import AlertSeverityProposal
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


@pytest.mark.parametrize("test_app", ["NO_AUTH"], indirect=True)
def test_create_get_update_delete_alert_severity_proposal(
    db_session, client, test_app, monkeypatch
):
    monkeypatch.setattr(
        "keep.api.routes.alerts.sync_alert_severity_proposal_to_vector_store",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "keep.api.routes.alerts.delete_alert_severity_proposal_from_vector_store",
        lambda *args, **kwargs: None,
    )

    alert = _create_test_alert(client)
    event_id = alert["event_id"]

    create_response = client.post(
        f"/alerts/event/{event_id}/propose-severity",
        json={
            "proposed_severity": "info",
            "reason": "The user triage indicates this is informational only.",
        },
        headers={"x-api-key": "some-api-key"},
    )
    assert create_response.status_code == 200
    created = create_response.json()
    assert created["proposed_severity"] == "info"
    assert created["reason"] == "The user triage indicates this is informational only."
    assert created["deduplicated"] is False

    dedupe_response = client.post(
        f"/alerts/event/{event_id}/propose-severity",
        json={
            "proposed_severity": "info",
            "reason": "The user triage indicates this is informational only.",
        },
        headers={"x-api-key": "some-api-key"},
    )
    assert dedupe_response.status_code == 200
    dedupe_body = dedupe_response.json()
    assert dedupe_body["id"] == created["id"]
    assert dedupe_body["deduplicated"] is True

    get_response = client.get(
        f"/alerts/event/{event_id}/propose-severity",
        headers={"x-api-key": "some-api-key"},
    )
    assert get_response.status_code == 200
    fetched = get_response.json()
    assert fetched["id"] == created["id"]
    assert fetched["proposed_severity"] == "info"

    update_response = client.put(
        f"/alerts/event/{event_id}/propose-severity",
        json={
            "proposed_severity": "critical",
            "reason": "Impact has increased, escalate to critical.",
        },
        headers={"x-api-key": "some-api-key"},
    )
    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["id"] == created["id"]
    assert updated["proposed_severity"] == "critical"
    assert updated["reason"] == "Impact has increased, escalate to critical."
    assert updated["updated_at"] is not None

    delete_response = client.delete(
        f"/alerts/event/{event_id}/propose-severity",
        headers={"x-api-key": "some-api-key"},
    )
    assert delete_response.status_code == 200
    deleted = delete_response.json()
    assert deleted["id"] == created["id"]
    assert deleted["deleted"] is True

    get_after_delete = client.get(
        f"/alerts/event/{event_id}/propose-severity",
        headers={"x-api-key": "some-api-key"},
    )
    assert get_after_delete.status_code == 404

    proposal = db_session.exec(select(AlertSeverityProposal)).first()
    assert proposal is not None
    assert proposal.is_deleted is True
    assert proposal.deleted_at is not None


@pytest.mark.parametrize("test_app", ["NO_AUTH"], indirect=True)
def test_alert_severity_proposal_idempotency_key(db_session, client, test_app, monkeypatch):
    monkeypatch.setattr(
        "keep.api.routes.alerts.sync_alert_severity_proposal_to_vector_store",
        lambda *args, **kwargs: None,
    )

    alert = _create_test_alert(client)
    event_id = alert["event_id"]

    idempotency_key = "proposal-key-1"
    response1 = client.post(
        f"/alerts/event/{event_id}/propose-severity",
        json={"proposed_severity": "info", "reason": "Informational pattern."},
        headers={"x-api-key": "some-api-key", "Idempotency-Key": idempotency_key},
    )
    assert response1.status_code == 200
    body1 = response1.json()

    response2 = client.post(
        f"/alerts/event/{event_id}/propose-severity",
        json={"proposed_severity": "high", "reason": "Different payload."},
        headers={"x-api-key": "some-api-key", "Idempotency-Key": idempotency_key},
    )
    assert response2.status_code == 200
    body2 = response2.json()

    assert body1["id"] == body2["id"]
    assert body2["proposed_severity"] == "info"
    assert body2["deduplicated"] is True
    proposals = db_session.exec(select(AlertSeverityProposal)).all()
    assert len(proposals) == 1


@pytest.mark.parametrize("test_app", ["NO_AUTH"], indirect=True)
def test_alert_severity_proposal_invalid_event_id(client, test_app):
    for method in ("get", "post", "put", "delete"):
        kwargs = {
            "headers": {"x-api-key": "some-api-key"},
        }
        if method in ("post", "put"):
            kwargs["json"] = {"proposed_severity": "warning", "reason": "test"}

        response = getattr(client, method)(
            "/alerts/event/not-a-uuid/propose-severity",
            **kwargs,
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid alert event id"
