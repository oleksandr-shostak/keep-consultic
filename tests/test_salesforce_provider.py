import datetime
import json
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from keep.api.models.db.incident import IncidentSeverity, IncidentStatus
from keep.api.models.incident import IncidentDto
from keep.contextmanager.contextmanager import ContextManager
from keep.providers.models.provider_config import ProviderConfig
from keep.providers.salesforce_provider.salesforce_provider import SalesforceProvider


def _build_response(status_code: int, payload: dict | list | None = None) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.text = json.dumps(payload) if payload is not None else ""
    response.headers = {}
    if payload is not None:
        response.json.return_value = payload
    else:
        response.json.side_effect = ValueError("No JSON body")

    if status_code >= 400:
        response.raise_for_status.side_effect = Exception("HTTP error")
    else:
        response.raise_for_status.return_value = None
    return response


def _build_incident_dto(incident_id: uuid.UUID) -> IncidentDto:
    return IncidentDto(
        id=incident_id,
        user_generated_name="Keep incident",
        user_summary="Incident summary",
        assignee=None,
        same_incident_in_the_past_id=None,
        severity=IncidentSeverity.HIGH,
        start_time=None,
        last_seen_time=None,
        end_time=None,
        creation_time=datetime.datetime.now(tz=datetime.timezone.utc),
        alerts_count=0,
        alert_sources=["keep"],
        status=IncidentStatus.FIRING,
        services=[],
        is_predicted=False,
        is_candidate=False,
        generated_summary=None,
        ai_generated_name=None,
        rule_fingerprint=None,
        fingerprint=str(incident_id),
        merged_into_incident_id=None,
        merged_by=None,
        merged_at=None,
        incident_type=None,
        incident_application=None,
        resolve_on="all",
        rule_id=None,
        rule_name=None,
        rule_is_deleted=None,
    )


@pytest.fixture
def salesforce_provider():
    context_manager = ContextManager(tenant_id="tenant-1", workflow_id="wf-1")
    config = ProviderConfig(
        authentication={
            "instance_url": "https://consultic.my.salesforce.com",
            "client_id": "client-id",
            "client_secret": "client-secret",
        }
    )
    return SalesforceProvider(context_manager, "salesforce-test", config)


@pytest.fixture
def salesforce_provider_external_disabled():
    context_manager = ContextManager(tenant_id="tenant-1", workflow_id="wf-1")
    config = ProviderConfig(
        authentication={
            "instance_url": "https://consultic.my.salesforce.com",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "allow_external_case_creation": False,
        }
    )
    return SalesforceProvider(context_manager, "salesforce-test", config)


@pytest.fixture
def salesforce_provider_external_enabled():
    context_manager = ContextManager(tenant_id="tenant-1", workflow_id="wf-1")
    config = ProviderConfig(
        authentication={
            "instance_url": "https://consultic.my.salesforce.com",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "allow_external_case_creation": True,
        }
    )
    return SalesforceProvider(context_manager, "salesforce-test", config)


@patch("keep.providers.salesforce_provider.salesforce_provider.requests.request")
def test_notify_upsert_by_keep_incident_id(mock_request, salesforce_provider):
    keep_incident_id = str(uuid.uuid4())
    case_payload = {
        "Id": "500ABCDEF123",
        "CaseNumber": "00012345",
        "Status": "Working",
        "Priority": "High",
        "Keep_Incident_Id__c": keep_incident_id,
    }
    mock_request.side_effect = [
        _build_response(204),
        _build_response(200, case_payload),
        _build_response(200, case_payload),
    ]

    result = salesforce_provider._notify(
        keep_incident_id=keep_incident_id,
        subject="Keep API outage",
        description="Incident details",
        status=IncidentStatus.ACKNOWLEDGED.value,
        priority=IncidentSeverity.HIGH.value,
        mode="upsert",
    )

    assert result["action"] == "upsert"
    assert result["created"] is False
    assert result["existing"] is True
    assert result["case"]["id"] == "500ABCDEF123"
    assert result["case"]["number"] == "00012345"
    assert result["case"]["status"] == "Working"
    assert result["case"]["priority"] == "High"

    first_call = mock_request.call_args_list[0].kwargs
    assert first_call["method"] == "PATCH"
    assert "sobjects/Case/Keep_Incident_Id__c/" in first_call["url"]
    assert first_call["headers"]["X-Client-Id"] == "client-id"
    assert first_call["headers"]["X-Client-Secret"] == "client-secret"
    assert first_call["json"]["Status"] == "Working"
    assert first_call["json"]["Priority"] == "High"
    assert "Keep_Incident_Id__c" not in first_call["json"]
    assert "Origin" not in first_call["json"]


@patch("keep.providers.salesforce_provider.salesforce_provider.requests.request")
def test_notify_upsert_duplicate_external_id_falls_back_to_get_and_update(
    mock_request, salesforce_provider
):
    keep_incident_id = str(uuid.uuid4())
    case_payload = {
        "Id": "500RACECASE01",
        "CaseNumber": "00099901",
        "Status": "Working",
        "Priority": "High",
        "Keep_Incident_Id__c": keep_incident_id,
    }
    mock_request.side_effect = [
        _build_response(
            400,
            [
                {
                    "message": "duplicate value found: Keep_Incident_Id__c duplicates value on record with id: 500RACECASE01",
                    "errorCode": "DUPLICATE_VALUE",
                }
            ],
        ),
        _build_response(200, case_payload),
        _build_response(204),
        _build_response(200, case_payload),
    ]

    result = salesforce_provider._notify(
        keep_incident_id=keep_incident_id,
        subject="Race fallback test",
        description="latest status should still be applied",
        status=IncidentStatus.ACKNOWLEDGED.value,
        priority=IncidentSeverity.HIGH.value,
        mode="upsert",
    )

    assert result["action"] == "upsert"
    assert result["created"] is False
    assert result["existing"] is True
    assert result["case"]["id"] == "500RACECASE01"

    first_call = mock_request.call_args_list[0].kwargs
    second_call = mock_request.call_args_list[1].kwargs
    third_call = mock_request.call_args_list[2].kwargs
    assert first_call["method"] == "PATCH"
    assert "sobjects/Case/Keep_Incident_Id__c/" in first_call["url"]
    assert second_call["method"] == "GET"
    assert "sobjects/Case/Keep_Incident_Id__c/" in second_call["url"]
    assert third_call["method"] == "PATCH"
    assert third_call["url"].endswith("/sobjects/Case/500RACECASE01")


@patch("keep.providers.salesforce_provider.salesforce_provider.requests.request")
def test_notify_uses_enum_values_from_incident_context(
    mock_request, salesforce_provider
):
    keep_incident_id = str(uuid.uuid4())
    salesforce_provider.context_manager.incident_context = SimpleNamespace(
        id=keep_incident_id,
        name="Keep incident enum mapping test",
        status=IncidentStatus.RESOLVED,
        severity=IncidentSeverity.CRITICAL,
    )
    case_payload = {
        "Id": "500ENUMCASE001",
        "CaseNumber": "00054321",
        "Status": "Closed",
        "Priority": "High",
        "Keep_Incident_Id__c": keep_incident_id,
    }
    mock_request.side_effect = [
        _build_response(204),
        _build_response(200, case_payload),
        _build_response(200, case_payload),
    ]

    result = salesforce_provider._notify(mode="upsert")

    assert result["case"]["id"] == "500ENUMCASE001"
    first_call_payload = mock_request.call_args_list[0].kwargs["json"]
    assert first_call_payload["Status"] == "Closed"
    assert first_call_payload["Priority"] == "High"


@patch("keep.providers.salesforce_provider.salesforce_provider.requests.request")
def test_notify_create_mode_creates_case(mock_request, salesforce_provider):
    case_payload = {
        "Id": "500CREATE001",
        "CaseNumber": "00077777",
        "Status": "New",
        "Priority": "High",
    }
    mock_request.side_effect = [
        _build_response(201, {"id": "500CREATE001"}),
        _build_response(200, case_payload),
    ]

    result = salesforce_provider._notify(
        mode="create",
        subject="Created from Keep",
        description="create mode",
        status=IncidentStatus.FIRING.value,
        priority=IncidentSeverity.CRITICAL.value,
    )

    assert result["created"] is True
    assert result["existing"] is False
    assert result["case"]["id"] == "500CREATE001"
    first_call = mock_request.call_args_list[0].kwargs
    assert first_call["method"] == "POST"
    assert first_call["url"].endswith("/sobjects/Case")
    assert first_call["json"]["Origin"] == "Keep"


@patch("keep.providers.salesforce_provider.salesforce_provider.requests.request")
def test_notify_update_mode_updates_case(mock_request, salesforce_provider):
    case_payload = {
        "Id": "500UPDATE001",
        "CaseNumber": "00088888",
        "Status": "Closed",
        "Priority": "Medium",
    }
    mock_request.side_effect = [
        _build_response(204),
        _build_response(200, case_payload),
    ]

    result = salesforce_provider._notify(
        mode="update",
        case_id="500UPDATE001",
        status=IncidentStatus.RESOLVED.value,
        priority=IncidentSeverity.WARNING.value,
    )

    assert result["created"] is False
    assert result["existing"] is True
    assert result["case"]["id"] == "500UPDATE001"
    first_call = mock_request.call_args_list[0].kwargs
    assert first_call["method"] == "PATCH"
    assert first_call["url"].endswith("/sobjects/Case/500UPDATE001")


@patch("keep.providers.salesforce_provider.salesforce_provider.requests.request")
def test_query_default_linked_cases(mock_request, salesforce_provider):
    mock_request.return_value = _build_response(
        200,
        {
            "records": [
                {
                    "Id": "500CASE001",
                    "CaseNumber": "00000001",
                    "Status": "New",
                    "Priority": "Low",
                    "Keep_Incident_Id__c": str(uuid.uuid4()),
                }
            ],
            "totalSize": 1,
            "done": True,
        },
    )

    result = salesforce_provider._query(limit=1, fields=["Id", "Status", "Priority"])

    assert result["total_size"] == 1
    assert result["done"] is True
    assert len(result["cases"]) == 1
    assert result["cases"][0]["id"] == "500CASE001"
    assert result["cases"][0]["status"] == "New"
    assert result["cases"][0]["priority"] == "Low"

    first_call = mock_request.call_args.kwargs
    assert first_call["method"] == "GET"
    assert first_call["url"].endswith("/query")
    assert "Keep_Incident_Id__c != null" in first_call["params"]["q"]
    assert "LIMIT 1" in first_call["params"]["q"]


def test_format_incident_external_case_creation(salesforce_provider_external_enabled):
    event = {
        "event_type": "case.updated",
        "occurred_at": "2026-02-18T09:00:00Z",
        "case": {
            "Id": "500EXTERNALCASE01",
            "CaseNumber": "00065432",
            "Subject": "External customer escalation",
            "Description": "Customer reported outage",
            "Status": "Closed",
            "Priority": "High",
            "CreatedDate": "2026-02-18T08:30:00Z",
            "LastModifiedDate": "2026-02-18T08:59:58Z",
        },
        "actor": {"Email": "agent@example.com", "Name": "Agent One"},
    }

    formatted = SalesforceProvider._format_incident(
        event, salesforce_provider_external_enabled
    )

    assert isinstance(formatted, IncidentDto)
    assert formatted.status == IncidentStatus.RESOLVED
    assert formatted.severity == IncidentSeverity.HIGH
    assert formatted.fingerprint == "500EXTERNALCASE01"
    assert formatted.status_source == "salesforce"
    assert formatted.status_changed_by == "agent@example.com"
    assert formatted._tenant_id == "tenant-1"


def test_format_incident_acknowledged_status_mapping(
    salesforce_provider_external_enabled,
):
    event = {
        "event_type": "case.updated",
        "occurred_at": "2026-02-18T09:00:00Z",
        "case": {
            "Id": "500ACKCASE01",
            "CaseNumber": "00065433",
            "Subject": "External customer escalation",
            "Status": "acknowledged",
            "Priority": "High",
        },
    }

    formatted = SalesforceProvider._format_incident(
        event, salesforce_provider_external_enabled
    )

    assert isinstance(formatted, IncidentDto)
    assert formatted.status == IncidentStatus.ACKNOWLEDGED


def test_format_incident_skips_external_creation_when_disabled(
    salesforce_provider_external_disabled,
):
    event = {
        "case": {
            "Id": "500NOEXTERNAL01",
            "Status": "New",
            "Priority": "Low",
            "Subject": "Do not import",
        }
    }

    formatted = SalesforceProvider._format_incident(
        event, salesforce_provider_external_disabled
    )
    assert formatted == []


def test_format_incident_skips_external_creation_by_default(salesforce_provider):
    event = {
        "case": {
            "Id": "500DEFAULTNOEXT01",
            "Status": "New",
            "Priority": "Low",
            "Subject": "Do not import by default",
        }
    }

    formatted = SalesforceProvider._format_incident(event, salesforce_provider)
    assert formatted == []


def test_format_incident_skips_linked_case_when_status_unchanged(salesforce_provider):
    keep_incident_id = str(uuid.uuid4())
    event = {
        "occurred_at": "2026-02-18T09:00:00Z",
        "case": {
            "Id": "500SAMESTATUS01",
            "Status": "Closed",
            "Priority": "High",
            "KeepIncidentId": keep_incident_id,
        },
    }

    with patch("keep.api.core.db.get_incident_by_id") as mock_get_incident:
        mock_get_incident.return_value = SimpleNamespace(status="resolved")
        formatted = SalesforceProvider._format_incident(event, salesforce_provider)
        mock_get_incident.assert_called_once()

    assert formatted == []


def test_format_incident_skips_when_actor_matches_sync_metadata(salesforce_provider):
    keep_incident_id = str(uuid.uuid4())
    event = {
        "occurred_at": "2026-02-18T09:00:00Z",
        "case": {
            "Id": "500SYNCLOOP01",
            "Status": "Working",
            "Priority": "High",
            "KeepIncidentId": keep_incident_id,
        },
        "actor": {
            "Email": "keep-salesforce-sync@example.com",
            "Name": "Keep Salesforce Sync",
        },
    }
    keep_incident = SimpleNamespace(
        status="firing",
        enrichments={"sf_sync_actor": "keep-salesforce-sync@example.com"},
    )

    with patch("keep.api.core.db.get_incident_by_id") as mock_get_incident:
        mock_get_incident.return_value = keep_incident
        formatted = SalesforceProvider._format_incident(event, salesforce_provider)
        mock_get_incident.assert_called_once()

    assert formatted == []


def test_format_incident_skips_stale_event_based_on_sync_timestamp(salesforce_provider):
    keep_incident_id = str(uuid.uuid4())
    event = {
        "occurred_at": "2026-02-18T09:00:00Z",
        "case": {
            "Id": "500STALEEVENT01",
            "Status": "Working",
            "Priority": "High",
            "KeepIncidentId": keep_incident_id,
        },
    }
    keep_incident = SimpleNamespace(
        status="firing",
        enrichments={"sf_last_sync_at": "2026-02-18T09:30:00Z"},
    )

    with patch("keep.api.core.db.get_incident_by_id") as mock_get_incident:
        mock_get_incident.return_value = keep_incident
        formatted = SalesforceProvider._format_incident(event, salesforce_provider)
        mock_get_incident.assert_called_once()

    assert formatted == []


def test_format_incident_skips_stale_external_event_without_linked_keep_incident(
    salesforce_provider_external_enabled,
):
    event = {
        "occurred_at": "2026-02-18T09:00:00Z",
        "case": {
            "Id": "500EXTERNALSTALE01",
            "Status": "firing",
            "Priority": "High",
            "Subject": "External stale test",
        },
    }
    keep_incident = SimpleNamespace(
        status="resolved",
        last_seen_time=datetime.datetime(2026, 2, 18, 9, 30, tzinfo=datetime.timezone.utc),
        creation_time=datetime.datetime(2026, 2, 18, 9, 0, tzinfo=datetime.timezone.utc),
    )

    with patch("keep.api.core.db.get_incident_by_id") as mock_get_incident:
        mock_get_incident.return_value = keep_incident
        formatted = SalesforceProvider._format_incident(
            event, salesforce_provider_external_enabled
        )
        mock_get_incident.assert_called_once()

    assert formatted == []


def test_format_incident_ignores_non_case_payload_with_only_event_id(salesforce_provider):
    event = {"Id": "evt-123", "event_type": "case.updated"}
    formatted = SalesforceProvider._format_incident(event, salesforce_provider)
    assert formatted == []


def test_setup_incident_webhook_manual_returns_none(salesforce_provider):
    result = salesforce_provider.setup_incident_webhook(
        tenant_id="tenant-1",
        keep_api_url="https://api.keep.example/incidents/event/salesforce?provider_id=salesforce-test",
        api_key="webhook-key",
        setup_alerts=True,
    )
    assert result is None


@patch("keep.providers.salesforce_provider.salesforce_provider.requests.request")
def test_setup_incident_webhook_auto_setup(mock_request):
    context_manager = ContextManager(tenant_id="tenant-1", workflow_id="wf-1")
    config = ProviderConfig(
        authentication={
            "instance_url": "https://consultic.my.salesforce.com",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "webhook_setup_url": "https://consultic.my.salesforce.com/setup/webhook",
        }
    )
    provider = SalesforceProvider(context_manager, "salesforce-test", config)
    mock_request.return_value = _build_response(200, {"ok": True})

    result = provider.setup_incident_webhook(
        tenant_id="tenant-1",
        keep_api_url="https://api.keep.example/incidents/event/salesforce?provider_id=salesforce-test",
        api_key="webhook-key",
        setup_alerts=True,
    )

    assert result is None
    first_call = mock_request.call_args.kwargs
    assert first_call["method"] == "POST"
    assert first_call["url"] == "https://consultic.my.salesforce.com/setup/webhook"
    assert first_call["json"]["keep_webhook_api_key"] == "webhook-key"
    assert first_call["json"]["provider_id"] == "salesforce-test"


@patch("keep.providers.salesforce_provider.salesforce_provider.requests.request")
def test_validate_scopes_success(mock_request, salesforce_provider):
    mock_request.side_effect = [
        _build_response(
            200,
            {
                "records": [{"Id": "500SCOPE001"}],
                "totalSize": 1,
                "done": True,
            },
        ),
        _build_response(200, {"name": "Case"}),
    ]

    scopes = salesforce_provider.validate_scopes()

    assert scopes["case_read"] is True
    assert scopes["case_write"] is True


def test_get_incidents_returns_only_status_changes(salesforce_provider):
    changed_incident_id = uuid.uuid4()
    unchanged_incident_id = uuid.uuid4()
    raw_cases = [
        {
            "Id": "500CASE-CHANGED",
            "Status": "Working",
            "Priority": "High",
            "Keep_Incident_Id__c": str(changed_incident_id),
            "LastModifiedDate": "2026-02-18T10:00:00Z",
        },
        {
            "Id": "500CASE-UNCHANGED",
            "Status": "Closed",
            "Priority": "Low",
            "Keep_Incident_Id__c": str(unchanged_incident_id),
            "LastModifiedDate": "2026-02-18T10:05:00Z",
        },
    ]

    changed_incident = SimpleNamespace(id=changed_incident_id, status="firing")
    unchanged_incident = SimpleNamespace(id=unchanged_incident_id, status="resolved")

    with patch.object(
        salesforce_provider, "_get_linked_cases_raw", return_value=raw_cases
    ), patch("keep.api.core.db.get_incident_by_id") as mock_get_incident, patch.object(
        IncidentDto, "from_db_incident"
    ) as mock_from_db_incident:
        mock_get_incident.side_effect = [changed_incident, unchanged_incident]
        mock_from_db_incident.side_effect = [
            _build_incident_dto(changed_incident_id),
            _build_incident_dto(unchanged_incident_id),
        ]

        incidents = salesforce_provider._get_incidents()

    assert len(incidents) == 1
    assert incidents[0].status == IncidentStatus.ACKNOWLEDGED
    assert incidents[0].status_source == "salesforce"
    assert isinstance(incidents[0].status_changed_at, datetime.datetime)


@patch("keep.providers.salesforce_provider.salesforce_provider.requests.request")
def test_request_uses_oauth_client_credentials_bearer_header(mock_request):
    context_manager = ContextManager(tenant_id="tenant-1", workflow_id="wf-1")
    config = ProviderConfig(
        authentication={
            "instance_url": "https://consultic.my.salesforce.com",
            "client_id": "oauth-client-id",
            "client_secret": "oauth-client-secret",
            "use_oauth_client_credentials": True,
            "oauth_token_url": "https://login.salesforce.com/services/oauth2/token",
        }
    )
    provider = SalesforceProvider(context_manager, "salesforce-test", config)

    mock_request.side_effect = [
        _build_response(200, {"access_token": "token-123", "expires_in": 1200}),
        _build_response(200, {"records": [], "totalSize": 0, "done": True}),
    ]

    result = provider._query(limit=1)
    assert result["total_size"] == 0

    token_call = mock_request.call_args_list[0].kwargs
    assert token_call["method"] == "POST"
    assert token_call["url"] == "https://login.salesforce.com/services/oauth2/token"
    assert token_call["data"]["grant_type"] == "client_credentials"
    assert token_call["data"]["client_id"] == "oauth-client-id"
    assert token_call["data"]["client_secret"] == "oauth-client-secret"

    api_call = mock_request.call_args_list[1].kwargs
    assert api_call["headers"]["Authorization"] == "Bearer token-123"


@patch("keep.providers.salesforce_provider.salesforce_provider.requests.request")
def test_request_refreshes_oauth_token_on_401(mock_request):
    context_manager = ContextManager(tenant_id="tenant-1", workflow_id="wf-1")
    config = ProviderConfig(
        authentication={
            "instance_url": "https://consultic.my.salesforce.com",
            "client_id": "oauth-client-id",
            "client_secret": "oauth-client-secret",
            "use_oauth_client_credentials": True,
            "oauth_token_url": "https://login.salesforce.com/services/oauth2/token",
        }
    )
    provider = SalesforceProvider(context_manager, "salesforce-test", config)

    mock_request.side_effect = [
        _build_response(200, {"access_token": "token-old", "expires_in": 1200}),
        _build_response(401, [{"message": "Session expired", "errorCode": "INVALID_SESSION_ID"}]),
        _build_response(200, {"access_token": "token-new", "expires_in": 1200}),
        _build_response(200, {"records": [], "totalSize": 0, "done": True}),
    ]

    result = provider._query(limit=1)
    assert result["total_size"] == 0
    assert mock_request.call_count == 4

    first_api_call = mock_request.call_args_list[1].kwargs
    second_api_call = mock_request.call_args_list[3].kwargs
    assert first_api_call["headers"]["Authorization"] == "Bearer token-old"
    assert second_api_call["headers"]["Authorization"] == "Bearer token-new"
