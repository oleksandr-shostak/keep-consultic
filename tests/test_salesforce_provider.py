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
    if payload is not None:
        response.json.return_value = payload
    else:
        response.json.side_effect = ValueError("No JSON body")

    if status_code >= 400:
        response.raise_for_status.side_effect = Exception("HTTP error")
    else:
        response.raise_for_status.return_value = None
    return response


@pytest.fixture
def salesforce_provider():
    context_manager = ContextManager(tenant_id="tenant-1", workflow_id="wf-1")
    context_manager.api_url = "https://api.keep.example"
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
    assert first_call["json"]["Keep_Incident_Id__c"] == keep_incident_id


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


def test_format_incident_external_case_creation(salesforce_provider):
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

    formatted = SalesforceProvider._format_incident(event, salesforce_provider)

    assert isinstance(formatted, IncidentDto)
    assert formatted.status == IncidentStatus.RESOLVED
    assert formatted.severity == IncidentSeverity.HIGH
    assert formatted.fingerprint == "500EXTERNALCASE01"
    assert formatted.status_source == "salesforce"
    assert formatted.status_changed_by == "agent@example.com"


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

    assert formatted == []


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

    dto_template = SimpleNamespace(
        status=IncidentStatus.FIRING,
        _alerts=[],
        status_source=None,
        status_changed_at=None,
        end_time=None,
    )

    with patch.object(
        salesforce_provider, "_get_linked_cases_raw", return_value=raw_cases
    ), patch("keep.api.core.db.get_incident_by_id") as mock_get_incident, patch.object(
        IncidentDto, "from_db_incident"
    ) as mock_from_db_incident:
        mock_get_incident.side_effect = [changed_incident, unchanged_incident]
        mock_from_db_incident.side_effect = [
            SimpleNamespace(**dto_template.__dict__),
            SimpleNamespace(**dto_template.__dict__),
        ]

        incidents = salesforce_provider._get_incidents()

    assert len(incidents) == 1
    assert incidents[0].status == IncidentStatus.ACKNOWLEDGED
    assert incidents[0].status_source == "salesforce"
    assert isinstance(incidents[0].status_changed_at, datetime.datetime)
