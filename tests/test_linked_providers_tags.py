import datetime
from unittest.mock import patch

from keep.api.models.provider import Provider
from keep.providers.providers_factory import ProvidersFactory


def test_linked_providers_always_include_alert_tag():
    linked_provider_rows = [
        ("salesforce", "salesforce-linked-1", datetime.datetime(2025, 1, 1, 0, 0, 0)),
        ("jira", "jira-linked-1", datetime.datetime(2025, 1, 1, 0, 0, 0)),
    ]
    available_providers = [
        Provider(
            display_name="Salesforce",
            type="salesforce",
            can_notify=False,
            can_query=False,
            tags=[],
        ),
        Provider(
            display_name="Jira",
            type="jira",
            can_notify=False,
            can_query=False,
            tags=["ticketing"],
        ),
    ]

    with patch(
        "keep.providers.providers_factory.get_linked_providers",
        return_value=linked_provider_rows,
    ), patch.object(
        ProvidersFactory, "get_all_providers", return_value=available_providers
    ):
        linked = ProvidersFactory.get_linked_providers("tenant-1")

    assert len(linked) == 2
    salesforce = next(p for p in linked if p.type == "salesforce")
    jira = next(p for p in linked if p.type == "jira")

    assert salesforce.linked is True
    assert salesforce.id == "salesforce-linked-1"
    assert "alert" in salesforce.tags

    assert jira.linked is True
    assert jira.id == "jira-linked-1"
    assert jira.tags == ["ticketing", "alert"]

    # Ensure we didn't mutate cached/static provider definitions.
    assert available_providers[0].tags == []
    assert available_providers[1].tags == ["ticketing"]
