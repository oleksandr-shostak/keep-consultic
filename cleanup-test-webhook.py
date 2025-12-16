#!/usr/bin/env python3
"""
Cleanup script to remove the test webhook created by the debug script.

Usage:
    python3 cleanup-test-webhook.py <pagerduty_api_key>
"""

import sys
import requests

def cleanup_test_webhook(api_key: str):
    """Delete the test webhook created during debugging."""

    SUBSCRIPTION_API_URL = "https://api.pagerduty.com/webhook_subscriptions"

    headers = {
        "Accept": "application/vnd.pagerduty+json;version=2",
        "Content-Type": "application/json",
        "Authorization": f"Token token={api_key}",
    }

    print("Fetching all webhooks...")
    response = requests.get(SUBSCRIPTION_API_URL, headers=headers)

    if not response.ok:
        print(f"Failed to fetch webhooks: {response.text}")
        return

    webhooks = response.json().get("webhook_subscriptions", [])

    # Find test webhook
    test_webhook = None
    for webhook in webhooks:
        desc = webhook.get("description", "")
        if "DEBUG TEST" in desc:
            test_webhook = webhook
            break

    if not test_webhook:
        print("No test webhook found. Nothing to clean up.")
        return

    webhook_id = test_webhook.get("id")
    webhook_url = test_webhook.get("delivery_method", {}).get("url", "N/A")

    print(f"\nFound test webhook:")
    print(f"  ID: {webhook_id}")
    print(f"  URL: {webhook_url}")
    print(f"\nDeleting test webhook...")

    response = requests.delete(
        f"{SUBSCRIPTION_API_URL}/{webhook_id}",
        headers=headers
    )

    if response.ok:
        print("✓ Test webhook deleted successfully!")
    else:
        print(f"✗ Failed to delete webhook: {response.text}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 cleanup-test-webhook.py <pagerduty_api_key>")
        sys.exit(1)

    api_key = sys.argv[1]
    cleanup_test_webhook(api_key)
