#!/usr/bin/env python3
"""
Debug script for PagerDuty webhook creation issues.
Run this on your server to see the exact error from PagerDuty.

Usage:
    python3 debug-pagerduty-webhook.py <pagerduty_api_key>
"""

import sys
import json
import requests

def test_pagerduty_webhook(api_key: str):
    """Test PagerDuty webhook creation with detailed error reporting."""

    SUBSCRIPTION_API_URL = "https://api.pagerduty.com/webhook_subscriptions"

    # Test webhook URL - replace with your actual Keep instance
    keep_webhook_url = "https://api.keep-zpz9.consultic.tech/incidents/event/pagerduty?provider_id=test-debug"
    keep_api_key = "test-api-key-for-debugging"

    headers = {
        "Accept": "application/vnd.pagerduty+json;version=2",
        "Content-Type": "application/json",
        "Authorization": f"Token token={api_key}",
    }

    print("=" * 80)
    print("PagerDuty Webhook Creation Debug Script")
    print("=" * 80)
    print()

    # Step 1: Test API key by getting existing webhooks
    print("Step 1: Testing API key by fetching existing webhooks...")
    try:
        response = requests.get(SUBSCRIPTION_API_URL, headers=headers)
        print(f"  Status Code: {response.status_code}")

        if response.ok:
            data = response.json()
            webhook_count = len(data.get("webhook_subscriptions", []))
            print(f"  ✓ Success! Found {webhook_count} existing webhook(s)")

            # List existing webhooks
            if webhook_count > 0:
                print("\n  Existing webhooks:")
                for webhook in data.get("webhook_subscriptions", []):
                    url = webhook.get("delivery_method", {}).get("url", "N/A")
                    desc = webhook.get("description", "N/A")
                    print(f"    - {desc}")
                    print(f"      URL: {url}")
        else:
            print(f"  ✗ Failed to fetch webhooks")
            print(f"  Response: {response.text}")
            return
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return

    print()

    # Step 2: Try to create a test webhook
    print("Step 2: Attempting to create test webhook...")
    print(f"  Target URL: {keep_webhook_url}")

    webhook_payload = {
        "webhook_subscription": {
            "type": "webhook_subscription",
            "delivery_method": {
                "type": "http_delivery_method",
                "url": keep_webhook_url,
                "custom_headers": [{"name": "X-API-KEY", "value": keep_api_key}],
            },
            "description": "Keep PagerDuty webhook (DEBUG TEST) - safe to delete",
            "events": [
                "incident.triggered",
                "incident.acknowledged",
                "incident.resolved",
            ],
            "filter": {"type": "account_reference"},
        },
    }

    try:
        response = requests.post(
            SUBSCRIPTION_API_URL,
            headers=headers,
            json=webhook_payload,
        )

        print(f"  Status Code: {response.status_code}")

        if response.ok:
            webhook_data = response.json()
            webhook_id = webhook_data.get("webhook_subscription", {}).get("id")
            print(f"  ✓ Success! Webhook created with ID: {webhook_id}")
            print()
            print("  NOTE: This is a test webhook. You can delete it from PagerDuty UI or keep it.")
            print(f"  Webhook ID: {webhook_id}")
        else:
            print(f"  ✗ Failed to create webhook")
            print()
            print("  Error Response:")
            try:
                error_data = response.json()
                print(json.dumps(error_data, indent=2))

                # Parse common errors
                error_message = error_data.get("error", {}).get("message", "")
                errors = error_data.get("error", {}).get("errors", [])

                if error_message:
                    print()
                    print(f"  Error Message: {error_message}")

                if errors:
                    print()
                    print("  Detailed Errors:")
                    for error in errors:
                        print(f"    - {error}")

            except:
                print(response.text)
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()

    print()
    print("=" * 80)
    print("Debug complete")
    print("=" * 80)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 debug-pagerduty-webhook.py <pagerduty_api_key>")
        print()
        print("Get your PagerDuty API key from:")
        print("  1. Go to your PagerDuty account")
        print("  2. Navigate to Integrations > API Access Keys")
        print("  3. Copy your API key (or create a new one)")
        sys.exit(1)

    api_key = sys.argv[1]
    test_pagerduty_webhook(api_key)
