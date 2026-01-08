"""
SigNoz Provider - receives alerts via webhook from SigNoz.
"""

import dataclasses
import datetime
import json
import logging

import pydantic
import requests

from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus
from keep.contextmanager.contextmanager import ContextManager
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig, ProviderScope

logger = logging.getLogger(__name__)


@pydantic.dataclasses.dataclass
class SignozProviderAuthConfig:
    """
    SigNoz authentication configuration.

    All fields are optional - the provider can work as a webhook-only receiver
    without connecting to SigNoz. Just configure the webhook manually in SigNoz
    to send alerts to Keep's webhook endpoint.
    """

    host: str | None = dataclasses.field(
        default=None,
        metadata={
            "required": False,
            "description": "SigNoz host URL (optional - only needed for automatic webhook setup)",
            "hint": "e.g. https://signoz.example.com",
            "validation": "any_http_url",
        },
    )
    api_key: str | None = dataclasses.field(
        default=None,
        metadata={
            "required": False,
            "description": "SigNoz API Key (optional - only needed for automatic webhook setup)",
            "hint": "Your SIGNOZ-API-KEY for authentication",
            "sensitive": True,
        },
    )


class SignozProvider(BaseProvider):
    """
    SigNoz provider for receiving alerts via webhook.
    """

    PROVIDER_DISPLAY_NAME = "SigNoz"
    PROVIDER_CATEGORY = ["Monitoring", "Observability"]
    PROVIDER_TAGS = ["alert"]
    FINGERPRINT_FIELDS = ["fingerprint"]

    PROVIDER_SCOPES = [
        ProviderScope(
            name="alerts:read",
            description="Optional - only needed if connecting to SigNoz API",
            mandatory=False,
            mandatory_for_webhook=False,
        ),
        ProviderScope(
            name="channels:write",
            description="Optional - only needed for automatic webhook setup in SigNoz",
            mandatory=False,
            mandatory_for_webhook=True,
        ),
    ]

    SEVERITIES_MAP = {
        "critical": AlertSeverity.CRITICAL,
        "error": AlertSeverity.HIGH,
        "high": AlertSeverity.HIGH,
        "warning": AlertSeverity.WARNING,
        "info": AlertSeverity.INFO,
        "low": AlertSeverity.LOW,
    }

    STATUS_MAP = {
        "firing": AlertStatus.FIRING,
        "resolved": AlertStatus.RESOLVED,
    }

    # Webhook setup instructions for manual configuration
    webhook_description = "Receive alerts from SigNoz"
    webhook_template = ""
    webhook_markdown = """
To manually configure SigNoz to send alerts to Keep:

1. In SigNoz, go to **Settings** > **Alert Channels**
2. Click **New Channel** and select **Webhook**
3. Configure the webhook:
   - **Name**: Keep Integration
   - **Webhook URL**: `{keep_webhook_api_url}`
   - **Username**: (leave empty)
   - **Password**: `{api_key}`
4. Click **Test** to verify the connection
5. Click **Save**

Alternatively, use the automatic setup by clicking "Connect" with your SigNoz API key.
"""

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)

    def dispose(self):
        """Dispose the provider."""
        pass

    def validate_config(self):
        """Validates required configuration for SigNoz provider.

        No fields are required - the provider can work as a webhook-only receiver.
        """
        if self.config.authentication is None:
            self.config.authentication = {}
        self.authentication_config = SignozProviderAuthConfig(
            **self.config.authentication
        )

    def validate_scopes(self) -> dict[str, bool | str]:
        """Validate that the API key has required permissions.

        If no host/api_key is configured, skip validation - the provider
        will work as a webhook-only receiver.
        """
        validated_scopes = {}

        # If no auth configured, skip validation - webhook-only mode
        if not self.authentication_config.host or not self.authentication_config.api_key:
            logger.info("SigNoz provider configured in webhook-only mode (no host/api_key)")
            # Return scopes as skipped since we're in webhook-only mode
            validated_scopes["alerts:read"] = "Skipped (webhook-only mode)"
            validated_scopes["channels:write"] = "Skipped (webhook-only mode)"
            return validated_scopes

        headers = {"SIGNOZ-API-KEY": self.authentication_config.api_key}
        host = str(self.authentication_config.host).rstrip("/")

        # Check alerts:read scope by trying to list alert rules
        try:
            response = requests.get(
                f"{host}/api/v1/rules",
                headers=headers,
                timeout=10,
            )
            if response.status_code == 200:
                validated_scopes["alerts:read"] = True
            elif response.status_code == 401:
                validated_scopes["alerts:read"] = "Invalid API key"
            elif response.status_code == 403:
                validated_scopes["alerts:read"] = "API key lacks permission"
            else:
                validated_scopes["alerts:read"] = f"Failed: HTTP {response.status_code}"
        except requests.exceptions.ConnectionError:
            validated_scopes["alerts:read"] = "Failed to connect to SigNoz"
        except Exception as e:
            validated_scopes["alerts:read"] = f"Error: {str(e)}"

        # Check channels:write scope by trying to list channels
        try:
            response = requests.get(
                f"{host}/api/v1/channels",
                headers=headers,
                timeout=10,
            )
            if response.status_code == 200:
                validated_scopes["channels:write"] = True
            elif response.status_code == 401:
                validated_scopes["channels:write"] = "Invalid API key"
            elif response.status_code == 403:
                validated_scopes["channels:write"] = "API key lacks permission"
            else:
                validated_scopes["channels:write"] = f"Failed: HTTP {response.status_code}"
        except requests.exceptions.ConnectionError:
            validated_scopes["channels:write"] = "Failed to connect to SigNoz"
        except Exception as e:
            validated_scopes["channels:write"] = f"Error: {str(e)}"

        return validated_scopes

    def setup_webhook(
        self, tenant_id: str, keep_api_url: str, api_key: str, setup_alerts: bool = True
    ):
        """
        Setup a webhook channel in SigNoz to send alerts to Keep.

        SigNoz uses the Alertmanager API format for channels:
        https://signoz.io/docs/alerts-management/notification-channel/webhook/

        If no host/api_key is configured, this method will skip setup and
        the user should configure the webhook manually in SigNoz.
        """
        # Skip webhook setup if no auth configured (webhook-only mode)
        if not self.authentication_config.host or not self.authentication_config.api_key:
            self.logger.info(
                "Skipping automatic webhook setup - no SigNoz host/api_key configured. "
                "Please configure the webhook manually in SigNoz."
            )
            return

        self.logger.info("Setting up SigNoz webhook")

        headers = {
            "SIGNOZ-API-KEY": self.authentication_config.api_key,
            "Content-Type": "application/json",
        }
        host = str(self.authentication_config.host).rstrip("/")
        webhook_name = f"keep-{tenant_id}"

        # SigNoz webhook payload format (Alertmanager style)
        # Keep expects X-API-KEY header, but SigNoz/Alertmanager doesn't support custom headers.
        # Nginx maps ?api_key=... query param to X-API-KEY header, so we append the key to URL.
        url_separator = "&" if "?" in keep_api_url else "?"
        webhook_url = f"{keep_api_url}{url_separator}api_key={api_key}"

        webhook_payload = {
            "name": webhook_name,
            "webhook_configs": [
                {
                    "send_resolved": True,
                    "url": webhook_url,
                    "http_config": {
                        "tls_config": {
                            "insecure_skip_verify": False,
                        },
                        "follow_redirects": True,
                        "enable_http2": True,
                    },
                    "max_alerts": 0,
                    "timeout": 0,
                }
            ],
        }

        # Check if webhook already exists
        try:
            response = requests.get(
                f"{host}/api/v1/channels",
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()
            existing_channels = response.json()

            # Handle both list and dict response formats
            if isinstance(existing_channels, dict):
                channels_list = existing_channels.get("data", [])
            else:
                channels_list = existing_channels

            existing_webhook = None
            for channel in channels_list:
                if channel.get("name") == webhook_name:
                    existing_webhook = channel
                    break

            if existing_webhook:
                self.logger.info(f"Webhook '{webhook_name}' already exists, updating...")
                channel_id = existing_webhook.get("id")

                response = requests.put(
                    f"{host}/api/v1/channels/{channel_id}",
                    headers=headers,
                    json=webhook_payload,
                    timeout=10,
                )
                response.raise_for_status()
                self.logger.info(f"Updated webhook '{webhook_name}'")
            else:
                # Create new webhook
                self.logger.info(f"Creating new webhook '{webhook_name}'")

                response = requests.post(
                    f"{host}/api/v1/channels",
                    headers=headers,
                    json=webhook_payload,
                    timeout=10,
                )
                # SigNoz returns empty body on success (200/201)
                if response.status_code in (200, 201):
                    self.logger.info(f"Created webhook '{webhook_name}'")
                elif response.text:
                    # Check for name conflict error
                    try:
                        result = response.json()
                        if "alertmanager_config_conflict" in str(result):
                            self.logger.warning(
                                f"Webhook name '{webhook_name}' already exists in Alertmanager config"
                            )
                        else:
                            response.raise_for_status()
                    except ValueError:
                        response.raise_for_status()
                else:
                    response.raise_for_status()

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to setup webhook: {str(e)}")
            raise Exception(f"Failed to setup SigNoz webhook: {str(e)}")

        self.logger.info("SigNoz webhook setup completed")

    @staticmethod
    def _format_alert(
        event: dict, provider_instance: "BaseProvider" = None
    ) -> list[AlertDto]:
        """
        Format a SigNoz webhook event (Alertmanager format) into Keep AlertDto.

        SigNoz sends alerts in Prometheus Alertmanager webhook format:
        {
            "receiver": "channel-name",
            "status": "firing|resolved",
            "alerts": [...],
            "groupLabels": {...},
            "commonLabels": {...},
            "commonAnnotations": {...},
            "externalURL": "https://signoz.example.com"
        }
        """
        alerts = event.get("alerts", [])

        if not alerts:
            logger.warning("No alerts found in SigNoz webhook payload")
            return []

        logger.info(f"Formatting {len(alerts)} SigNoz alerts")

        formatted_alerts = []
        external_url = event.get("externalURL", "")

        for alert in alerts:
            try:
                labels = alert.get("labels", {})
                annotations = alert.get("annotations", {})

                # Extract alert name
                name = labels.get("alertname", "SigNoz Alert")

                # Map status
                status_str = alert.get("status", event.get("status", "firing"))
                status = SignozProvider.STATUS_MAP.get(
                    status_str.lower(), AlertStatus.FIRING
                )

                # Map severity
                severity_str = labels.get("severity", "info")
                severity = SignozProvider.SEVERITIES_MAP.get(
                    severity_str.lower(), AlertSeverity.INFO
                )

                # Get fingerprint
                fingerprint = alert.get("fingerprint", "")

                # Get timestamps
                starts_at = alert.get("startsAt", "")
                ends_at = alert.get("endsAt", "")

                # Parse lastReceived timestamp
                if starts_at:
                    try:
                        last_received = datetime.datetime.fromisoformat(
                            starts_at.replace("Z", "+00:00")
                        ).isoformat()
                    except ValueError:
                        last_received = datetime.datetime.now(
                            tz=datetime.timezone.utc
                        ).isoformat()
                else:
                    last_received = datetime.datetime.now(
                        tz=datetime.timezone.utc
                    ).isoformat()

                # Get description from annotations
                description = annotations.get(
                    "description", annotations.get("summary", "")
                )

                # Get URL - prefer generatorURL, fallback to externalURL
                url = alert.get("generatorURL", external_url) or None

                # Extract environment from labels
                environment = labels.get(
                    "environment",
                    labels.get("env", labels.get("deployment_environment", "unknown"))
                )

                # Get rule ID from labels if available
                rule_id = labels.get("ruleId", "")

                # Get service from labels
                service = labels.get("service", labels.get("service.name", ""))

                # Build extra fields from annotations
                extra = {}
                if annotations:
                    extra["annotations"] = annotations

                # Create AlertDto
                alert_dto = AlertDto(
                    id=fingerprint or rule_id or name,
                    fingerprint=fingerprint,
                    name=name,
                    status=status,
                    severity=severity,
                    environment=environment,
                    service=service if service else None,
                    lastReceived=last_received,
                    description=description,
                    source=["signoz"],
                    labels=labels,
                    url=url,
                    startedAt=starts_at if starts_at else None,
                    **extra,
                )

                # Enrich with additional label fields
                for label_key, label_value in labels.items():
                    # Skip already mapped fields
                    if label_key in ("alertname", "severity", "environment", "env", "service", "ruleId"):
                        continue
                    # Add as attribute if not already set
                    if getattr(alert_dto, label_key.replace(".", "_"), None) is None:
                        setattr(alert_dto, label_key.replace(".", "_"), label_value)

                formatted_alerts.append(alert_dto)

            except Exception as e:
                logger.exception(
                    f"Error formatting SigNoz alert: {str(e)}",
                    extra={"alert": alert},
                )
                continue

        logger.info(f"Successfully formatted {len(formatted_alerts)} SigNoz alerts")
        return formatted_alerts

    @classmethod
    def simulate_alert(cls, **kwargs) -> dict:
        """
        Simulate a SigNoz alert for testing purposes.
        """
        import random
        import hashlib

        alert_types = [
            {
                "alertname": "High CPU Usage",
                "severity": "warning",
                "description": "CPU usage exceeded 80% threshold",
            },
            {
                "alertname": "Memory Pressure",
                "severity": "critical",
                "description": "Memory usage is above 90%",
            },
            {
                "alertname": "Disk Space Low",
                "severity": "warning",
                "description": "Disk space below 10% remaining",
            },
            {
                "alertname": "Service Latency High",
                "severity": "error",
                "description": "P99 latency exceeded 500ms",
            },
        ]

        alert_type = random.choice(alert_types)
        fingerprint = hashlib.md5(
            f"{alert_type['alertname']}-{random.randint(1, 1000)}".encode()
        ).hexdigest()[:12]

        now = datetime.datetime.now(tz=datetime.timezone.utc)

        payload = {
            "receiver": "keep-webhook",
            "status": "firing",
            "alerts": [
                {
                    "status": "firing",
                    "labels": {
                        "alertname": alert_type["alertname"],
                        "severity": alert_type["severity"],
                        "ruleId": f"019ade8d-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}",
                        "host.name": f"server-{random.randint(1, 10)}",
                        "service": "demo-service",
                    },
                    "annotations": {
                        "description": alert_type["description"],
                        "summary": alert_type["description"],
                    },
                    "startsAt": now.isoformat(),
                    "endsAt": "0001-01-01T00:00:00Z",
                    "generatorURL": "https://signoz.example.com/alerts",
                    "fingerprint": fingerprint,
                }
            ],
            "groupLabels": {"alertname": alert_type["alertname"]},
            "commonLabels": {
                "alertname": alert_type["alertname"],
                "severity": alert_type["severity"],
            },
            "commonAnnotations": {"summary": alert_type["description"]},
            "externalURL": "https://signoz.example.com",
        }

        to_wrap_with_provider_type = kwargs.get("to_wrap_with_provider_type")
        if to_wrap_with_provider_type:
            return {"keep_source_type": "signoz", "event": payload}
        return payload


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])

    # Test alert formatting
    test_payload = {
        "receiver": "test-webhook",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "Test Alert",
                    "severity": "warning",
                    "ruleId": "test-rule-123",
                    "host.name": "test-host",
                },
                "annotations": {
                    "description": "This is a test alert",
                    "summary": "Test alert summary",
                },
                "startsAt": "2024-01-02T13:30:00.000000Z",
                "endsAt": "0001-01-01T00:00:00Z",
                "generatorURL": "https://signoz.example.com/alerts/edit?ruleId=test-rule-123",
                "fingerprint": "abc123def456",
            }
        ],
        "externalURL": "https://signoz.example.com",
    }

    alerts = SignozProvider._format_alert(test_payload)
    for alert in alerts:
        print(f"Alert: {alert.name}, Status: {alert.status}, Severity: {alert.severity}")
        print(f"  Fingerprint: {alert.fingerprint}")
        print(f"  Description: {alert.description}")
