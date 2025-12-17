import dataclasses
import datetime
import hashlib
import json
import logging
import os
import re
import time
import typing
import urllib.parse
import uuid

import pydantic
import requests

from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus
from keep.api.models.db.incident import IncidentSeverity, IncidentStatus
from keep.api.models.db.topology import TopologyServiceInDto
from keep.api.models.incident import IncidentDto
from keep.contextmanager.contextmanager import ContextManager
from keep.exceptions.provider_config_exception import ProviderConfigException
from keep.providers.base.base_provider import (
    BaseIncidentProvider,
    BaseProvider,
    BaseTopologyProvider,
    ProviderHealthMixin,
)
from keep.providers.models.provider_config import ProviderConfig, ProviderScope
from keep.providers.providers_factory import ProvidersFactory

# Todo: think about splitting in to PagerdutyIncidentsProvider and PagerdutyAlertsProvider
# Read this: https://community.pagerduty.com/forum/t/create-incident-using-python/3596/3

logger = logging.getLogger(__name__)
KEEP_PD_ALERT_INCIDENT_KEY_PREFIX = "keep-alert:"


@pydantic.dataclasses.dataclass
class PagerdutyProviderAuthConfig:
    routing_key: str | None = dataclasses.field(
        metadata={
            "required": False,
            "description": "Routing Key (an integration or ruleset key)",
        },
        default=None,
    )
    api_key: str | None = dataclasses.field(
        metadata={
            "required": False,
            "description": "Api Key (a user or team API key)",
            "sensitive": True,
        },
        default=None,
    )
    oauth_data: dict = dataclasses.field(
        metadata={
            "description": "For oauth flow",
            "required": False,
            "sensitive": True,
            "hidden": True,
        },
        default="",
    )
    service_id: str | None = dataclasses.field(
        metadata={
            "required": False,
            "description": "Service Id (if provided, keep will only operate on this service)",
            "sensitive": False,
        },
        default=None,
    )


class PagerdutyProvider(
    BaseTopologyProvider, BaseIncidentProvider, ProviderHealthMixin
):
    """Pull alerts and query incidents from PagerDuty."""

    PROVIDER_SCOPES = [
        ProviderScope(
            name="incidents_read",
            description="Read incidents data.",
            mandatory=True,
            alias="Incidents Data Read",
        ),
        ProviderScope(
            name="incidents_write",
            description="Write incidents.",
            mandatory=False,
            alias="Incidents Write",
        ),
        ProviderScope(
            name="webhook_subscriptions_read",
            description="Read webhook data.",
            mandatory=False,
            mandatory_for_webhook=True,
            alias="Webhooks Data Read",
        ),
        ProviderScope(
            name="webhook_subscriptions_write",
            description="Write webhooks.",
            mandatory=False,
            mandatory_for_webhook=True,
            alias="Webhooks Write",
        ),
    ]
    BASE_API_URL = "https://api.pagerduty.com"
    SUBSCRIPTION_API_URL = f"{BASE_API_URL}/webhook_subscriptions"
    PROVIDER_DISPLAY_NAME = "PagerDuty"
    ALERT_SEVERITIES_MAP = {
        "critical": AlertSeverity.CRITICAL,
        "error": AlertSeverity.HIGH,
        "warning": AlertSeverity.WARNING,
        "info": AlertSeverity.INFO,
    }
    INCIDENT_SEVERITIES_MAP = {
        "P1": IncidentSeverity.CRITICAL,
        "P2": IncidentSeverity.HIGH,
        "P3": IncidentSeverity.WARNING,
        "P4": IncidentSeverity.INFO,
    }
    ALERT_STATUS_MAP = {
        "triggered": AlertStatus.FIRING,
        "resolved": AlertStatus.RESOLVED,
    }
    ALERT_STATUS_TO_EVENT_TYPE_MAP = {
        AlertStatus.FIRING.value: "trigger",
        AlertStatus.RESOLVED.value: "resolve",
        AlertStatus.ACKNOWLEDGED.value: "acknowledge",
    }
    INCIDENT_STATUS_MAP = {
        "triggered": IncidentStatus.FIRING,
        "acknowledged": IncidentStatus.ACKNOWLEDGED,
        "resolved": IncidentStatus.RESOLVED,
    }

    BASE_OAUTH_URL = "https://identity.pagerduty.com"
    PAGERDUTY_CLIENT_ID = os.environ.get("PAGERDUTY_CLIENT_ID")
    PAGERDUTY_CLIENT_SECRET = os.environ.get("PAGERDUTY_CLIENT_SECRET")
    OAUTH2_URL = (
        f"{BASE_OAUTH_URL}/oauth/authorize?client_id={PAGERDUTY_CLIENT_ID}&response_type=code"
        if PAGERDUTY_CLIENT_ID is not None and PAGERDUTY_CLIENT_SECRET is not None
        else None
    )
    PROVIDER_CATEGORY = ["Incident Management"]
    FINGERPRINT_FIELDS = ["alert_key"]

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)

        if self.authentication_config.oauth_data:
            last_fetched_at = self.authentication_config.oauth_data["last_fetched_at"]
            expires_in: float | None = self.authentication_config.oauth_data.get(
                "expires_in", None
            )
            if expires_in:
                # Calculate expiration time by adding expires_in to last_fetched_at
                expiration_time = last_fetched_at + expires_in - 600

                # Check if the current epoch time (in seconds) has passed the expiration time
                if time.time() <= expiration_time:
                    self.logger.debug("access_token is still valid")
                    return

            self.logger.info("Refreshing access token")
            self.__refresh_token()
        elif (
            self.authentication_config.api_key or self.authentication_config.routing_key
        ):
            # No need to do anything
            return
        else:
            raise Exception("WTF Exception: No authentication provided")

    def __refresh_token(self):
        """
        Refresh the access token using the refresh token.
        """
        # Using the refresh token to get the access token
        try:
            access_token_response = requests.post(
                url=f"{PagerdutyProvider.BASE_OAUTH_URL}/oauth/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "refresh_token",
                    "client_id": PagerdutyProvider.PAGERDUTY_CLIENT_ID,
                    "client_secret": PagerdutyProvider.PAGERDUTY_CLIENT_SECRET,
                    "refresh_token": f'{self.authentication_config.oauth_data["refresh_token"]}',
                },
            )
            access_token_response.raise_for_status()
            access_token_response = access_token_response.json()
            self.config.authentication["oauth_data"] = {
                "access_token": access_token_response["access_token"],
                "refresh_token": access_token_response["refresh_token"],
                "expires_in": access_token_response["expires_in"],
                "last_fetched_at": time.time(),
            }
        except Exception:
            self.logger.exception(
                "Error while refreshing token",
            )
            raise

    def validate_config(self):
        self.authentication_config = PagerdutyProviderAuthConfig(
            **self.config.authentication
        )
        if (
            not self.authentication_config.routing_key
            and not self.authentication_config.api_key
            and not self.authentication_config.oauth_data
        ):
            raise ProviderConfigException(
                "PagerdutyProvider requires either routing_key or api_key or OAuth configuration",
                provider_id=self.provider_id,
            )

    @staticmethod
    def oauth2_logic(**payload) -> dict:
        """
        OAuth2 callback logic for Pagerduty.

        Raises:
            Exception: No code verifier
            Exception: No code
            Exception: No redirect URI
            Exception: Failed to get access token
            Exception: No access token

        Returns:
            dict: access token and refresh token
        """
        code_verifier = payload.get("verifier")
        if not code_verifier:
            raise Exception("No code verifier")

        code = payload.get("code")
        if not code:
            raise Exception("No code")

        redirect_uri = payload.get("redirect_uri")
        if not redirect_uri:
            raise Exception("Missing redirect URI")

        access_token_params = {
            "client_id": PagerdutyProvider.PAGERDUTY_CLIENT_ID,
            "client_secret": PagerdutyProvider.PAGERDUTY_CLIENT_SECRET,
            "code_verifier": code_verifier,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }

        access_token_response = requests.post(
            url=f"{PagerdutyProvider.BASE_OAUTH_URL}/oauth/token",
            data=access_token_params,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            access_token_response.raise_for_status()
            access_token_response = access_token_response.json()
        except Exception:
            response_text = access_token_response.text
            response_status = access_token_response.status_code
            logger.exception(
                "Failed to get access token",
                extra={
                    "response_text": response_text,
                    "response_status": response_status,
                },
            )
            raise

        access_token = access_token_response.get("access_token")
        if not access_token:
            raise Exception("No access token provided")
        return {
            "oauth_data": {
                "access_token": access_token_response["access_token"],
                "refresh_token": access_token_response["refresh_token"],
                "last_fetched_at": time.time(),
                "expires_in": access_token_response.get("expires_in", None),
            }
        }

    def __get_headers(self, **kwargs):
        if self.authentication_config.api_key:
            return {
                "Accept": "application/vnd.pagerduty+json;version=2",
                "Content-Type": "application/json",
                "Authorization": f"Token token={self.authentication_config.api_key}",
                **kwargs,
            }
        elif self.authentication_config.oauth_data:
            return {
                "Accept": "application/vnd.pagerduty+json;version=2",
                "Authorization": f"Bearer {self.authentication_config.oauth_data['access_token']}",
                "Content-Type": "application/json",
            }
        return {}

    @staticmethod
    def _is_truthy(value: object) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "t", "yes", "y", "on"}
        return bool(value)

    def _get_keep_ui_url(self, override: str | None = None) -> str | None:
        if override:
            return override.rstrip("/")

        env_url = os.environ.get("KEEP_URL") or os.environ.get("KEEP_UI_URL")
        if env_url:
            return env_url.rstrip("/")

        try:
            api_url = self.context_manager.api_url
            parsed = urllib.parse.urlparse(api_url)
            if not parsed.scheme or not parsed.hostname:
                return None

            host = parsed.hostname
            if host.startswith("api."):
                host = host[len("api.") :]

            # Best-effort: default local UI port if backend is on common local ports.
            ui_port: int | None = None
            if parsed.port in {8080, 8000}:
                ui_port = 3000

            netloc = host if ui_port is None else f"{host}:{ui_port}"
            return f"{parsed.scheme}://{netloc}"
        except Exception:
            return None

    def _build_keep_incident_url(self, keep_ui_url: str, keep_incident_id: str) -> str:
        return f"{keep_ui_url}/incidents/{keep_incident_id}"

    def _build_keep_alert_url(self, keep_ui_url: str, alert_fingerprint: str) -> str:
        fingerprint = urllib.parse.quote(str(alert_fingerprint), safe="")
        return f"{keep_ui_url}/alerts/feed?alertPayloadFingerprint={fingerprint}"

    def _normalize_alert_dict(self, alert: object) -> dict:
        if isinstance(alert, dict):
            return alert
        if hasattr(alert, "dict") and callable(getattr(alert, "dict")):
            try:
                return alert.dict()
            except Exception:
                pass
        if hasattr(alert, "__dict__"):
            try:
                return dict(alert.__dict__)
            except Exception:
                pass
        return {}

    def _alert_is_active(self, alert_dict: dict) -> bool:
        status = alert_dict.get("status")
        if isinstance(status, AlertStatus):
            status_value = status.value
        else:
            status_value = str(status).lower() if status is not None else ""

        is_resolved = status_value == AlertStatus.RESOLVED.value
        dismissed = alert_dict.get("dismissed")
        deleted = alert_dict.get("deleted")

        return not (is_resolved or self._is_truthy(dismissed) or self._is_truthy(deleted))

    def _build_keep_alert_incident_key(self, keep_incident_id: str, alert_fingerprint: str) -> str:
        raw_key = f"{KEEP_PD_ALERT_INCIDENT_KEY_PREFIX}{keep_incident_id}:{alert_fingerprint}"
        if len(raw_key) <= 255:
            return raw_key
        digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        return f"{KEEP_PD_ALERT_INCIDENT_KEY_PREFIX}{digest}"

    def _get_incident_alert_keys(self, incident_id: str) -> set[str]:
        url = f"{self.BASE_API_URL}/incidents/{incident_id}/alerts"
        keys: set[str] = set()

        offset = 0
        limit = 100
        while True:
            response = requests.get(
                url,
                headers=self.__get_headers(),
                params={"offset": offset, "limit": limit},
            )
            response.raise_for_status()
            data = response.json() or {}
            alerts = data.get("alerts", []) or []
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                alert_key = alert.get("alert_key")
                if alert_key:
                    keys.add(str(alert_key))

            if not data.get("more", False):
                break
            offset += limit

        return keys

    def _merge_incidents(
        self,
        target_incident_id: str,
        source_incident_ids: list[str],
        requester: str,
    ) -> dict:
        if not requester:
            raise ValueError("requester is required to merge PagerDuty incidents")
        url = f"{self.BASE_API_URL}/incidents/{target_incident_id}/merge"
        payload = {
            "source_incidents": [
                {"id": incident_id, "type": "incident_reference"}
                for incident_id in source_incident_ids
            ]
        }
        response = requests.put(
            url,
            headers=self.__get_headers(From=requester),
            json=payload,
        )
        try:
            response.raise_for_status()
        except Exception as e:
            raise Exception(response.text) from e
        return response.json()

    def _get_incident_id_by_incident_key(
        self,
        incident_key: str,
        retries: int = 6,
        sleep_seconds: float = 1.0,
    ) -> str | None:
        for attempt in range(retries):
            try:
                response = self._get_specific_incident_with_incident_key(incident_key)
                incidents = response.get("incidents", []) if isinstance(response, dict) else []
                if incidents:
                    incident_id = incidents[0].get("id")
                    if incident_id:
                        return str(incident_id)
            except Exception:
                self.logger.exception(
                    "Failed to find PagerDuty incident by incident_key",
                    extra={
                        "incident_key": incident_key,
                        "attempt": attempt + 1,
                        "retries": retries,
                        "tenant_id": self.context_manager.tenant_id,
                    },
                )
            if attempt < retries - 1:
                time.sleep(sleep_seconds)
        return None

    def _sync_keep_incident_alerts_as_pagerduty_alerts(
        self,
        pagerduty_parent_incident_id: str,
        requester: str,
        routing_key: str | None = None,
        keep_ui_url: str | None = None,
        merge_into_parent: bool = True,
    ) -> dict:
        incident_context = self.context_manager.incident_context
        if not incident_context:
            raise Exception(
                "PagerDuty alert sync requires Keep incident context (workflow trigger type: incident)"
            )

        if not routing_key:
            routing_key = self.authentication_config.routing_key
        if not routing_key:
            raise ProviderConfigException(
                "PagerDuty alert sync requires a routing_key (Events API v2 integration key); set it in the provider config or pass routing_key in the workflow action",
                provider_id=self.provider_id,
            )

        if merge_into_parent and not (self.authentication_config.api_key or self.authentication_config.oauth_data):
            raise ProviderConfigException(
                "PagerDuty alert sync merge requires api_key (REST) or OAuth; set it in the provider config",
                provider_id=self.provider_id,
            )

        keep_incident_id = ""
        expected_alerts_count = 0
        if isinstance(incident_context, dict):
            keep_incident_id = str(incident_context.get("id", "") or "")
            alerts = incident_context.get("alerts") or []
            previous_synced = (
                incident_context.get("pagerduty_synced_alert_fingerprints") or []
            )
            try:
                expected_alerts_count = int(incident_context.get("alerts_count") or 0)
            except Exception:
                expected_alerts_count = 0
        else:
            keep_incident_id = str(getattr(incident_context, "id", "") or "")
            alerts = getattr(incident_context, "alerts", []) or []
            previous_synced = (
                getattr(incident_context, "pagerduty_synced_alert_fingerprints", []) or []
            )
            try:
                expected_alerts_count = int(getattr(incident_context, "alerts_count", 0) or 0)
            except Exception:
                expected_alerts_count = 0

        if not isinstance(alerts, list):
            try:
                alerts = list(alerts)
            except Exception:
                alerts = []

        if not alerts and keep_incident_id and expected_alerts_count > 0:
            self.logger.warning(
                "PagerDuty alert sync: incident context has no alerts; attempting DB lookup",
                extra={
                    "tenant_id": self.context_manager.tenant_id,
                    "workflow_id": getattr(self.context_manager, "workflow_id", None),
                    "workflow_execution_id": getattr(
                        self.context_manager, "workflow_execution_id", None
                    ),
                    "keep_incident_id": keep_incident_id,
                    "expected_alerts_count": expected_alerts_count,
                },
            )
            try:
                from keep.api.core.db import get_incident_alerts_by_incident_id
                from keep.api.utils.enrichment_helpers import (
                    convert_db_alerts_to_dto_alerts,
                )

                db_alerts, _ = get_incident_alerts_by_incident_id(
                    self.context_manager.tenant_id, keep_incident_id
                )
                alerts = convert_db_alerts_to_dto_alerts(db_alerts)
                self.logger.info(
                    "PagerDuty alert sync: loaded incident alerts from DB",
                    extra={
                        "tenant_id": self.context_manager.tenant_id,
                        "workflow_id": getattr(self.context_manager, "workflow_id", None),
                        "workflow_execution_id": getattr(
                            self.context_manager, "workflow_execution_id", None
                        ),
                        "keep_incident_id": keep_incident_id,
                        "alerts_total": len(alerts),
                    },
                )
            except Exception:
                self.logger.exception(
                    "PagerDuty alert sync: failed to load incident alerts from DB",
                    extra={
                        "tenant_id": self.context_manager.tenant_id,
                        "workflow_id": getattr(self.context_manager, "workflow_id", None),
                        "workflow_execution_id": getattr(
                            self.context_manager, "workflow_execution_id", None
                        ),
                        "keep_incident_id": keep_incident_id,
                    },
                )

        if isinstance(previous_synced, str):
            try:
                previous_synced = json.loads(previous_synced)
            except Exception:
                previous_synced = []

        previous_synced_set = set(str(x) for x in previous_synced if x)

        current_fingerprints: set[str] = set()
        skipped_missing_fingerprint = 0
        for alert in alerts:
            alert_dict = self._normalize_alert_dict(alert)
            fingerprint = str(alert_dict.get("fingerprint", "") or "")
            if not fingerprint:
                skipped_missing_fingerprint += 1
                continue
            current_fingerprints.add(fingerprint)

        removed_fingerprints = sorted(previous_synced_set - current_fingerprints)

        resolved_keep_ui_url = self._get_keep_ui_url(keep_ui_url)
        keep_incident_url = (
            self._build_keep_incident_url(resolved_keep_ui_url, keep_incident_id)
            if resolved_keep_ui_url and keep_incident_id
            else None
        )

        parent_alert_keys: set[str] = set()
        if merge_into_parent and pagerduty_parent_incident_id:
            try:
                parent_alert_keys = self._get_incident_alert_keys(pagerduty_parent_incident_id)
            except Exception:
                self.logger.exception(
                    "Failed to fetch PagerDuty parent incident alerts; will still attempt merge",
                    extra={
                        "pagerduty_parent_incident_id": pagerduty_parent_incident_id,
                        "tenant_id": self.context_manager.tenant_id,
                    },
                )
                parent_alert_keys = set()

        self.logger.info(
            "PagerDuty alert sync: start",
            extra={
                "tenant_id": self.context_manager.tenant_id,
                "workflow_id": getattr(self.context_manager, "workflow_id", None),
                "workflow_execution_id": getattr(
                    self.context_manager, "workflow_execution_id", None
                ),
                "keep_incident_id": keep_incident_id,
                "pagerduty_parent_incident_id": pagerduty_parent_incident_id,
                "alerts_total": len(alerts),
                "alerts_skipped_missing_fingerprint": skipped_missing_fingerprint,
                "alerts_removed_since_last_sync": len(removed_fingerprints),
                "merge_into_parent": merge_into_parent,
                "has_keep_ui_url": bool(resolved_keep_ui_url),
            },
        )

        created_or_updated: list[dict] = []
        merged: list[dict] = []
        resolved: list[dict] = []
        errors: list[dict] = []

        for alert in alerts:
            alert_dict = self._normalize_alert_dict(alert)
            fingerprint = str(alert_dict.get("fingerprint", "") or "")
            if not fingerprint:
                continue

            alert_name = str(alert_dict.get("name", "") or f"Keep alert {fingerprint}")
            alert_message = alert_dict.get("message")
            alert_description = alert_dict.get("description")
            alert_description_format = alert_dict.get("description_format")
            keep_alert_url = (
                self._build_keep_alert_url(resolved_keep_ui_url, fingerprint)
                if resolved_keep_ui_url
                else None
            )

            status = alert_dict.get("status")
            if isinstance(status, AlertStatus):
                status_value = status.value
            else:
                status_value = str(status).lower() if status is not None else ""

            dismissed = self._is_truthy(alert_dict.get("dismissed"))
            deleted = self._is_truthy(alert_dict.get("deleted"))
            if deleted or dismissed:
                event_type_value: typing.Literal["trigger", "acknowledge", "resolve"] = "resolve"
            elif status_value == AlertStatus.RESOLVED.value:
                event_type_value = "resolve"
            elif status_value == AlertStatus.ACKNOWLEDGED.value:
                event_type_value = "acknowledge"
            else:
                event_type_value = "trigger"

            keep_severity = alert_dict.get("severity")
            if isinstance(keep_severity, AlertSeverity):
                keep_severity_value = keep_severity.value
            else:
                keep_severity_value = str(keep_severity).lower() if keep_severity is not None else "info"

            severity_map = {
                AlertSeverity.CRITICAL.value: "critical",
                AlertSeverity.HIGH.value: "error",
                AlertSeverity.WARNING.value: "warning",
                AlertSeverity.INFO.value: "info",
                AlertSeverity.LOW.value: "info",
            }
            pd_severity: typing.Literal["critical", "error", "warning", "info"] = severity_map.get(
                keep_severity_value, "info"
            )

            incident_key = self._build_keep_alert_incident_key(keep_incident_id, fingerprint)
            source = str(alert_dict.get("service") or "keep")

            custom_details = {
                "keep_incident_id": keep_incident_id,
                "keep_incident_url": keep_incident_url,
                "keep_alert_fingerprint": fingerprint,
                "keep_alert_url": keep_alert_url,
                "keep_alert_id": alert_dict.get("event_id") or alert_dict.get("id"),
                "keep_alert_name": alert_name,
                "keep_alert_message": alert_message,
                "keep_alert_description": alert_description,
                "keep_alert_description_format": alert_description_format,
                "keep_alert_status": status_value,
                "keep_alert_severity": keep_severity_value,
            }

            links: list[dict] = []
            if keep_alert_url:
                links.append({"href": keep_alert_url, "text": "Open Keep alert"})
            if keep_incident_url:
                links.append({"href": keep_incident_url, "text": "Open Keep incident"})

            try:
                result = self._send_alert(
                    title=alert_name,
                    routing_key=routing_key,
                    dedup=incident_key,
                    severity=pd_severity,
                    event_type=event_type_value,
                    source=source,
                    custom_details=custom_details,
                    component=alert_dict.get("service"),
                    group=keep_incident_id,
                    links=links or None,
                )
                created_or_updated.append(
                    {
                        "fingerprint": fingerprint,
                        "incident_key": incident_key,
                        "event_type": event_type_value,
                        "result_status": result.get("status") if isinstance(result, dict) else None,
                    }
                )
                self.logger.info(
                    "PagerDuty alert sync: sent event",
                    extra={
                        "tenant_id": self.context_manager.tenant_id,
                        "keep_incident_id": keep_incident_id,
                        "pagerduty_parent_incident_id": pagerduty_parent_incident_id,
                        "keep_alert_fingerprint": fingerprint,
                        "pagerduty_incident_key": incident_key,
                        "event_type": event_type_value,
                    },
                )

                if event_type_value == "resolve":
                    resolved.append({"fingerprint": fingerprint, "incident_key": incident_key})
                    continue

                if not merge_into_parent or not pagerduty_parent_incident_id:
                    continue

                if incident_key in parent_alert_keys:
                    continue

                source_incident_id = self._get_incident_id_by_incident_key(incident_key)
                if not source_incident_id:
                    self.logger.warning(
                        "PagerDuty alert sync: could not find source incident id for merge",
                        extra={
                            "tenant_id": self.context_manager.tenant_id,
                            "keep_incident_id": keep_incident_id,
                            "pagerduty_parent_incident_id": pagerduty_parent_incident_id,
                            "keep_alert_fingerprint": fingerprint,
                            "pagerduty_incident_key": incident_key,
                        },
                    )
                    continue

                if source_incident_id == pagerduty_parent_incident_id:
                    parent_alert_keys.add(incident_key)
                    continue

                self._merge_incidents(
                    target_incident_id=pagerduty_parent_incident_id,
                    source_incident_ids=[source_incident_id],
                    requester=requester,
                )
                parent_alert_keys.add(incident_key)
                merged.append(
                    {
                        "fingerprint": fingerprint,
                        "incident_key": incident_key,
                        "source_incident_id": source_incident_id,
                    }
                )
                self.logger.info(
                    "PagerDuty alert sync: merged incident into parent",
                    extra={
                        "tenant_id": self.context_manager.tenant_id,
                        "keep_incident_id": keep_incident_id,
                        "pagerduty_parent_incident_id": pagerduty_parent_incident_id,
                        "keep_alert_fingerprint": fingerprint,
                        "pagerduty_incident_key": incident_key,
                        "source_incident_id": source_incident_id,
                    },
                )
            except Exception as e:
                errors.append(
                    {
                        "fingerprint": fingerprint,
                        "incident_key": incident_key,
                        "error": str(e),
                    }
                )
                self.logger.exception(
                    "PagerDuty alert sync: failed for alert",
                    extra={
                        "tenant_id": self.context_manager.tenant_id,
                        "keep_incident_id": keep_incident_id,
                        "pagerduty_parent_incident_id": pagerduty_parent_incident_id,
                        "keep_alert_fingerprint": fingerprint,
                        "pagerduty_incident_key": incident_key,
                    },
                )

        for fingerprint in removed_fingerprints:
            incident_key = self._build_keep_alert_incident_key(keep_incident_id, fingerprint)
            if merge_into_parent and parent_alert_keys and incident_key not in parent_alert_keys:
                # If it was never merged, skip resolving to avoid noisy PD errors.
                continue
            try:
                self._send_alert(
                    title=f"Keep alert removed ({fingerprint})",
                    routing_key=routing_key,
                    dedup=incident_key,
                    severity="info",
                    event_type="resolve",
                    source="keep",
                    custom_details={
                        "keep_incident_id": keep_incident_id,
                        "keep_incident_url": keep_incident_url,
                        "keep_alert_fingerprint": fingerprint,
                        "keep_alert_removed": True,
                    },
                    group=keep_incident_id,
                )
                resolved.append({"fingerprint": fingerprint, "incident_key": incident_key, "removed": True})
                self.logger.info(
                    "PagerDuty alert sync: resolved removed alert",
                    extra={
                        "tenant_id": self.context_manager.tenant_id,
                        "keep_incident_id": keep_incident_id,
                        "pagerduty_parent_incident_id": pagerduty_parent_incident_id,
                        "keep_alert_fingerprint": fingerprint,
                        "pagerduty_incident_key": incident_key,
                    },
                )
            except Exception as e:
                errors.append({"fingerprint": fingerprint, "incident_key": incident_key, "error": str(e)})
                self.logger.exception(
                    "PagerDuty alert sync: failed to resolve removed alert",
                    extra={
                        "tenant_id": self.context_manager.tenant_id,
                        "keep_incident_id": keep_incident_id,
                        "pagerduty_parent_incident_id": pagerduty_parent_incident_id,
                        "keep_alert_fingerprint": fingerprint,
                        "pagerduty_incident_key": incident_key,
                    },
                )

        result = {
            "action": "sync_incident_alerts_as_pagerduty_alerts",
            "keep_incident_id": keep_incident_id,
            "pagerduty_parent_incident_id": pagerduty_parent_incident_id,
            "alerts_total": len(alerts),
            "alerts_sent": len(created_or_updated),
            "alerts_merged": len(merged),
            "alerts_resolved": len(resolved),
            "alerts_removed_since_last_sync": len(removed_fingerprints),
            "pagerduty_synced_alert_fingerprints": sorted(current_fingerprints),
            "events": created_or_updated,
            "merged": merged,
            "resolved": resolved,
            "errors": errors,
        }

        self.logger.info(
            "PagerDuty alert sync: done",
            extra={
                "tenant_id": self.context_manager.tenant_id,
                "workflow_id": getattr(self.context_manager, "workflow_id", None),
                "workflow_execution_id": getattr(
                    self.context_manager, "workflow_execution_id", None
                ),
                "keep_incident_id": keep_incident_id,
                "pagerduty_parent_incident_id": pagerduty_parent_incident_id,
                "sent": len(created_or_updated),
                "merged": len(merged),
                "resolved": len(resolved),
                "errors": len(errors),
            },
        )

        return result

    def validate_scopes(self):
        """
        Validate that the provider has the required scopes.
        """
        headers = self.__get_headers()
        scopes = {}
        for scope in self.PROVIDER_SCOPES:

            # If the provider is installed using a routing key, we skip scopes validation for now.
            if self.authentication_config.routing_key:
                if scope.name == "incidents_read":
                    # This is because incidents_read is mandatory and will not let the provider install otherwise
                    scopes[scope.name] = True
                else:
                    scopes[scope.name] = "Skipped due to routing key"
                continue

            try:
                # Todo: how to check validity for write scopes?
                if scope.name.startswith("incidents"):
                    response = requests.get(
                        f"{self.BASE_API_URL}/incidents",
                        headers=headers,
                    )
                elif scope.name.startswith("webhook_subscriptions"):
                    response = requests.get(
                        self.SUBSCRIPTION_API_URL,
                        headers=headers,
                    )
                if response.ok:
                    scopes[scope.name] = True
                else:
                    try:
                        response_json = response.json()
                        scopes[scope.name] = str(
                            response_json.get("error", response.reason)
                        )
                    except Exception:
                        scopes[scope.name] = response.reason
            except Exception as e:
                self.logger.exception("Error validating scopes")
                scopes[scope.name] = str(e)
        return scopes

    def _build_alert(
        self,
        title: str,
        routing_key: str,
        dedup: str | None = None,
        severity: typing.Literal["critical", "error", "warning", "info"] | None = None,
        event_type: typing.Literal["trigger", "acknowledge", "resolve"] | None = None,
        source: str | None = None,
        **kwargs,
    ) -> typing.Dict[str, typing.Any]:
        """
        Builds the payload for an event alert.

        Args:
            title: Title of alert
            alert_body: UTF-8 string of custom message for alert. Shown in incident body
            dedup: Any string, max 255, characters used to deduplicate alerts
            event_type: The type of event to send to PagerDuty

        Returns:
            Dictionary of alert body for JSON serialization
        """
        if not severity:
            # this is the default severity
            severity = "critical"
            # try to get it automatically from the context (if there's an alert, for example)
            if self.context_manager.event_context:
                # Handle both dict and AlertDto cases for event_context
                if isinstance(self.context_manager.event_context, dict):
                    severity = self.context_manager.event_context.get("severity")
                else:
                    severity = self.context_manager.event_context.severity

        if not event_type:
            event_type = "trigger"
            # try to get it automatically from the context (if there's an alert, for example)
            if self.context_manager.event_context:
                # Handle both dict and AlertDto cases for event_context
                if isinstance(self.context_manager.event_context, dict):
                    status = self.context_manager.event_context.get("status")
                else:
                    status = self.context_manager.event_context.status
                event_type = PagerdutyProvider.ALERT_STATUS_TO_EVENT_TYPE_MAP.get(
                    status, "trigger"
                )

        if not dedup:
            # If no dedup is given, use epoch timestamp
            dedup = str(datetime.datetime.now().timestamp())
            # Try to get it from the context (if there's an alert, for example)
            if self.context_manager.event_context:
                # Handle both dict and AlertDto cases for event_context
                if isinstance(self.context_manager.event_context, dict):
                    dedup = self.context_manager.event_context.get("fingerprint")
                else:
                    dedup = self.context_manager.event_context.fingerprint

        if not source:
            source = "custom_event"
            if self.context_manager.event_context:
                # Handle both dict and AlertDto cases for event_context
                if isinstance(self.context_manager.event_context, dict):
                    source = self.context_manager.event_context.get("service") or "custom_event"
                else:
                    source = self.context_manager.event_context.service or "custom_event"

        payload = {
            "routing_key": routing_key,
            "event_action": event_type,
            "dedup_key": dedup,
            "payload": {
                "summary": title,
                "source": source,
                "severity": severity,
            },
        }
        custom_details = kwargs.get("custom_details", {})
        if isinstance(custom_details, str):
            custom_details = json.loads(custom_details)
        if not custom_details and kwargs.get("alert_body"):
            custom_details = {"alert_body": kwargs.get("alert_body")}

        if custom_details:
            payload["payload"]["custom_details"] = custom_details

        if kwargs.get("timestamp"):
            payload["payload"]["timestamp"] = kwargs.get("timestamp")

        if kwargs.get("component"):
            payload["payload"]["component"] = kwargs.get("component")

        if kwargs.get("group"):
            payload["payload"]["group"] = kwargs.get("group")

        if kwargs.get("class"):
            payload["payload"]["class"] = kwargs.get("class")

        if kwargs.get("images"):
            images = kwargs.get("images", [])
            if isinstance(images, str):
                images = json.loads(images)
            payload["payload"]["images"] = images

        if kwargs.get("links"):
            links = kwargs.get("links", [])
            if isinstance(links, str):
                links = json.loads(links)
            payload["payload"]["links"] = links
        return payload

    def _send_alert(
        self,
        title: str,
        routing_key: str,
        dedup: str | None = None,
        severity: typing.Literal["critical", "error", "warning", "info"] | None = None,
        event_type: typing.Literal["trigger", "acknowledge", "resolve"] | None = None,
        source: str | None = None,
        **kwargs,
    ):
        """
        Sends PagerDuty Alert

        Args:
            title: Title of the alert.
            alert_body: UTF-8 string of custom message for alert. Shown in incident body
            dedup: Any string, max 255, characters used to deduplicate alerts
            event_type: The type of event to send to PagerDuty
        """
        url = "https://events.pagerduty.com/v2/enqueue"

        payload = self._build_alert(
            title, routing_key, dedup, severity, event_type, source, **kwargs
        )
        result = requests.post(url, json=payload)
        result.raise_for_status()

        response_json: dict | None = None
        try:
            response_json = result.json()
        except Exception:
            response_json = None

        self.logger.info(
            "Sent alert to PagerDuty",
            extra={
                "tenant_id": self.context_manager.tenant_id,
                "workflow_id": getattr(self.context_manager, "workflow_id", None),
                "workflow_execution_id": getattr(
                    self.context_manager, "workflow_execution_id", None
                ),
                "status_code": result.status_code,
                "event_type": event_type,
                "dedup_key": dedup,
                "response_status": (
                    response_json.get("status") if isinstance(response_json, dict) else None
                ),
                "response_message": (
                    response_json.get("message") if isinstance(response_json, dict) else None
                ),
                "routing_key_hash": hashlib.sha256(routing_key.encode("utf-8")).hexdigest()[:8]
                if routing_key
                else None,
            },
        )
        return response_json or {}

    def _trigger_incident(
        self,
        service_id: str,
        title: str,
        body: dict | str,
        requester: str,
        incident_key: str | None = None,
        priority: str = "",
        status: typing.Literal["resolved", "acknowledged"] = "",
        resolution: str = "",
    ):
        """Triggers an incident via the V2 REST API using sample data."""

        update = True

        if not incident_key:
            incident_key = str(uuid.uuid4()).replace("-", "")
            update = False

        url = (
            f"{self.BASE_API_URL}/incidents"
            if not update
            else f"{self.BASE_API_URL}/incidents/{incident_key}"
        )
        headers = self.__get_headers(From=requester)

        if isinstance(body, str):
            body = json.loads(body)
            if "details" in body and "type" not in body:
                body["type"] = "incident_body"

        payload = {
            "incident": {
                "type": "incident",
                "title": title,
                "service": {"id": service_id, "type": "service_reference"},
                "incident_key": incident_key,
                "body": body,
            }
        }

        if status:
            payload["incident"]["status"] = status
            if status == "resolved" and resolution:
                payload["incident"]["resolution"] = resolution

        if priority:
            payload["incident"]["priority"] = {
                "id": priority,
                "type": "priority_reference",
            }

        r = (
            requests.post(url, headers=headers, data=json.dumps(payload))
            if not update
            else requests.put(url, headers=headers, data=json.dumps(payload))
        )
        try:
            r.raise_for_status()
            response = r.json()
            self.logger.info(
                "Incident triggered",
                extra={
                    "update": update,
                    "incident_key": incident_key,
                    "tenant_id": self.context_manager.tenant_id,
                },
            )
            return response
        except Exception as e:
            self.logger.error(
                "Failed to trigger incident",
                extra={
                    "response_text": r.text,
                    "update": update,
                    "incident_key": incident_key,
                    "tenant_id": self.context_manager.tenant_id,
                },
            )
            # This will give us a better error message in Keep workflows
            raise Exception(r.text) from e

    def _extract_error_message(self, response: requests.Response) -> str:
        """
        Extract a user-friendly error message from PagerDuty API error response.

        Args:
            response: The failed requests.Response object

        Returns:
            A formatted error message with details from PagerDuty
        """
        try:
            error_data = response.json()
            error_obj = error_data.get("error", {})

            # Get the main error message
            error_message = error_obj.get("message", "Unknown error")

            # Get detailed errors if available
            errors = error_obj.get("errors", [])

            # Build the error message
            if errors:
                error_details = "; ".join(str(e) for e in errors)
                return f"{error_message} - {error_details}"
            else:
                return error_message
        except Exception:
            # Fallback to raw response text if JSON parsing fails
            return f"HTTP {response.status_code}: {response.text[:200]}"

    def clean_up(self):
        """
        Clean up the provider.
        It will remove the webhook from PagerDuty if it exists.
        """
        self.logger.info(
            "Cleaning up %s provider with id %s",
            self.PROVIDER_DISPLAY_NAME,
            self.provider_id,
        )
        keep_webhook_incidents_api_url = f"{self.context_manager.api_url}/incidents/event/{self.provider_type}?provider_id={self.provider_id}"
        headers = self.__get_headers()
        request = requests.get(self.SUBSCRIPTION_API_URL, headers=headers)
        if not request.ok:
            error_detail = self._extract_error_message(request)
            raise Exception(f"Could not get existing webhooks: {error_detail}")
        existing_webhooks = request.json().get("webhook_subscriptions", [])
        webhook_exists = next(
            iter(
                [
                    webhook
                    for webhook in existing_webhooks
                    if keep_webhook_incidents_api_url
                    == webhook.get("delivery_method", {}).get("url", "")
                ]
            ),
            False,
        )
        if webhook_exists:
            self.logger.info("Webhook exists, removing it")
            webhook_id = webhook_exists.get("id")
            request = requests.delete(
                f"{self.SUBSCRIPTION_API_URL}/{webhook_id}", headers=headers
            )
            if not request.ok:
                error_detail = self._extract_error_message(request)
                raise Exception(f"Could not remove existing webhook: {error_detail}")
            self.logger.info("Webhook removed", extra={"webhook_id": webhook_id})

    def dispose(self):
        """
        No need to dispose of anything, so just do nothing.
        """
        pass

    def setup_incident_webhook(
        self,
        tenant_id: str,
        keep_api_url: str,
        api_key: str,
        setup_alerts: bool = True,
    ):
        self.logger.info("Setting up Pagerduty webhook")

        if not (self.authentication_config.api_key or self.authentication_config.oauth_data):
            self.logger.info("Skipping webhook setup due to missing API key / OAuth")
            return

        headers = self.__get_headers()
        request = requests.get(self.SUBSCRIPTION_API_URL, headers=headers)
        if not request.ok:
            error_detail = self._extract_error_message(request)
            raise Exception(f"Could not get existing webhooks: {error_detail}")
        existing_webhooks = request.json().get("webhook_subscriptions", [])
        webhook_exists = next(
            iter(
                [
                    webhook
                    for webhook in existing_webhooks
                    if keep_api_url == webhook.get("delivery_method", {}).get("url", "")
                ]
            ),
            False,
        )
        webhook_payload = {
            "webhook_subscription": {
                "type": "webhook_subscription",
                "delivery_method": {
                    "type": "http_delivery_method",
                    "url": keep_api_url,
                    "custom_headers": [{"name": "X-API-KEY", "value": api_key}],
                },
                "description": f"Keep Pagerduty webhook ({self.provider_id}) - do not change",
                "events": [
                    "incident.acknowledged",
                    "incident.annotated",
                    "incident.delegated",
                    "incident.escalated",
                    "incident.priority_updated",
                    "incident.reassigned",
                    "incident.reopened",
                    "incident.resolved",
                    "incident.responder.added",
                    "incident.responder.replied",
                    "incident.triggered",
                    "incident.unacknowledged",
                ],
                "filter": (
                    {
                        "type": "service_reference",
                        "id": self.authentication_config.service_id,
                    }
                    if self.authentication_config.service_id
                    else {"type": "account_reference"}
                ),
            },
        }
        if webhook_exists:
            self.logger.info("Webhook already exists, removing and re-creating")
            webhook_id = webhook_exists.get("id")
            request = requests.delete(
                f"{self.SUBSCRIPTION_API_URL}/{webhook_id}", headers=headers
            )
            if not request.ok:
                error_detail = self._extract_error_message(request)
                raise Exception(f"Could not remove existing webhook: {error_detail}")
            self.logger.info("Webhook removed", extra={"webhook_id": webhook_id})

        self.logger.info("Creating Pagerduty webhook")
        request = requests.post(
            self.SUBSCRIPTION_API_URL,
            headers=headers,
            json=webhook_payload,
        )
        if not request.ok:
            error_detail = self._extract_error_message(request)
            self.logger.error("Failed to add webhook", extra={"error": error_detail, "response": request.json()})
            raise Exception(f"Could not create webhook: {error_detail}")
        self.logger.info("Webhook created")

    def _notify(
        self,
        title: str = "",
        dedup: str = "",
        service_id: str = "",
        routing_key: str = "",
        requester: str = "",
        incident_id: str = "",
        incident_key: str = "",
        body: dict | str | None = None,
        event_type: typing.Literal["trigger", "acknowledge", "resolve"] | None = None,
        severity: typing.Literal["critical", "error", "warning", "info"] | None = None,
        source: str = "custom_event",
        priority: str = "",
        status: typing.Literal["resolved", "acknowledged"] = "",
        resolution: str = "",
        sync_incident_alerts_as_alerts: bool = False,
        merge_into_parent: bool = True,
        keep_ui_url: str = "",
        **kwargs: dict,
    ):
        """
        Create a PagerDuty alert or incident.
        For events API, uses Events API v2. For incidents, uses REST API v2.
        See: https://developer.pagerduty.com/docs/ZG9jOjQ1NzA0NTc-overview

        Args:
            title (str): Title of the alert or incident
            dedup (str | None): String used to deduplicate alerts for events API, max 255 chars
            service_id (str): ID of the service for incidents
            routing_key (str): API routing_key (optional), if not specified, fallbacks to the one provided in provider
            body (dict): Body of the incident as per https://developer.pagerduty.com/api-reference/a7d81b0e9200f-create-an-incident#request-body
            requester (str): Email of the user requesting the incident creation
            incident_id (str | None): Key to identify the incident. UUID generated if not provided
            incident_key (str | None): Incident key (dedup key) to find/upsert incidents without a stored PagerDuty incident id
            priority (str | None): Priority reference ID for incidents
            event_type (str | None): Event type for events API (trigger/acknowledge/resolve)
            severity (str | None): Severity for events API (critical/error/warning/info)
            source (str): Source field for events API
            status (str): Status for incident updates (resolved/acknowledged)
            resolution (str): Resolution note for resolved incidents
            kwargs (dict): Additional event/incident fields
        """
        self.logger.info(
            "PagerDuty notify called",
            extra={
                "tenant_id": self.context_manager.tenant_id,
                "workflow_id": getattr(self.context_manager, "workflow_id", None),
                "workflow_execution_id": getattr(
                    self.context_manager, "workflow_execution_id", None
                ),
                "service_id": service_id,
                "incident_id": incident_id,
                "incident_key": incident_key,
                "status": status,
                "has_resolution": bool(resolution),
                "has_routing_key": bool(routing_key),
                "has_api_key": bool(bool(self.authentication_config.api_key)),
                "has_oauth": bool(bool(self.authentication_config.oauth_data)),
            },
        )

        sync_incident_alerts = self._is_truthy(sync_incident_alerts_as_alerts) or self._is_truthy(
            kwargs.get("sync_keep_incident_alerts_as_alerts")
            or kwargs.get("sync_incident_alerts_to_alerts")
        )
        if sync_incident_alerts:
            pagerduty_parent_incident_id = (
                incident_id
                or kwargs.get("pagerduty_parent_incident_id")
                or kwargs.get("pagerduty_incident_id")
                or kwargs.get("pd_incident_id")
            )
            keep_ui_url_override = keep_ui_url or (
                kwargs.get("keep_url")
                or kwargs.get("keep_frontend_url")
            )
            return self._sync_keep_incident_alerts_as_pagerduty_alerts(
                pagerduty_parent_incident_id=pagerduty_parent_incident_id,
                requester=requester,
                routing_key=routing_key,
                keep_ui_url=keep_ui_url_override,
                merge_into_parent=merge_into_parent,
            )

        # Prefer the Incidents API when incident-related fields are provided; otherwise fall back to
        # the Events API when a routing_key is available.
        use_incidents_api = bool(
            service_id or incident_id or incident_key or status or resolution or priority
        )

        if use_incidents_api:
            if not (self.authentication_config.api_key or self.authentication_config.oauth_data):
                raise ProviderConfigException(
                    "PagerDuty incidents API requires api_key or OAuth authentication",
                    provider_id=self.provider_id,
                )
            incident_body = body or kwargs.get("body") or kwargs.get("alert_body")
            # Backward-compatible: older workflows used `alert_body`, schema/docs use `body`.
            return self._upsert_or_update_incident(
                service_id=service_id,
                title=title,
                body=incident_body,
                requester=requester,
                incident_id=incident_id,
                incident_key=incident_key,
                priority=priority,
                status=status,
                resolution=resolution,
            )

        if not routing_key:  # If routing_key not specified in workflow, fallback to config routing_key
            routing_key = self.authentication_config.routing_key
        if not routing_key:
            raise ProviderConfigException(
                "PagerDuty events API requires routing_key authentication",
                provider_id=self.provider_id,
            )

        return self._send_alert(
            title,
            dedup=dedup,
            event_type=event_type,
            routing_key=routing_key,
            source=source,
            severity=severity,
            **kwargs,
        )

    def _upsert_or_update_incident(
        self,
        service_id: str,
        title: str,
        body: dict | str,
        requester: str,
        incident_id: str = "",
        incident_key: str = "",
        priority: str = "",
        status: typing.Literal["resolved", "acknowledged"] = "",
        resolution: str = "",
    ) -> dict:
        """
        Create/lookup/update a PagerDuty incident via REST API.

        Behavior:
        - If `incident_id` is provided, updates that PagerDuty incident id.
        - Else if `incident_key` is provided:
          - For create-intent calls (no status/resolution), returns an existing incident with that key if present,
            otherwise creates a new incident with that key.
          - For update-intent calls (status/resolution), looks up the incident by key and updates it; never creates.
        - Else creates a new incident with a generated key.
        """
        if incident_id:
            self.logger.info(
                "PagerDuty incident: updating by incident_id",
                extra={
                    "tenant_id": self.context_manager.tenant_id,
                    "workflow_id": getattr(self.context_manager, "workflow_id", None),
                    "workflow_execution_id": getattr(
                        self.context_manager, "workflow_execution_id", None
                    ),
                    "incident_id": incident_id,
                    "incident_key": incident_key,
                    "status": status,
                    "has_resolution": bool(resolution),
                },
            )
            return self._update_incident(
                incident_id=incident_id,
                service_id=service_id,
                title=title,
                body=body,
                requester=requester,
                priority=priority,
                status=status,
                resolution=resolution,
            )

        has_update_intent = bool(status or resolution)

        if incident_key:
            self.logger.info(
                "PagerDuty incident: lookup by incident_key",
                extra={
                    "tenant_id": self.context_manager.tenant_id,
                    "workflow_id": getattr(self.context_manager, "workflow_id", None),
                    "workflow_execution_id": getattr(
                        self.context_manager, "workflow_execution_id", None
                    ),
                    "incident_key": incident_key,
                    "has_update_intent": has_update_intent,
                    "status": status,
                    "has_resolution": bool(resolution),
                },
            )
            existing = self._get_specific_incident_with_incident_key(incident_key)
            incidents = existing.get("incidents", []) if isinstance(existing, dict) else []

            if incidents:
                incident = incidents[0]
                existing_incident_id = incident.get("id", "")
                self.logger.info(
                    "PagerDuty incident: found existing by incident_key",
                    extra={
                        "tenant_id": self.context_manager.tenant_id,
                        "workflow_id": getattr(self.context_manager, "workflow_id", None),
                        "workflow_execution_id": getattr(
                            self.context_manager, "workflow_execution_id", None
                        ),
                        "incident_key": incident_key,
                        "incident_id": existing_incident_id,
                        "will_update": has_update_intent,
                        "will_return_existing": not has_update_intent,
                    },
                )
                if has_update_intent:
                    if not existing_incident_id:
                        raise Exception(
                            f"PagerDuty incident lookup by incident_key='{incident_key}' did not return an id"
                        )
                    return self._update_incident(
                        incident_id=existing_incident_id,
                        service_id=service_id,
                        title=title,
                        body=body,
                        requester=requester,
                        priority=priority,
                        status=status,
                        resolution=resolution,
                    )
                # Create-intent: return an object compatible with create response (`results.incident.id`)
                return {"incident": incident, "existing": True}

            if has_update_intent:
                self.logger.error(
                    "PagerDuty incident: not found by incident_key; refusing to create on update",
                    extra={
                        "tenant_id": self.context_manager.tenant_id,
                        "workflow_id": getattr(self.context_manager, "workflow_id", None),
                        "workflow_execution_id": getattr(
                            self.context_manager, "workflow_execution_id", None
                        ),
                        "incident_key": incident_key,
                        "status": status,
                        "has_resolution": bool(resolution),
                    },
                )
                raise Exception(
                    f"PagerDuty incident with incident_key='{incident_key}' not found; refusing to create on update"
                )
            self.logger.info(
                "PagerDuty incident: creating new with incident_key",
                extra={
                    "tenant_id": self.context_manager.tenant_id,
                    "workflow_id": getattr(self.context_manager, "workflow_id", None),
                    "workflow_execution_id": getattr(
                        self.context_manager, "workflow_execution_id", None
                    ),
                    "incident_key": incident_key,
                },
            )
            return self._create_incident(
                service_id=service_id,
                title=title,
                body=body,
                requester=requester,
                incident_key=incident_key,
                priority=priority,
                status=status,
                resolution=resolution,
            )

        self.logger.info(
            "PagerDuty incident: creating new (no incident_id/incident_key provided)",
            extra={
                "tenant_id": self.context_manager.tenant_id,
                "workflow_id": getattr(self.context_manager, "workflow_id", None),
                "workflow_execution_id": getattr(
                    self.context_manager, "workflow_execution_id", None
                ),
            },
        )
        return self._create_incident(
            service_id=service_id,
            title=title,
            body=body,
            requester=requester,
            incident_key="",
            priority=priority,
            status=status,
            resolution=resolution,
        )

    def _create_incident(
        self,
        service_id: str,
        title: str,
        body: dict | str,
        requester: str,
        incident_key: str = "",
        priority: str = "",
        status: typing.Literal["resolved", "acknowledged"] = "",
        resolution: str = "",
    ) -> dict:
        if not incident_key:
            incident_key = str(uuid.uuid4()).replace("-", "")

        url = f"{self.BASE_API_URL}/incidents"
        headers = self.__get_headers(From=requester)

        if isinstance(body, str):
            body = json.loads(body)
            if "details" in body and "type" not in body:
                body["type"] = "incident_body"

        self.logger.info(
            "PagerDuty incident: POST /incidents",
            extra={
                "tenant_id": self.context_manager.tenant_id,
                "workflow_id": getattr(self.context_manager, "workflow_id", None),
                "workflow_execution_id": getattr(
                    self.context_manager, "workflow_execution_id", None
                ),
                "service_id": service_id,
                "incident_key": incident_key,
                "status": status,
            },
        )
        payload = {
            "incident": {
                "type": "incident",
                "title": title,
                "service": {"id": service_id, "type": "service_reference"},
                "incident_key": incident_key,
                "body": body,
            }
        }

        if status:
            payload["incident"]["status"] = status
            if status == "resolved" and resolution:
                payload["incident"]["resolution"] = resolution

        if priority:
            payload["incident"]["priority"] = {
                "id": priority,
                "type": "priority_reference",
            }

        r = requests.post(url, headers=headers, data=json.dumps(payload))
        try:
            r.raise_for_status()
            response = r.json()
            self.logger.info(
                "Incident created",
                extra={
                    "incident_key": incident_key,
                    "tenant_id": self.context_manager.tenant_id,
                    "workflow_id": getattr(self.context_manager, "workflow_id", None),
                    "workflow_execution_id": getattr(
                        self.context_manager, "workflow_execution_id", None
                    ),
                },
            )
            return response
        except Exception as e:
            self.logger.error(
                "Failed to create incident",
                extra={
                    "response_text": r.text,
                    "incident_key": incident_key,
                    "tenant_id": self.context_manager.tenant_id,
                    "workflow_id": getattr(self.context_manager, "workflow_id", None),
                    "workflow_execution_id": getattr(
                        self.context_manager, "workflow_execution_id", None
                    ),
                },
            )
            raise Exception(r.text) from e

    def _update_incident(
        self,
        incident_id: str,
        service_id: str,
        title: str,
        body: dict | str,
        requester: str,
        priority: str = "",
        status: typing.Literal["resolved", "acknowledged"] = "",
        resolution: str = "",
    ) -> dict:
        url = f"{self.BASE_API_URL}/incidents/{incident_id}"
        headers = self.__get_headers(From=requester)

        if isinstance(body, str):
            body = json.loads(body)
            if "details" in body and "type" not in body:
                body["type"] = "incident_body"

        self.logger.info(
            "PagerDuty incident: PUT /incidents/{incident_id}",
            extra={
                "tenant_id": self.context_manager.tenant_id,
                "workflow_id": getattr(self.context_manager, "workflow_id", None),
                "workflow_execution_id": getattr(
                    self.context_manager, "workflow_execution_id", None
                ),
                "service_id": service_id,
                "incident_id": incident_id,
                "status": status,
                "has_resolution": bool(resolution),
            },
        )
        payload = {
            "incident": {
                "type": "incident",
                "title": title,
                "service": {"id": service_id, "type": "service_reference"},
                "body": body,
            }
        }

        if status:
            payload["incident"]["status"] = status
            if status == "resolved" and resolution:
                payload["incident"]["resolution"] = resolution

        if priority:
            payload["incident"]["priority"] = {
                "id": priority,
                "type": "priority_reference",
            }

        r = requests.put(url, headers=headers, data=json.dumps(payload))
        try:
            r.raise_for_status()
            response = r.json()
            self.logger.info(
                "Incident updated",
                extra={
                    "incident_id": incident_id,
                    "tenant_id": self.context_manager.tenant_id,
                    "workflow_id": getattr(self.context_manager, "workflow_id", None),
                    "workflow_execution_id": getattr(
                        self.context_manager, "workflow_execution_id", None
                    ),
                },
            )
            return response
        except Exception as e:
            response_json: dict | None = None
            try:
                response_json = r.json()
            except Exception:
                response_json = None

            def _has_error(substring: str) -> bool:
                if not response_json or not isinstance(response_json, dict):
                    return False
                needle = substring.lower()
                for container_key in ("incident", "error"):
                    container = response_json.get(container_key) or {}
                    if isinstance(container, dict):
                        errors = container.get("errors") or []
                        if isinstance(errors, list) and any(
                            needle in str(err).lower() for err in errors
                        ):
                            return True
                return False

            already_resolved = _has_error("Incident Already Resolved")
            already_acknowledged = _has_error("Incident Already Acknowledged")
            if status and (already_resolved or already_acknowledged):
                self.logger.info(
                    "PagerDuty incident update: no-op (already in desired state)",
                    extra={
                        "tenant_id": self.context_manager.tenant_id,
                        "workflow_id": getattr(self.context_manager, "workflow_id", None),
                        "workflow_execution_id": getattr(
                            self.context_manager, "workflow_execution_id", None
                        ),
                        "incident_id": incident_id,
                        "requested_status": status,
                        "already_resolved": already_resolved,
                        "already_acknowledged": already_acknowledged,
                    },
                )
                if isinstance(response_json, dict):
                    return response_json
                return {"incident": {"id": incident_id}}

            self.logger.error(
                "Failed to update incident",
                extra={
                    "response_text": r.text,
                    "response_json": response_json,
                    "incident_id": incident_id,
                    "tenant_id": self.context_manager.tenant_id,
                    "workflow_id": getattr(self.context_manager, "workflow_id", None),
                    "workflow_execution_id": getattr(
                        self.context_manager, "workflow_execution_id", None
                    ),
                },
            )
            raise Exception(r.text) from e

    def _query(self, incident_id: str = None, incident_key: str = None):
        if incident_id:
            return self._get_specific_incident(incident_id)
        elif incident_key: # Query Incident via incident_key (dedup_key)
            return self._get_specific_incident_with_incident_key(incident_key)
        else:
            return self.__get_all_incidents_or_alerts()

    @staticmethod
    def _format_alert(
        event: dict,
        provider_instance: "BaseProvider" = None,
        force_new_format: bool = False,
    ) -> AlertDto:
        # If somebody connected the provider before we refactored it
        old_format_event = event.get("event", {})
        if (
            old_format_event is not None
            and isinstance(old_format_event, dict)
            and not force_new_format
        ):
            return PagerdutyProvider._format_alert_old(event)

        status = PagerdutyProvider.ALERT_STATUS_MAP.get(event.get("status", "firing"))
        severity = PagerdutyProvider.ALERT_SEVERITIES_MAP.get(
            event.get("severity", "info")
        )
        source = ["pagerduty"]
        fingerprint = event.get("alert_key", event.get("id"))
        try:
            origin = event.get("body", {}).get("cef_details", {}).get("source_origin")
            if origin:
                source.append(origin)
        except Exception:
            # Could not extract origin or fingerprint, so we'll use the event id
            pass
        return AlertDto(
            id=event.get("id"),
            name=event.get("summary"),
            url=event.get("html_url"),
            service=event.get("service", {}).get("name"),
            lastReceived=event.get("created_at"),
            status=status,
            severity=severity,
            source=source,
            original_alert=event,
            fingerprint=fingerprint,
        )

    def _format_alert_old(event: dict) -> AlertDto:
        actual_event = event.get("event", {})
        data = actual_event.get("data", {})

        event_type = data.get("type", "incident")
        if event_type != "incident":
            return None

        url = data.pop("self", data.pop("html_url", None))
        # format status and severity to Keep format
        status = PagerdutyProvider.ALERT_STATUS_MAP.get(data.pop("status", "firing"))
        priority_summary = (data.get("priority", {}) or {}).get("summary")
        priority = PagerdutyProvider.ALERT_SEVERITIES_MAP.get(priority_summary, "P4")
        last_received = data.pop(
            "created_at", datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
        )
        name = data.pop("title", "unknown title")
        service = data.pop("service", {}).get("summary", "unknown")
        environment = next(
            iter(
                [
                    x
                    for x in data.pop("custom_fields", [])
                    if x.get("name") == "environment"
                ]
            ),
            {},
        ).get("value", "unknown")

        last_status_change_by = data.get("last_status_change_by", {}).get("summary")
        acknowledgers = [x.get("summary") for x in data.get("acknowledgers", [])]
        conference_bridge = data.get("conference_bridge", {})
        if isinstance(conference_bridge, dict):
            conference_bridge = conference_bridge.get("summary")
        urgency = data.get("urgency")

        # Additional metadata
        metadata = {
            "urgency": urgency,
            "acknowledgers": acknowledgers,
            "last_updated_by": last_status_change_by,
            "conference_bridge": conference_bridge,
            "impacted_services": service,
        }

        return AlertDto(
            **data,
            url=url,
            status=status,
            lastReceived=last_received,
            name=name,
            severity=priority,
            environment=environment,
            source=["pagerduty"],
            service=service,
            labels=metadata,
        )

    def _get_specific_incident(self, incident_id: str):
        self.logger.info("Getting Incident", extra={"incident_id": incident_id})
        url = f"{self.BASE_API_URL}/incidents/{incident_id}"
        params = {
            "include[]": [
                "acknowledgers",
                "agents",
                "assignees",
                "conference_bridge",
                "custom_fields",
                "escalation_policies",
                "first_trigger_log_entries",
                "priorities",
                "services",
                "teams",
                "users",
            ]
        }
        response = requests.get(url, headers=self.__get_headers(), params=params)
        response.raise_for_status()
        return response.json()

    def _get_specific_incident_with_incident_key(self, incident_key: str): # Query Incident via incident_key (dedup_key)
        self.logger.info("Getting Incident", extra={"incident_key": incident_key})
        url = f"{self.BASE_API_URL}/incidents"
        params = {
            "incident_key": incident_key,
            "include[]": [
                "acknowledgers",
                "agents",
                "assignees",
                "conference_bridge",
                "custom_fields",
                "escalation_policies",
                "first_trigger_log_entries",
                "priorities",
                "services",
                "teams",
                "users",
            ]
        }
        response = requests.get(url, headers=self.__get_headers(), params=params)
        response.raise_for_status()
        return response.json()

    def __get_all_incidents_or_alerts(self, incident_id: str = None, limit: int = 100):
        self.logger.info(
            "Getting incidents or alerts",
            extra={
                "incident_id": incident_id,
                "tenant_id": self.context_manager.tenant_id,
            },
        )
        paginated_response = []
        offset = 0
        max_iterations = os.environ.get("KEEP_PAGERDUTY_MAX_ITERATIONS", 2)
        current_iteration = 0
        total = True
        while True:
            try:
                url = f"{self.BASE_API_URL}/incidents"
                include = []
                resource = "incidents"
                if incident_id is not None:
                    url += f"/{incident_id}/alerts"
                    include = ["teams", "services"]
                    resource = "alerts"
                params = {
                    "include[]": include,
                    "offset": offset,
                    "limit": limit,
                    "total": total,
                    "sort_by": ["created_at:desc"],
                }
                if not incident_id and self.authentication_config.service_id:
                    params["service_ids[]"] = [self.authentication_config.service_id]
                response = requests.get(
                    url=url,
                    headers=self.__get_headers(),
                    params=params,
                )
                response.raise_for_status()
                response = response.json()
            except Exception:
                self.logger.exception(
                    "Failed to get incidents or alerts",
                    extra={
                        "incident_id": incident_id,
                        "tenant_id": self.context_manager.tenant_id,
                    },
                )
                if paginated_response:
                    self.logger.warning(
                        "Failed to get incidents from offset",
                        extra={
                            "offset": offset,
                            "tenant_id": self.context_manager.tenant_id,
                        },
                    )
                    break
                else:
                    self.logger.exception(
                        "Failed to get any incidents or alerts",
                        extra={"tenant_id": self.context_manager.tenant_id},
                    )
                    raise
            offset += limit
            paginated_response.extend(response.get(resource, []))
            extra = {"offset": offset, "tenant_id": self.context_manager.tenant_id}
            if total:
                extra["total"] = response.get("total", 0)
                extra["to_fetch"] = min([limit * max_iterations, extra["total"]])
            self.logger.info(
                "Fetched incidents or alerts",
                extra=extra,
            )
            # No more results
            if not response.get("more", False) or current_iteration >= max_iterations:
                self.logger.info(
                    "No more incidents or alerts",
                    extra={
                        "tenant_id": self.context_manager.tenant_id,
                        "current_iteration": current_iteration,
                        "max_iterations": max_iterations,
                    },
                )
                break
            current_iteration += 1
            # We want total only on the first iteration
            total = False
        self.logger.info(
            "Fetched all incidents or alerts",
            extra={
                "count": len(paginated_response),
                "incident_id": incident_id,
                "tenant_id": self.context_manager.tenant_id,
            },
        )
        return paginated_response

    def __get_all_services(self, business_services: bool = False):
        all_services = []
        offset = 0
        more = True
        endpoint = "business_services" if business_services else "services"
        while more:
            try:
                services_response = requests.get(
                    url=f"{self.BASE_API_URL}/{endpoint}",
                    headers=self.__get_headers(),
                    params={"include[]": ["teams"], "offset": offset, "limit": 100},
                )
                services_response.raise_for_status()
                services_response = services_response.json()
            except Exception as e:
                self.logger.error("Failed to get all services", extra={"exception": e})
                raise e
            more = services_response.get("more", False)
            offset = services_response.get("offset", 0)
            all_services.extend(services_response.get(endpoint, []))
        return all_services

    def pull_topology(self) -> tuple[list[TopologyServiceInDto], dict]:
        # Skipping topology pulling when we're installed with routing_key
        if self.authentication_config.routing_key:
            return [], {}

        all_services = self.__get_all_services()
        all_business_services = self.__get_all_services(business_services=True)
        service_metadata = {}
        for service in all_services:
            service_metadata[service["id"]] = service

        for business_service in all_business_services:
            service_metadata[business_service["id"]] = business_service

        try:
            service_map_response = requests.get(
                url=f"{self.BASE_API_URL}/service_dependencies",
                headers=self.__get_headers(),
            )
            service_map_response.raise_for_status()
            service_map_response = service_map_response.json()
        except Exception:
            self.logger.exception("Error while getting service dependencies")
            raise

        service_topology = {}

        for relationship in service_map_response.get("relationships", []):
            # Extract dependent and supporting service details
            dependent = relationship["dependent_service"]
            supporting = relationship["supporting_service"]

            if dependent["id"] not in service_topology:
                service_topology[dependent["id"]] = TopologyServiceInDto(
                    source_provider_id=self.provider_id,
                    service=dependent["id"],
                    display_name=service_metadata[dependent["id"]]["name"],
                    description=service_metadata[dependent["id"]]["description"],
                    team=", ".join(
                        team["name"]
                        for team in service_metadata[dependent["id"]].get("teams", [])
                    ),
                )
            if supporting["id"] not in service_topology:
                service_topology[supporting["id"]] = TopologyServiceInDto(
                    source_provider_id=self.provider_id,
                    service=supporting["id"],
                    display_name=service_metadata[supporting["id"]]["name"],
                    description=service_metadata[supporting["id"]]["description"],
                    team=", ".join(
                        team["name"]
                        for team in service_metadata[supporting["id"]].get("teams", [])
                    ),
                )
            service_topology[dependent["id"]].dependencies[supporting["id"]] = "unknown"
        return list(service_topology.values()), {}

    def _get_incidents(self) -> list[IncidentDto]:
        # Skipping incidents pulling when we don't have credentials for the Incidents API
        if not (self.authentication_config.api_key or self.authentication_config.oauth_data):
            return []

        # Consultic behavior: when Keep is the source of truth, we only want to sync
        # status changes for incidents that Keep originally created in PagerDuty.
        #
        # We use the PagerDuty `incident_key` to map back to the Keep incident id
        # (we set `incident_key` to `incident.id` when creating the parent incident).
        #
        # This prevents:
        # - importing arbitrary PagerDuty incidents into Keep
        # - Keep↔PagerDuty feedback loops on periodic incident pulls
        from uuid import UUID

        from keep.api.core.db import get_incident_by_id

        raw_incidents = self.__get_all_incidents_or_alerts()

        incidents: list[IncidentDto] = []
        skipped_missing_or_invalid_incident_key = 0
        skipped_missing_keep_incident = 0
        skipped_no_status_change = 0
        status_updates = 0

        for pagerduty_incident in raw_incidents:
            if not isinstance(pagerduty_incident, dict):
                skipped_missing_or_invalid_incident_key += 1
                continue

            incident_key = pagerduty_incident.get("incident_key")
            if not incident_key:
                skipped_missing_or_invalid_incident_key += 1
                continue

            try:
                keep_incident_id = UUID(str(incident_key))
            except Exception:
                skipped_missing_or_invalid_incident_key += 1
                continue

            keep_incident = get_incident_by_id(
                tenant_id=self.context_manager.tenant_id, incident_id=keep_incident_id
            )
            if not keep_incident:
                skipped_missing_keep_incident += 1
                continue

            pagerduty_status = PagerdutyProvider.INCIDENT_STATUS_MAP.get(
                pagerduty_incident.get("status") or "triggered",
                IncidentStatus.FIRING,
            )

            keep_status = str(getattr(keep_incident, "status", "") or "")
            if keep_status == pagerduty_status.value:
                skipped_no_status_change += 1
                continue

            try:
                incident_dto = IncidentDto.from_db_incident(keep_incident)
            except Exception:
                self.logger.exception(
                    "PagerDuty incident pull: failed to convert Keep incident to DTO",
                    extra={
                        "provider_id": self.provider_id,
                        "tenant_id": self.context_manager.tenant_id,
                        "keep_incident_id": str(keep_incident_id),
                        "pagerduty_incident_id": pagerduty_incident.get("id"),
                        "incident_key": str(incident_key),
                    },
                )
                continue

            # Only apply the status change; keep all other fields as-is.
            incident_dto.status = pagerduty_status
            # Do not sync PagerDuty alerts into Keep incidents in this flow.
            incident_dto._alerts = []

            incidents.append(incident_dto)
            status_updates += 1

            self.logger.info(
                "PagerDuty incident pull: status change detected",
                extra={
                    "provider_id": self.provider_id,
                    "tenant_id": self.context_manager.tenant_id,
                    "keep_incident_id": str(keep_incident_id),
                    "pagerduty_incident_id": pagerduty_incident.get("id"),
                    "incident_key": str(incident_key),
                    "keep_status": keep_status,
                    "pagerduty_status": pagerduty_status.value,
                },
            )

        if status_updates:
            self.logger.info(
                "PagerDuty incident pull: summary",
                extra={
                    "provider_id": self.provider_id,
                    "tenant_id": self.context_manager.tenant_id,
                    "raw_incidents": len(raw_incidents),
                    "status_updates": status_updates,
                    "skipped_missing_or_invalid_incident_key": skipped_missing_or_invalid_incident_key,
                    "skipped_missing_keep_incident": skipped_missing_keep_incident,
                    "skipped_no_status_change": skipped_no_status_change,
                },
            )

        return incidents

    @staticmethod
    def _get_incident_id(incident_id: str) -> str:
        """
        Create a UUID from the incident id.

        Args:
            incident_id (str): The original incident id

        Returns:
            str: The UUID
        """
        md5 = hashlib.md5()
        md5.update(incident_id.encode("utf-8"))
        return uuid.UUID(md5.hexdigest())

    @staticmethod
    def _format_incident(
        event: dict, provider_instance: "BaseProvider" = None
    ) -> IncidentDto | list[IncidentDto]:

        def _parse_datetime(value: typing.Any) -> datetime.datetime | None:
            if not value:
                return None
            if isinstance(value, datetime.datetime):
                return value
            if isinstance(value, str):
                normalized = value
                if normalized.endswith("Z"):
                    normalized = normalized[:-1] + "+00:00"
                try:
                    parsed = datetime.datetime.fromisoformat(normalized)
                except ValueError:
                    for fmt in (
                        "%Y-%m-%dT%H:%M:%S.%f%z",
                        "%Y-%m-%dT%H:%M:%S%z",
                        "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%d %H:%M:%S",
                    ):
                        try:
                            parsed = datetime.datetime.strptime(value, fmt)
                            break
                        except ValueError:
                            parsed = None
                    if parsed is None:
                        raise
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=datetime.timezone.utc)
                return parsed
            return None

        def _extract_incident_payload(
            raw: dict,
        ) -> tuple[dict | None, str | None, str | None]:
            """
            Supports PagerDuty webhooks v3 (messages[]) and legacy formats.

            Returns:
                (incident_payload, message_created_on, event_type)
            """
            if not isinstance(raw, dict):
                return None, None, None

            if "incident" in raw and isinstance(raw["incident"], dict):
                return (
                    raw["incident"],
                    raw.get("created_on") or raw.get("created_at"),
                    raw.get("event_type") or raw.get("type"),
                )

            if "event" in raw and isinstance(raw["event"], dict):
                event_type = raw["event"].get("event_type") or raw["event"].get("type")
                data = raw["event"].get("data")
                if isinstance(data, dict):
                    # Some payloads wrap incident under data.incident
                    if "incident" in data and isinstance(data["incident"], dict):
                        return (
                            data["incident"],
                            raw.get("created_on") or data.get("created_at"),
                            event_type,
                        )
                    return data, raw.get("created_on") or data.get("created_at"), event_type

            return raw, raw.get("created_on") or raw.get("created_at"), raw.get(
                "event_type"
            ) or raw.get("type")

        if isinstance(event, dict) and isinstance(event.get("messages"), list):
            incidents: list[IncidentDto] = []
            for message in event.get("messages", []):
                incident_payload, message_created_on, _event_type = _extract_incident_payload(
                    message
                )
                if not incident_payload:
                    continue
                formatted = PagerdutyProvider._format_incident(
                    {
                        "event": {
                            "data": incident_payload,
                            "event_type": _event_type,
                        },
                        "created_on": message_created_on,
                    },
                    provider_instance,
                )
                if isinstance(formatted, list):
                    incidents.extend(formatted)
                elif formatted:
                    incidents.append(formatted)
            return incidents

        incident_payload, message_created_on, event_type = _extract_incident_payload(event)
        event = incident_payload or {}

        # This will be the same for the same incident
        original_incident_id = event.get("id")
        # https://github.com/keephq/keep/issues/4681
        if not original_incident_id:
            logger.warning(
                "No incident id found in the event",
                extra={
                    "event": event,
                },
            )
            return []

        tenant_id = (
            getattr(getattr(provider_instance, "context_manager", None), "tenant_id", None)
            if provider_instance
            else None
        )
        provider_id = getattr(provider_instance, "provider_id", None) if provider_instance else None

        incident_key = event.get("incident_key")
        incident_key_source = "webhook" if incident_key else None
        api_incident: dict | None = None
        if (
            not incident_key
            and provider_instance
            and hasattr(provider_instance, "_get_specific_incident")
        ):
            try:
                response = provider_instance._get_specific_incident(original_incident_id)
                if isinstance(response, dict) and isinstance(response.get("incident"), dict):
                    api_incident = response["incident"]
                    incident_key = api_incident.get("incident_key") or incident_key
                    if incident_key:
                        incident_key_source = "api"
                        logger.info(
                            "PagerDuty incident webhook: loaded incident_key from PagerDuty API",
                            extra={
                                "tenant_id": tenant_id,
                                "provider_id": provider_id,
                                "pagerduty_incident_id": original_incident_id,
                                "incident_key": incident_key,
                                "event_type": event_type,
                            },
                        )
            except Exception:
                logger.exception(
                    "PagerDuty incident webhook: failed fetching incident from PagerDuty API",
                    extra={
                        "tenant_id": tenant_id,
                        "provider_id": provider_id,
                        "pagerduty_incident_id": original_incident_id,
                        "event_type": event_type,
                    },
                )
        if isinstance(incident_key, str) and incident_key.startswith(
            KEEP_PD_ALERT_INCIDENT_KEY_PREFIX
        ):
            logger.info(
                "Skipping Keep-originated PagerDuty alert incident",
                extra={
                    "tenant_id": tenant_id,
                    "provider_id": provider_id,
                    "pagerduty_incident_id": original_incident_id,
                    "incident_key": incident_key,
                    "event_type": event_type,
                    "incident_key_source": incident_key_source,
                },
            )
            return []

        def _extract_keep_incident_id_from_details(raw_details: typing.Any) -> uuid.UUID | None:
            if not raw_details:
                return None
            details = raw_details if isinstance(raw_details, str) else str(raw_details)
            for pattern in (
                r"/incidents/("
                r"[0-9a-fA-F]{8}-"
                r"[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{12}"
                r")",
                r"Keep Incident ID:\s*("
                r"[0-9a-fA-F]{8}-"
                r"[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{12}"
                r")",
            ):
                match = re.search(pattern, details, flags=re.IGNORECASE)
                if not match:
                    continue
                try:
                    return uuid.UUID(match.group(1))
                except Exception:
                    continue
            return None

        keep_incident_id: uuid.UUID | None = None
        keep_origin_detected_by: str | None = None

        if isinstance(incident_key, str):
            try:
                keep_incident_id = uuid.UUID(incident_key)
                keep_origin_detected_by = "incident_key_uuid"
            except (ValueError, AttributeError, TypeError):
                keep_incident_id = None

        if keep_incident_id is None:
            body = event.get("body")
            details = None
            details_source = None
            if isinstance(body, dict):
                details = body.get("details") or body.get("detail") or body.get("summary")
                if details:
                    details_source = "webhook_body"
            if not details and isinstance(api_incident, dict):
                api_body = api_incident.get("body")
                if isinstance(api_body, dict):
                    details = (
                        api_body.get("details")
                        or api_body.get("detail")
                        or api_body.get("summary")
                    )
                    if details:
                        details_source = "api_body"
            keep_incident_id = _extract_keep_incident_id_from_details(details)
            if keep_incident_id is not None:
                keep_origin_detected_by = (
                    "body_details_keep_url"
                    if details_source == "webhook_body"
                    else "api_body_details_keep_url"
                )

        if keep_incident_id is not None:
            if not tenant_id:
                logger.warning(
                    "PagerDuty incident webhook: Keep incident id detected but tenant_id is missing; skipping",
                    extra={
                        "tenant_id": tenant_id,
                        "provider_id": provider_id,
                        "pagerduty_incident_id": original_incident_id,
                        "incident_key": incident_key,
                        "incident_key_source": incident_key_source,
                        "event_type": event_type,
                        "keep_incident_id": str(keep_incident_id),
                        "detected_by": keep_origin_detected_by,
                    },
                )
                return []

            try:
                from keep.api.core.db import get_incident_by_id

                keep_incident = get_incident_by_id(
                    tenant_id=tenant_id,
                    incident_id=keep_incident_id,
                )
            except Exception:
                logger.exception(
                    "PagerDuty incident webhook: failed loading Keep incident",
                    extra={
                        "tenant_id": tenant_id,
                        "provider_id": provider_id,
                        "pagerduty_incident_id": original_incident_id,
                        "incident_key": incident_key,
                        "incident_key_source": incident_key_source,
                        "event_type": event_type,
                        "keep_incident_id": str(keep_incident_id),
                        "detected_by": keep_origin_detected_by,
                    },
                )
                return []

            if not keep_incident:
                logger.info(
                    "PagerDuty incident webhook: Keep incident not found; ignoring event",
                    extra={
                        "tenant_id": tenant_id,
                        "provider_id": provider_id,
                        "pagerduty_incident_id": original_incident_id,
                        "incident_key": incident_key,
                        "incident_key_source": incident_key_source,
                        "event_type": event_type,
                        "keep_incident_id": str(keep_incident_id),
                        "detected_by": keep_origin_detected_by,
                    },
                )
                return []

            pagerduty_status = PagerdutyProvider.INCIDENT_STATUS_MAP.get(
                event.get("status", "firing"), IncidentStatus.FIRING
            )
            keep_status_value = str(getattr(keep_incident, "status", "") or "")
            if keep_status_value == pagerduty_status.value:
                logger.info(
                    "PagerDuty incident webhook: Keep incident status already matches; skipping",
                    extra={
                        "tenant_id": tenant_id,
                        "provider_id": provider_id,
                        "pagerduty_incident_id": original_incident_id,
                        "incident_key": incident_key,
                        "incident_key_source": incident_key_source,
                        "event_type": event_type,
                        "keep_incident_id": str(keep_incident_id),
                        "detected_by": keep_origin_detected_by,
                        "keep_status": keep_status_value,
                        "pagerduty_status": pagerduty_status.value,
                    },
                )
                return []

            keep_incident_dto = IncidentDto.from_db_incident(keep_incident)
            keep_incident_dto.status = pagerduty_status
            keep_incident_dto._alerts = []
            if pagerduty_status == IncidentStatus.RESOLVED:
                keep_incident_dto.end_time = datetime.datetime.now(tz=datetime.timezone.utc)

            logger.info(
                "PagerDuty incident webhook: syncing Keep incident status",
                extra={
                    "tenant_id": tenant_id,
                    "provider_id": provider_id,
                        "pagerduty_incident_id": original_incident_id,
                        "incident_key": incident_key,
                        "incident_key_source": incident_key_source,
                        "event_type": event_type,
                        "keep_incident_id": str(keep_incident_id),
                        "detected_by": keep_origin_detected_by,
                        "keep_status": keep_status_value,
                    "pagerduty_status": pagerduty_status.value,
                },
            )
            return keep_incident_dto

        incident_id = PagerdutyProvider._get_incident_id(original_incident_id)

        status = PagerdutyProvider.INCIDENT_STATUS_MAP.get(
            event.get("status", "firing"), IncidentStatus.FIRING
        )
        priority_summary = (event.get("priority", {}) or {}).get("summary", "P4")
        severity = PagerdutyProvider.INCIDENT_SEVERITIES_MAP.get(
            priority_summary, IncidentSeverity.INFO
        )
        service = event.pop("service", {}).get("summary", "unknown")

        created_at = _parse_datetime(message_created_on or event.get("created_at"))
        if not created_at:
            created_at = datetime.datetime.now(tz=datetime.timezone.utc)

        title = event.get("title")
        if not title:
            logger.warning(
                "No title found in the event",
                extra={
                    "event": event,
                },
            )
            return []

        return IncidentDto(
            id=incident_id,
            creation_time=created_at,
            user_generated_name=f'PD-{event.get("title", "unknown")}-{original_incident_id}',
            status=status,
            severity=severity,
            alert_sources=["pagerduty"],
            alerts_count=event.get("alert_counts", {}).get("all", 0),
            services=[service],
            is_predicted=False,
            is_candidate=False,
            # This is the reference to the incident in PagerDuty
            fingerprint=original_incident_id,
        )


if __name__ == "__main__":
    # Output debug messages
    import logging

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )
    # Load environment variables
    import os

    api_key = os.environ.get("PAGERDUTY_API_KEY")

    provider_config = {
        "authentication": {"api_key": api_key},
    }
    provider = ProvidersFactory.get_provider(
        context_manager=context_manager,
        provider_id="keep-pd",
        provider_type="pagerduty",
        provider_config=provider_config,
    )
    incidents = provider.get_incidents()
    print(len(incidents))
