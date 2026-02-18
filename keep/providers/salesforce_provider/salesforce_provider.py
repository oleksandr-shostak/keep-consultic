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

from keep.api.models.db.incident import IncidentSeverity, IncidentStatus
from keep.api.models.incident import IncidentDto
from keep.contextmanager.contextmanager import ContextManager
from keep.exceptions.provider_config_exception import ProviderConfigException
from keep.providers.base.base_provider import BaseIncidentProvider, BaseProvider
from keep.providers.models.provider_config import ProviderConfig, ProviderScope
from keep.validation.fields import HttpsUrl

logger = logging.getLogger(__name__)


@pydantic.dataclasses.dataclass
class SalesforceProviderAuthConfig:
    instance_url: HttpsUrl = dataclasses.field(
        metadata={
            "required": True,
            "description": "Salesforce instance URL",
            "hint": "https://your-domain.my.salesforce.com",
            "validation": "https_url",
        }
    )
    client_id: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Static client id for Salesforce integration",
            "sensitive": False,
        }
    )
    client_secret: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Static client secret for Salesforce integration",
            "sensitive": True,
        }
    )
    api_version: str = dataclasses.field(
        default="v61.0",
        metadata={
            "required": False,
            "description": "Salesforce REST API version",
            "sensitive": False,
        },
    )
    client_id_header: str = dataclasses.field(
        default="X-Client-Id",
        metadata={
            "required": False,
            "description": "Header name used for client id",
            "sensitive": False,
        },
    )
    client_secret_header: str = dataclasses.field(
        default="X-Client-Secret",
        metadata={
            "required": False,
            "description": "Header name used for client secret",
            "sensitive": False,
        },
    )
    timeout_seconds: int = dataclasses.field(
        default=30,
        metadata={
            "required": False,
            "description": "HTTP timeout for Salesforce requests",
            "sensitive": False,
        },
    )
    retry_max_attempts: int = dataclasses.field(
        default=2,
        metadata={
            "required": False,
            "description": "Number of retries for transient HTTP errors (429/5xx)",
            "sensitive": False,
        },
    )
    retry_backoff_seconds: float = dataclasses.field(
        default=0.5,
        metadata={
            "required": False,
            "description": "Initial retry backoff seconds for transient HTTP errors",
            "sensitive": False,
        },
    )
    allow_external_case_creation: bool = dataclasses.field(
        default=True,
        metadata={
            "required": False,
            "description": "Allow creating Keep incidents from external Salesforce cases",
            "sensitive": False,
        },
    )
    default_origin: str = dataclasses.field(
        default="Keep",
        metadata={
            "required": False,
            "description": "Default Salesforce Case Origin value",
            "sensitive": False,
        },
    )
    default_owner_id: str = dataclasses.field(
        default="",
        metadata={
            "required": False,
            "description": "Default Salesforce Case owner id",
            "sensitive": False,
        },
    )
    default_record_type_id: str = dataclasses.field(
        default="",
        metadata={
            "required": False,
            "description": "Default Salesforce Case record type id",
            "sensitive": False,
        },
    )
    ticket_creation_url: str = dataclasses.field(
        default="",
        metadata={
            "required": False,
            "description": "URL for creating cases in Salesforce (optional)",
            "sensitive": False,
        },
    )
    status_map_keep_to_salesforce: dict | str = dataclasses.field(
        default_factory=dict,
        metadata={
            "required": False,
            "description": "Optional override map for Keep->Salesforce statuses",
            "sensitive": False,
        },
    )
    status_map_salesforce_to_keep: dict | str = dataclasses.field(
        default_factory=dict,
        metadata={
            "required": False,
            "description": "Optional override map for Salesforce->Keep statuses",
            "sensitive": False,
        },
    )
    priority_map_keep_to_salesforce: dict | str = dataclasses.field(
        default_factory=dict,
        metadata={
            "required": False,
            "description": "Optional override map for Keep->Salesforce priorities",
            "sensitive": False,
        },
    )
    priority_map_salesforce_to_keep: dict | str = dataclasses.field(
        default_factory=dict,
        metadata={
            "required": False,
            "description": "Optional override map for Salesforce->Keep priorities",
            "sensitive": False,
        },
    )
    additional_headers: dict | str = dataclasses.field(
        default_factory=dict,
        metadata={
            "required": False,
            "description": "Optional static headers added to Salesforce API requests",
            "sensitive": True,
        },
    )
    webhook_setup_url: str = dataclasses.field(
        default="",
        metadata={
            "required": False,
            "description": "Optional Salesforce endpoint to auto-register Keep webhook",
            "sensitive": False,
        },
    )
    webhook_setup_headers: dict | str = dataclasses.field(
        default_factory=dict,
        metadata={
            "required": False,
            "description": "Optional headers for webhook_setup_url request",
            "sensitive": True,
        },
    )


class SalesforceProvider(BaseIncidentProvider):
    PROVIDER_DISPLAY_NAME = "Salesforce"
    PROVIDER_CATEGORY = ["CRM", "Incident Management"]
    PROVIDER_TAGS = ["ticketing", "incident", "data"]
    PROVIDER_COMING_SOON = False
    PROVIDER_SCOPES = [
        ProviderScope(
            name="case_read",
            description="Read Salesforce Cases",
            mandatory=True,
            alias="Case Read",
        ),
        ProviderScope(
            name="case_write",
            description="Write Salesforce Cases",
            mandatory=False,
            alias="Case Write",
        ),
    ]

    DEFAULT_KEEP_TO_SF_STATUS_MAP = {
        IncidentStatus.FIRING.value: "New",
        IncidentStatus.ACKNOWLEDGED.value: "Working",
        IncidentStatus.RESOLVED.value: "Closed",
    }
    DEFAULT_SF_TO_KEEP_STATUS_MAP = {
        "new": IncidentStatus.FIRING.value,
        "working": IncidentStatus.ACKNOWLEDGED.value,
        "in progress": IncidentStatus.ACKNOWLEDGED.value,
        "in_progress": IncidentStatus.ACKNOWLEDGED.value,
        "escalated": IncidentStatus.ACKNOWLEDGED.value,
        "closed": IncidentStatus.RESOLVED.value,
        "resolved": IncidentStatus.RESOLVED.value,
    }
    DEFAULT_KEEP_TO_SF_PRIORITY_MAP = {
        IncidentSeverity.CRITICAL.value: "High",
        IncidentSeverity.HIGH.value: "High",
        IncidentSeverity.WARNING.value: "Medium",
        IncidentSeverity.INFO.value: "Low",
        IncidentSeverity.LOW.value: "Low",
    }
    DEFAULT_SF_TO_KEEP_PRIORITY_MAP = {
        "critical": IncidentSeverity.CRITICAL.value,
        "urgent": IncidentSeverity.CRITICAL.value,
        "high": IncidentSeverity.HIGH.value,
        "medium": IncidentSeverity.WARNING.value,
        "low": IncidentSeverity.LOW.value,
    }
    DEFAULT_CASE_FIELDS = [
        "Id",
        "CaseNumber",
        "Subject",
        "Description",
        "Status",
        "Priority",
        "Origin",
        "OwnerId",
        "RecordTypeId",
        "Type",
        "CreatedDate",
        "LastModifiedDate",
        "Keep_Incident_Id__c",
        "Keep_Incident_Url__c",
        "Keep_Tenant_Id__c",
    ]

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)
        self.base_api_url = (
            f"{self.authentication_config.instance_url.rstrip('/')}"
            f"/services/data/{self.authentication_config.api_version.strip('/')}"
        )

    def validate_config(self):
        self.authentication_config = SalesforceProviderAuthConfig(
            **self.config.authentication
        )
        if (
            not self.authentication_config.instance_url
            or not self.authentication_config.client_id
            or not self.authentication_config.client_secret
        ):
            raise ProviderConfigException(
                "SalesforceProvider requires instance_url, client_id and client_secret",
                provider_id=self.provider_id,
            )

        self.keep_to_salesforce_status_map = self._build_mapping(
            self.DEFAULT_KEEP_TO_SF_STATUS_MAP,
            self.authentication_config.status_map_keep_to_salesforce,
        )
        self.salesforce_to_keep_status_map = self._build_mapping(
            self.DEFAULT_SF_TO_KEEP_STATUS_MAP,
            self.authentication_config.status_map_salesforce_to_keep,
        )
        self.keep_to_salesforce_priority_map = self._build_mapping(
            self.DEFAULT_KEEP_TO_SF_PRIORITY_MAP,
            self.authentication_config.priority_map_keep_to_salesforce,
        )
        self.salesforce_to_keep_priority_map = self._build_mapping(
            self.DEFAULT_SF_TO_KEEP_PRIORITY_MAP,
            self.authentication_config.priority_map_salesforce_to_keep,
        )

    @staticmethod
    def _is_truthy(value: typing.Any) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "t", "yes", "y", "on"}
        return bool(value)

    @staticmethod
    def _parse_dict_like(value: dict | str | None) -> dict:
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return {}
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return {}
        return {}

    def _build_mapping(
        self, defaults: dict[str, str], custom: dict | str | None
    ) -> dict[str, str]:
        mapping = {str(k).strip().lower(): str(v).strip() for k, v in defaults.items()}
        custom_map = self._parse_dict_like(custom)
        for key, value in custom_map.items():
            if key is None or value is None:
                continue
            mapping[str(key).strip().lower()] = str(value).strip()
        return mapping

    def _get_headers(self, extra: dict | None = None) -> dict:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            self.authentication_config.client_id_header: self.authentication_config.client_id,
            self.authentication_config.client_secret_header: self.authentication_config.client_secret,
        }
        headers.update(self._parse_dict_like(self.authentication_config.additional_headers))
        if extra:
            headers.update(extra)
        return headers

    def _extract_error_message(self, response: requests.Response) -> str:
        try:
            payload = response.json()
            if isinstance(payload, list):
                return "; ".join(
                    str(item.get("message", item)) if isinstance(item, dict) else str(item)
                    for item in payload
                )
            if isinstance(payload, dict):
                if isinstance(payload.get("errors"), list):
                    return "; ".join(str(err) for err in payload["errors"])
                if payload.get("message"):
                    return str(payload["message"])
                if payload.get("error_description"):
                    return str(payload["error_description"])
                return str(payload)
        except Exception:
            pass
        return f"HTTP {response.status_code}: {response.text[:500]}"

    def _request(
        self,
        method: str,
        path_or_url: str,
        *,
        params: dict | None = None,
        json_payload: dict | None = None,
        allow_404: bool = False,
        extra_headers: dict | None = None,
    ) -> tuple[int, dict | list | None]:
        url = (
            path_or_url
            if path_or_url.startswith("http://") or path_or_url.startswith("https://")
            else f"{self.base_api_url}/{path_or_url.lstrip('/')}"
        )
        retry_max_attempts = max(
            int(getattr(self.authentication_config, "retry_max_attempts", 0) or 0), 0
        )
        retry_backoff_seconds = max(
            float(getattr(self.authentication_config, "retry_backoff_seconds", 0.5) or 0.5),
            0.1,
        )
        attempt = 0
        while True:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=self._get_headers(extra_headers),
                params=params,
                json=json_payload,
                timeout=self.authentication_config.timeout_seconds,
            )
            if allow_404 and response.status_code == 404:
                return response.status_code, None

            should_retry = response.status_code == 429 or 500 <= response.status_code < 600
            if should_retry and attempt < retry_max_attempts:
                retry_after_header = (response.headers or {}).get("Retry-After")
                retry_delay = None
                if retry_after_header:
                    try:
                        retry_delay = float(retry_after_header)
                    except (TypeError, ValueError):
                        retry_delay = None
                if retry_delay is None:
                    retry_delay = retry_backoff_seconds * (2**attempt)
                retry_delay = min(max(retry_delay, 0.1), 60.0)
                self.logger.warning(
                    "Salesforce API transient error, retrying request",
                    extra={
                        "provider_id": self.provider_id,
                        "url": url,
                        "method": method.upper(),
                        "status_code": response.status_code,
                        "attempt": attempt + 1,
                        "max_attempts": retry_max_attempts,
                        "retry_delay_seconds": retry_delay,
                    },
                )
                attempt += 1
                time.sleep(retry_delay)
                continue

            try:
                response.raise_for_status()
            except Exception as e:
                raise Exception(self._extract_error_message(response)) from e

            if response.status_code == 204 or not response.text:
                return response.status_code, {}

            try:
                payload = response.json()
            except Exception:
                payload = {"raw": response.text}
            return response.status_code, payload

    @staticmethod
    def _parse_datetime(value: typing.Any) -> datetime.datetime | None:
        if value is None or value == "":
            return None
        if isinstance(value, datetime.datetime):
            return value
        if isinstance(value, (int, float)):
            return datetime.datetime.fromtimestamp(float(value), tz=datetime.timezone.utc)
        if isinstance(value, str):
            normalized = value.strip()
            if not normalized:
                return None
            if normalized.endswith("Z"):
                normalized = normalized[:-1] + "+00:00"
            try:
                parsed = datetime.datetime.fromisoformat(normalized)
            except ValueError:
                for fmt in (
                    "%Y-%m-%dT%H:%M:%S.%f%z",
                    "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S",
                ):
                    try:
                        parsed = datetime.datetime.strptime(value, fmt)
                        break
                    except ValueError:
                        parsed = None
                if parsed is None:
                    return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            return parsed
        return None

    @staticmethod
    def _get_dict_value_case_insensitive(data: dict, *keys: str) -> typing.Any:
        if not isinstance(data, dict):
            return None
        lowered = {str(k).lower(): v for k, v in data.items()}
        for key in keys:
            if key in data:
                return data[key]
            value = lowered.get(str(key).lower())
            if value is not None:
                return value
        return None

    @staticmethod
    def _coerce_uuid(value: typing.Any) -> uuid.UUID | None:
        if value is None:
            return None
        try:
            return uuid.UUID(str(value))
        except Exception:
            return None

    @staticmethod
    def _to_text_value(value: typing.Any) -> str:
        if value is None:
            return ""
        if hasattr(value, "value"):
            try:
                return str(value.value)
            except Exception:
                pass
        return str(value)

    def _map_keep_status_to_salesforce(self, value: str) -> str:
        raw = self._to_text_value(value).strip()
        if not raw:
            return ""
        normalized = raw.lower()
        return self.keep_to_salesforce_status_map.get(normalized, raw)

    def _map_salesforce_status_to_keep(self, value: str) -> IncidentStatus:
        normalized = str(value or "").strip().lower()
        mapped = self.salesforce_to_keep_status_map.get(normalized, IncidentStatus.FIRING.value)
        try:
            return IncidentStatus(mapped)
        except ValueError:
            return IncidentStatus.FIRING

    def _map_keep_priority_to_salesforce(self, value: str) -> str:
        raw = self._to_text_value(value).strip()
        if not raw:
            return ""
        normalized = raw.lower()
        return self.keep_to_salesforce_priority_map.get(normalized, raw)

    def _map_salesforce_priority_to_keep(self, value: str) -> IncidentSeverity:
        normalized = str(value or "").strip().lower()
        mapped = self.salesforce_to_keep_priority_map.get(normalized, IncidentSeverity.INFO.value)
        try:
            return IncidentSeverity(mapped)
        except ValueError:
            return IncidentSeverity.INFO

    def _extract_keep_ui_url(self) -> str | None:
        env_url = os.environ.get("KEEP_URL") or os.environ.get("KEEP_UI_URL")
        if env_url:
            return env_url.rstrip("/")
        api_url = getattr(self.context_manager, "api_url", None)
        if not api_url:
            return None
        parsed = urllib.parse.urlparse(api_url)
        if not parsed.scheme or not parsed.hostname:
            return None
        host = parsed.hostname
        if host.startswith("api."):
            host = host[len("api.") :]
        netloc = host
        if parsed.port in {8080, 8000}:
            netloc = f"{host}:3000"
        return f"{parsed.scheme}://{netloc}"

    def _resolve_incident_context_value(self, key: str, default: typing.Any = None) -> typing.Any:
        incident = getattr(self.context_manager, "incident_context", None)
        if incident is None:
            return default
        if isinstance(incident, dict):
            return incident.get(key, default)
        return getattr(incident, key, default)

    def _resolve_keep_incident_id(self, keep_incident_id: str = "", **kwargs) -> str:
        if keep_incident_id:
            return str(keep_incident_id)
        if kwargs.get("incident_id"):
            return str(kwargs["incident_id"])
        context_id = self._resolve_incident_context_value("id")
        if context_id:
            return str(context_id)
        return ""

    def _normalize_case_result(self, case: dict | None, fallback_case_id: str = "") -> dict:
        case = case if isinstance(case, dict) else {}
        case_id = self._get_dict_value_case_insensitive(case, "Id", "id") or fallback_case_id
        case_number = self._get_dict_value_case_insensitive(case, "CaseNumber", "number")
        status = self._get_dict_value_case_insensitive(case, "Status", "status")
        priority = self._get_dict_value_case_insensitive(case, "Priority", "priority")
        url = (
            f"{self.authentication_config.instance_url.rstrip('/')}/{case_id}"
            if case_id
            else ""
        )
        return {
            "id": case_id,
            "number": case_number,
            "url": url,
            "status": status,
            "priority": priority,
            "keep_incident_id": self._get_dict_value_case_insensitive(
                case, "Keep_Incident_Id__c", "KeepIncidentId"
            ),
        }

    def _build_case_payload(
        self,
        *,
        subject: str = "",
        description: str = "",
        keep_incident_id: str = "",
        status: str = "",
        priority: str = "",
        origin: str = "",
        owner_id: str = "",
        record_type_id: str = "",
        case_type: str = "",
        fields: dict | None = None,
    ) -> dict:
        payload: dict = {}
        if subject:
            payload["Subject"] = str(subject)
        if description:
            payload["Description"] = str(description)

        if status:
            payload["Status"] = self._map_keep_status_to_salesforce(str(status))
        if priority:
            payload["Priority"] = self._map_keep_priority_to_salesforce(str(priority))

        if origin:
            payload["Origin"] = origin

        resolved_owner = owner_id or self.authentication_config.default_owner_id
        if resolved_owner:
            payload["OwnerId"] = resolved_owner

        resolved_record_type = (
            record_type_id or self.authentication_config.default_record_type_id
        )
        if resolved_record_type:
            payload["RecordTypeId"] = resolved_record_type

        if case_type:
            payload["Type"] = str(case_type)

        if keep_incident_id:
            payload["Keep_Incident_Id__c"] = str(keep_incident_id)
            keep_ui_url = self._extract_keep_ui_url()
            if keep_ui_url:
                payload["Keep_Incident_Url__c"] = (
                    f"{keep_ui_url}/incidents/{keep_incident_id}"
                )
            payload["Keep_Tenant_Id__c"] = self.context_manager.tenant_id

        if fields:
            payload.update(fields)
        return payload

    def _get_case_by_id(self, case_id: str) -> dict | None:
        if not case_id:
            return None
        _, payload = self._request(
            "GET",
            f"sobjects/Case/{urllib.parse.quote(str(case_id), safe='')}",
            allow_404=True,
        )
        return payload if isinstance(payload, dict) else None

    def _get_case_by_keep_incident_id(self, keep_incident_id: str) -> dict | None:
        if not keep_incident_id:
            return None
        _, payload = self._request(
            "GET",
            "sobjects/Case/Keep_Incident_Id__c/"
            + urllib.parse.quote(str(keep_incident_id), safe=""),
            allow_404=True,
        )
        return payload if isinstance(payload, dict) else None

    def _create_case(self, payload: dict) -> str:
        endpoint = self.authentication_config.ticket_creation_url or "sobjects/Case"
        _, response = self._request("POST", endpoint, json_payload=payload)
        if isinstance(response, dict):
            case_id = response.get("id") or response.get("Id")
            if case_id:
                return str(case_id)
        raise Exception("Salesforce create case response does not include case id")

    def _update_case(self, case_id: str, payload: dict) -> None:
        self._request(
            "PATCH",
            f"sobjects/Case/{urllib.parse.quote(str(case_id), safe='')}",
            json_payload=payload,
        )

    def _upsert_case_by_keep_incident_id(
        self, keep_incident_id: str, payload: dict
    ) -> tuple[str, bool]:
        status_code, response = self._request(
            "PATCH",
            "sobjects/Case/Keep_Incident_Id__c/"
            + urllib.parse.quote(str(keep_incident_id), safe=""),
            json_payload=payload,
        )
        created = status_code == 201
        if isinstance(response, dict):
            response_case_id = response.get("id") or response.get("Id")
            if response_case_id:
                return str(response_case_id), created
        case = self._get_case_by_keep_incident_id(keep_incident_id)
        case_id = self._get_dict_value_case_insensitive(case or {}, "Id", "id")
        if case_id:
            return str(case_id), created
        raise Exception(
            f"Salesforce upsert succeeded but case id was not returned (keep_incident_id={keep_incident_id})"
        )

    def _create_case_comment(self, case_id: str, comment: str) -> None:
        if not case_id or not comment:
            return
        self._request(
            "POST",
            "sobjects/CaseComment",
            json_payload={"ParentId": case_id, "CommentBody": comment},
        )

    def _query_soql(self, soql: str) -> dict:
        _, payload = self._request("GET", "query", params={"q": soql})
        if not isinstance(payload, dict):
            return {"records": [], "totalSize": 0, "done": True}
        return payload

    def _format_soql_results(self, soql: str, payload: dict | None) -> dict:
        payload = payload if isinstance(payload, dict) else {}
        records = payload.get("records", [])
        records = records if isinstance(records, list) else []
        return {
            "cases": [self._normalize_case_result(record) for record in records],
            "total_size": payload.get("totalSize", len(records)),
            "done": payload.get("done", True),
            "soql": soql,
        }

    def _coerce_fields_for_query(self, fields: list[str] | str | None) -> list[str]:
        if fields is None:
            return list(self.DEFAULT_CASE_FIELDS)
        if isinstance(fields, list):
            parsed = [str(field).strip() for field in fields if str(field).strip()]
            return parsed if parsed else list(self.DEFAULT_CASE_FIELDS)
        if isinstance(fields, str):
            stripped = fields.strip()
            if not stripped:
                return list(self.DEFAULT_CASE_FIELDS)
            if stripped.startswith("[") and stripped.endswith("]"):
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, list):
                        return [
                            str(field).strip()
                            for field in parsed
                            if str(field).strip()
                        ] or list(self.DEFAULT_CASE_FIELDS)
                except Exception:
                    pass
            return [field.strip() for field in stripped.split(",") if field.strip()]
        return list(self.DEFAULT_CASE_FIELDS)

    def validate_scopes(self) -> dict[str, bool | str]:
        scopes: dict[str, bool | str] = {}
        try:
            self._query_soql("SELECT Id FROM Case LIMIT 1")
            scopes["case_read"] = True
        except Exception as e:
            scopes["case_read"] = str(e)
            scopes["case_write"] = "Skipped due to failed read validation"
            return scopes

        try:
            self._request("GET", "sobjects/Case/describe")
            scopes["case_write"] = True
        except Exception as e:
            scopes["case_write"] = str(e)
        return scopes

    def setup_incident_webhook(
        self,
        tenant_id: str,
        keep_api_url: str,
        api_key: str,
        setup_alerts: bool = True,
    ) -> dict | None:
        if not self.authentication_config.webhook_setup_url:
            self.logger.info(
                "Salesforce incident webhook setup requires manual configuration",
                extra={
                    "provider_id": self.provider_id,
                    "tenant_id": tenant_id,
                    "keep_api_url": keep_api_url,
                    "has_webhook_api_key": bool(api_key),
                },
            )
            return None

        payload = {
            "keep_webhook_url": keep_api_url,
            "keep_webhook_api_key": api_key,
            "provider_id": self.provider_id,
            "tenant_id": tenant_id,
            "setup_alerts": setup_alerts,
        }
        status_code, _ = self._request(
            "POST",
            self.authentication_config.webhook_setup_url,
            json_payload=payload,
            extra_headers=self._parse_dict_like(
                self.authentication_config.webhook_setup_headers
            ),
        )
        self.logger.info(
            "Salesforce webhook auto-setup request completed",
            extra={
                "provider_id": self.provider_id,
                "tenant_id": tenant_id,
                "status_code": status_code,
            },
        )
        return None

    def _notify(
        self,
        subject: str = "",
        description: str = "",
        case_id: str = "",
        keep_incident_id: str = "",
        status: str = "",
        priority: str = "",
        origin: str = "",
        owner_id: str = "",
        record_type_id: str = "",
        case_type: str = "",
        mode: typing.Literal["upsert", "create", "update"] = "upsert",
        fields: dict | str | None = None,
        add_comment: str = "",
        **kwargs: dict,
    ) -> dict:
        keep_incident_id = self._resolve_keep_incident_id(keep_incident_id, **kwargs)
        subject = (
            subject
            or kwargs.get("title", "")
            or str(self._resolve_incident_context_value("name", ""))
        )
        if not subject and keep_incident_id:
            subject = f"Keep incident {keep_incident_id}"

        if not description:
            body = kwargs.get("body") or kwargs.get("alert_body")
            if isinstance(body, dict):
                description = str(
                    body.get("details")
                    or body.get("description")
                    or body.get("summary")
                    or ""
                )
            elif body:
                description = str(body)

        parsed_fields = self._parse_dict_like(fields)
        mode_normalized = str(mode or "upsert").strip().lower()
        if mode_normalized not in {"upsert", "create", "update"}:
            raise Exception(f"Unknown Salesforce notify mode: {mode}")
        resolved_origin = origin
        # Avoid overriding existing Case Origin on update/upsert unless explicitly provided.
        if not resolved_origin and mode_normalized == "create":
            resolved_origin = self.authentication_config.default_origin
        resolved_status = (
            status
            if status not in (None, "")
            else self._resolve_incident_context_value("status", "")
        )
        resolved_priority = (
            priority
            if priority not in (None, "")
            else self._resolve_incident_context_value("severity", "")
        )

        payload = self._build_case_payload(
            subject=subject,
            description=description,
            keep_incident_id=keep_incident_id,
            status=self._to_text_value(resolved_status),
            priority=self._to_text_value(resolved_priority),
            origin=resolved_origin,
            owner_id=owner_id,
            record_type_id=record_type_id,
            case_type=case_type,
            fields=parsed_fields,
        )

        if not payload and mode in {"create", "update", "upsert"}:
            raise Exception("Salesforce notify payload is empty")

        existing = False
        action = mode_normalized
        created = False
        resolved_case_id = str(case_id or kwargs.get("salesforce_case_id") or "")

        if mode_normalized == "create":
            resolved_case_id = self._create_case(payload)
            created = True
        elif mode_normalized == "update":
            if not resolved_case_id and keep_incident_id:
                existing_case = self._get_case_by_keep_incident_id(keep_incident_id)
                resolved_case_id = str(
                    self._get_dict_value_case_insensitive(existing_case or {}, "Id", "id")
                    or ""
                )
            if not resolved_case_id:
                raise Exception(
                    "Salesforce update mode requires case_id or existing case linked by keep_incident_id"
                )
            self._update_case(resolved_case_id, payload)
            existing = True
        elif mode_normalized == "upsert":
            if resolved_case_id:
                self._update_case(resolved_case_id, payload)
                existing = True
            elif keep_incident_id:
                resolved_case_id, created = self._upsert_case_by_keep_incident_id(
                    keep_incident_id, payload
                )
                existing = not created
            else:
                resolved_case_id = self._create_case(payload)
                created = True
                existing = False
            action = "upsert"
        else:
            raise Exception(f"Unknown Salesforce notify mode: {mode}")

        if add_comment and resolved_case_id:
            self._create_case_comment(resolved_case_id, add_comment)

        case = self._get_case_by_id(resolved_case_id) if resolved_case_id else None
        if not case and keep_incident_id:
            case = self._get_case_by_keep_incident_id(keep_incident_id)

        return {
            "case": self._normalize_case_result(case, fallback_case_id=resolved_case_id),
            "existing": existing,
            "created": created,
            "action": action,
            "synced_from": "keep",
        }

    def _query(
        self,
        case_id: str = "",
        keep_incident_id: str = "",
        soql: str = "",
        limit: int = 100,
        fields: list[str] | str | None = None,
        **kwargs: dict,
    ) -> dict:
        if case_id:
            case = self._get_case_by_id(case_id)
            return {"case": self._normalize_case_result(case, fallback_case_id=case_id)}

        if keep_incident_id:
            case = self._get_case_by_keep_incident_id(keep_incident_id)
            if not case:
                return {"case": None}
            return {"case": self._normalize_case_result(case)}

        if soql:
            payload = self._query_soql(soql)
            return self._format_soql_results(soql, payload)

        selected_fields = self._coerce_fields_for_query(fields)
        safe_limit = max(min(int(limit), 2000), 1)
        soql = (
            f"SELECT {', '.join(selected_fields)} "
            "FROM Case "
            "WHERE Keep_Incident_Id__c != null "
            "ORDER BY LastModifiedDate DESC "
            f"LIMIT {safe_limit}"
        )
        return self._format_soql_results(soql, self._query_soql(soql))

    def _get_linked_cases_raw(self, limit: int = 200) -> list[dict]:
        query_fields = [
            "Id",
            "Status",
            "Priority",
            "Keep_Incident_Id__c",
            "LastModifiedDate",
        ]
        safe_limit = max(min(int(limit), 2000), 1)
        soql = (
            f"SELECT {', '.join(query_fields)} "
            "FROM Case "
            "WHERE Keep_Incident_Id__c != null "
            "ORDER BY LastModifiedDate DESC "
            f"LIMIT {safe_limit}"
        )
        payload = self._query_soql(soql)
        records = payload.get("records", [])
        return records if isinstance(records, list) else []

    def _get_incidents(self) -> list[IncidentDto]:
        from keep.api.core.db import get_incident_by_id

        raw_cases = self._get_linked_cases_raw()
        incidents: list[IncidentDto] = []
        skipped_invalid_keep_id = 0
        skipped_missing_keep_incident = 0
        skipped_unchanged_status = 0
        status_updates = 0

        for case in raw_cases:
            if not isinstance(case, dict):
                skipped_invalid_keep_id += 1
                continue

            keep_incident_id_raw = self._get_dict_value_case_insensitive(
                case, "Keep_Incident_Id__c", "KeepIncidentId"
            )
            keep_incident_id = self._coerce_uuid(keep_incident_id_raw)
            if not keep_incident_id:
                skipped_invalid_keep_id += 1
                continue

            keep_incident = get_incident_by_id(
                tenant_id=self.context_manager.tenant_id, incident_id=keep_incident_id
            )
            if not keep_incident:
                skipped_missing_keep_incident += 1
                continue

            salesforce_status = self._map_salesforce_status_to_keep(
                str(self._get_dict_value_case_insensitive(case, "Status", "status") or "")
            )
            keep_status = str(getattr(keep_incident, "status", "") or "")
            if keep_status == salesforce_status.value:
                skipped_unchanged_status += 1
                continue

            incident_dto = IncidentDto.from_db_incident(keep_incident)
            incident_dto.status = salesforce_status
            incident_dto._alerts = []
            incident_dto.status_source = "salesforce"
            modified = self._parse_datetime(
                self._get_dict_value_case_insensitive(
                    case, "LastModifiedDate", "last_modified_date"
                )
            )
            if modified:
                incident_dto.status_changed_at = modified
            if salesforce_status == IncidentStatus.RESOLVED:
                incident_dto.end_time = datetime.datetime.now(tz=datetime.timezone.utc)

            incidents.append(incident_dto)
            status_updates += 1

        if status_updates:
            self.logger.info(
                "Salesforce incident pull: summary",
                extra={
                    "provider_id": self.provider_id,
                    "tenant_id": self.context_manager.tenant_id,
                    "raw_cases": len(raw_cases),
                    "status_updates": status_updates,
                    "skipped_invalid_keep_id": skipped_invalid_keep_id,
                    "skipped_missing_keep_incident": skipped_missing_keep_incident,
                    "skipped_unchanged_status": skipped_unchanged_status,
                },
            )

        return incidents

    @staticmethod
    def _get_incident_id(case_id: str) -> uuid.UUID:
        md5 = hashlib.md5()
        md5.update(case_id.encode("utf-8"))
        return uuid.UUID(md5.hexdigest())

    @staticmethod
    def _extract_case_payload(raw_event: dict) -> dict | None:
        if not isinstance(raw_event, dict):
            return None
        if isinstance(raw_event.get("case"), dict):
            return raw_event.get("case")
        if isinstance(raw_event.get("Case"), dict):
            return raw_event.get("Case")
        payload = raw_event.get("payload")
        if isinstance(payload, dict):
            if isinstance(payload.get("case"), dict):
                return payload.get("case")
            if isinstance(payload.get("Case"), dict):
                return payload.get("Case")
        raw_case_id = SalesforceProvider._get_dict_value_case_insensitive(
            raw_event, "Id", "id"
        )
        raw_case_status = SalesforceProvider._get_dict_value_case_insensitive(
            raw_event, "Status", "status"
        )
        if raw_case_id not in (None, "") and raw_case_status not in (None, ""):
            return raw_event
        return None

    @staticmethod
    def _normalize_actor(raw_event: dict) -> dict:
        if not isinstance(raw_event, dict):
            return {}
        actor = raw_event.get("actor")
        if not isinstance(actor, dict):
            actor = raw_event.get("Actor") if isinstance(raw_event.get("Actor"), dict) else {}
        if not isinstance(actor, dict):
            return {}
        return {
            "id": SalesforceProvider._get_dict_value_case_insensitive(actor, "Id", "id"),
            "email": SalesforceProvider._get_dict_value_case_insensitive(
                actor, "Email", "email"
            ),
            "name": SalesforceProvider._get_dict_value_case_insensitive(
                actor, "Name", "name"
            ),
        }

    @staticmethod
    def _actor_tokens(values: list[typing.Any]) -> set[str]:
        tokens: set[str] = set()
        for value in values:
            if value is None:
                continue
            raw = str(value).strip().lower()
            if not raw:
                continue
            tokens.add(raw)
            canonical = re.sub(r"[^a-z0-9]+", "", raw)
            if canonical:
                tokens.add(canonical)
            if "@" in raw:
                local = raw.split("@", 1)[0]
                tokens.add(local)
                local_canon = re.sub(r"[^a-z0-9]+", "", local)
                if local_canon:
                    tokens.add(local_canon)
        return tokens

    @staticmethod
    def _get_status_map(provider_instance: BaseProvider | None = None) -> dict[str, str]:
        if provider_instance and hasattr(provider_instance, "salesforce_to_keep_status_map"):
            try:
                mapping = getattr(provider_instance, "salesforce_to_keep_status_map")
                if isinstance(mapping, dict):
                    return {str(k).strip().lower(): str(v).strip() for k, v in mapping.items()}
            except Exception:
                pass
        return SalesforceProvider.DEFAULT_SF_TO_KEEP_STATUS_MAP

    @staticmethod
    def _get_priority_map(provider_instance: BaseProvider | None = None) -> dict[str, str]:
        if provider_instance and hasattr(provider_instance, "salesforce_to_keep_priority_map"):
            try:
                mapping = getattr(provider_instance, "salesforce_to_keep_priority_map")
                if isinstance(mapping, dict):
                    return {str(k).strip().lower(): str(v).strip() for k, v in mapping.items()}
            except Exception:
                pass
        return SalesforceProvider.DEFAULT_SF_TO_KEEP_PRIORITY_MAP

    @staticmethod
    def _format_incident(
        event: dict, provider_instance: BaseProvider | None = None
    ) -> IncidentDto | list[IncidentDto]:
        raw_event = event if isinstance(event, dict) else {}
        case = SalesforceProvider._extract_case_payload(raw_event)
        if not case:
            return []

        case_id = SalesforceProvider._get_dict_value_case_insensitive(case, "Id", "id")
        if not case_id:
            logger.warning("Salesforce incident webhook: missing case id")
            return []

        status_map = SalesforceProvider._get_status_map(provider_instance)
        sf_status_raw = SalesforceProvider._get_dict_value_case_insensitive(
            case, "Status", "status"
        )
        mapped_status = status_map.get(
            str(sf_status_raw or "").strip().lower(), IncidentStatus.FIRING.value
        )
        try:
            keep_status = IncidentStatus(mapped_status)
        except ValueError:
            keep_status = IncidentStatus.FIRING

        priority_map = SalesforceProvider._get_priority_map(provider_instance)
        sf_priority_raw = SalesforceProvider._get_dict_value_case_insensitive(
            case, "Priority", "priority"
        )
        mapped_priority = priority_map.get(
            str(sf_priority_raw or "").strip().lower(), IncidentSeverity.INFO.value
        )
        try:
            keep_severity = IncidentSeverity(mapped_priority)
        except ValueError:
            keep_severity = IncidentSeverity.INFO

        event_time = SalesforceProvider._parse_datetime(
            SalesforceProvider._get_dict_value_case_insensitive(
                raw_event, "occurred_at", "OccurredAt", "event_time"
            )
            or SalesforceProvider._get_dict_value_case_insensitive(
                case, "LastModifiedDate", "lastModifiedDate"
            )
            or SalesforceProvider._get_dict_value_case_insensitive(
                case, "CreatedDate", "createdDate"
            )
        )
        actor = SalesforceProvider._normalize_actor(raw_event)
        actor_display = actor.get("email") or actor.get("name")

        keep_incident_id_raw = SalesforceProvider._get_dict_value_case_insensitive(
            case, "Keep_Incident_Id__c", "KeepIncidentId"
        ) or SalesforceProvider._get_dict_value_case_insensitive(
            raw_event, "keep_incident_id", "keepIncidentId"
        )
        keep_incident_uuid = SalesforceProvider._coerce_uuid(keep_incident_id_raw)

        allow_external = True
        tenant_id = None
        if provider_instance and hasattr(provider_instance, "context_manager"):
            tenant_id = getattr(provider_instance.context_manager, "tenant_id", None)
        if provider_instance and hasattr(provider_instance, "authentication_config"):
            allow_external = SalesforceProvider._is_truthy(
                getattr(
                    provider_instance.authentication_config,
                    "allow_external_case_creation",
                    True,
                )
            )

        if keep_incident_uuid and tenant_id and provider_instance:
            try:
                from keep.api.core.db import get_incident_by_id
            except Exception:
                logger.exception(
                    "Salesforce incident webhook: failed importing DB helpers"
                )
                return []

            keep_incident = get_incident_by_id(
                tenant_id=tenant_id, incident_id=keep_incident_uuid
            )
            if keep_incident:
                keep_status_value = str(getattr(keep_incident, "status", "") or "")
                if keep_status_value == keep_status.value:
                    return []

                sync_metadata = getattr(keep_incident, "enrichments", None) or {}
                if not isinstance(sync_metadata, dict):
                    sync_metadata = {}

                sync_actor = sync_metadata.get("sf_sync_actor")
                sync_actors = sync_metadata.get("sf_sync_actors")
                sync_tokens = SalesforceProvider._actor_tokens(
                    [sync_actor]
                    + (sync_actors if isinstance(sync_actors, list) else [sync_actors])
                )
                actor_tokens = SalesforceProvider._actor_tokens(
                    [actor.get("email"), actor.get("name"), actor.get("id")]
                )
                if sync_tokens and actor_tokens and sync_tokens.intersection(actor_tokens):
                    return []

                last_sync_time = SalesforceProvider._parse_datetime(
                    sync_metadata.get("sf_last_sync_at")
                )
                if event_time and last_sync_time and event_time <= last_sync_time:
                    return []

                incident_dto = IncidentDto.from_db_incident(keep_incident)
                incident_dto.status = keep_status
                incident_dto._alerts = []
                incident_dto.status_source = "salesforce"
                if event_time:
                    incident_dto.status_changed_at = event_time
                if actor_display:
                    incident_dto.status_changed_by = actor_display
                if keep_status == IncidentStatus.RESOLVED:
                    incident_dto.end_time = datetime.datetime.now(tz=datetime.timezone.utc)
                return incident_dto

            if not allow_external:
                return []

        if not allow_external and not keep_incident_uuid:
            return []

        subject = SalesforceProvider._get_dict_value_case_insensitive(
            case, "Subject", "subject"
        ) or "Salesforce Case"
        description = SalesforceProvider._get_dict_value_case_insensitive(
            case, "Description", "description"
        )
        case_number = SalesforceProvider._get_dict_value_case_insensitive(
            case, "CaseNumber", "caseNumber"
        )
        created_time = SalesforceProvider._parse_datetime(
            SalesforceProvider._get_dict_value_case_insensitive(
                case, "CreatedDate", "createdDate"
            )
        )
        if not created_time:
            created_time = event_time or datetime.datetime.now(tz=datetime.timezone.utc)

        incident_id = (
            keep_incident_uuid
            if keep_incident_uuid
            else SalesforceProvider._get_incident_id(str(case_id))
        )
        incident = IncidentDto(
            id=incident_id,
            creation_time=created_time,
            user_generated_name=f"SF-{subject}-{case_number or case_id}",
            user_summary=description,
            status=keep_status,
            severity=keep_severity,
            alert_sources=["salesforce"],
            alerts_count=0,
            services=["salesforce"],
            is_predicted=False,
            is_candidate=False,
            fingerprint=str(case_id),
            status_source="salesforce",
            status_changed_at=event_time,
            status_changed_by=actor_display,
        )
        if tenant_id:
            incident._tenant_id = tenant_id
        incident._alerts = []
        if keep_status == IncidentStatus.RESOLVED:
            incident.end_time = datetime.datetime.now(tz=datetime.timezone.utc)
        return incident

    def dispose(self):
        pass
