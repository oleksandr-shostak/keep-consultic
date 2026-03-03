import os
from dataclasses import dataclass
from pathlib import Path

import requests


@dataclass
class LocalKBSyncError(Exception):
    message: str
    status_code: int | None = None
    response_body: str | None = None

    def __str__(self) -> str:
        base = self.message
        if self.status_code:
            base = f"{base} (status={self.status_code})"
        if self.response_body:
            base = f"{base}: {self.response_body}"
        return base


class LocalKBSyncClient:
    def __init__(self, base_url: str, api_token: str | None, timeout_sec: int = 30):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout_sec = timeout_sec

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers

    @staticmethod
    def _response_text(response: requests.Response) -> str:
        try:
            return response.text[:2000]
        except Exception:
            return "<failed reading response body>"

    def _request(self, method: str, path: str, *, params: dict | None = None, body: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        try:
            response = requests.request(
                method,
                url,
                headers=self._headers(),
                params=params,
                json=body,
                timeout=self.timeout_sec,
            )
        except Exception as exc:
            raise LocalKBSyncError(f"Local KB request failed: {exc}") from exc

        if not response.ok:
            raise LocalKBSyncError(
                "Local KB request returned error",
                status_code=response.status_code,
                response_body=self._response_text(response),
            )

        try:
            return response.json()
        except Exception as exc:
            raise LocalKBSyncError("Local KB response is not JSON") from exc

    def create_example(self, body: dict) -> dict:
        return self._request("POST", "/v1/kb/examples", body=body)

    def list_examples(self, tenant_id: str, scope: str | None = None, limit: int = 500) -> dict:
        params: dict[str, str | int] = {"tenant_id": tenant_id, "limit": limit}
        if scope:
            params["scope"] = scope
        return self._request("GET", "/v1/kb/examples", params=params)

    def update_example(self, example_id: str, tenant_id: str, body: dict) -> dict:
        return self._request(
            "PUT",
            f"/v1/kb/examples/{example_id}",
            params={"tenant_id": tenant_id},
            body=body,
        )

    def delete_example(self, example_id: str, tenant_id: str) -> dict:
        return self._request(
            "DELETE",
            f"/v1/kb/examples/{example_id}",
            params={"tenant_id": tenant_id},
        )


def _load_api_token_from_file(file_path: str | None) -> str | None:
    if not file_path:
        return None
    try:
        token = Path(file_path).read_text(encoding="utf-8").strip()
    except Exception:
        return None
    return token or None


def get_local_kb_sync_client() -> LocalKBSyncClient:
    base_url = (
        os.environ.get("KEEP_LOCAL_KB_API_URL")
        or os.environ.get("KEEP_LOCAL_TRIAGE_API_URL")
        or "http://127.0.0.1:8099"
    )
    api_token = (
        os.environ.get("KEEP_LOCAL_KB_API_TOKEN")
        or os.environ.get("KEEP_LOCAL_TRIAGE_API_TOKEN")
        or _load_api_token_from_file(
            os.environ.get("KEEP_LOCAL_KB_API_TOKEN_FILE")
            or os.environ.get("KEEP_LOCAL_TRIAGE_API_TOKEN_FILE")
            or "/opt/keep/state/keep-local-triage-service-token"
        )
    )
    timeout_sec = int(os.environ.get("KEEP_LOCAL_KB_API_TIMEOUT_SEC", "30"))
    return LocalKBSyncClient(
        base_url=base_url,
        api_token=api_token,
        timeout_sec=timeout_sec,
    )
