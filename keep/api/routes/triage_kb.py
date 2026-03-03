from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from keep.api.models.triage_kb import (
    TriageKBExampleCreateRequest,
    TriageKBExampleDeleteResponse,
    TriageKBExampleResponse,
    TriageKBExampleScope,
    TriageKBExamplesListResponse,
    TriageKBExampleUpdateRequest,
    TriageRunDetailResponse,
    TriageRunMode,
    TriageRunsListResponse,
)
from keep.api.tasks.local_kb_sync_client import (
    LocalKBSyncError,
    get_local_kb_sync_client,
)
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.identitymanagerfactory import IdentityManagerFactory

router = APIRouter()


def _raise_local_kb_http_error(exc: LocalKBSyncError):
    status_code = exc.status_code if exc.status_code and 400 <= exc.status_code < 600 else 502
    detail = exc.response_body or exc.message
    raise HTTPException(status_code=status_code, detail=detail)


@router.get(
    "/examples",
    description="List triage knowledge base examples",
    response_model=TriageKBExamplesListResponse,
)
def list_examples(
    scope: TriageKBExampleScope | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    authenticated_entity: AuthenticatedEntity = Depends(
        IdentityManagerFactory.get_auth_verifier(["read:alert"])
    ),
):
    tenant_id = authenticated_entity.tenant_id
    client = get_local_kb_sync_client()
    try:
        payload = client.list_examples(
            tenant_id=tenant_id,
            scope=scope.value if scope else None,
            limit=limit,
        )
    except LocalKBSyncError as exc:
        _raise_local_kb_http_error(exc)
    return TriageKBExamplesListResponse(**payload)


@router.post(
    "/examples",
    description="Create a triage knowledge base example",
    response_model=TriageKBExampleResponse,
)
def create_example(
    payload: TriageKBExampleCreateRequest,
    authenticated_entity: AuthenticatedEntity = Depends(
        IdentityManagerFactory.get_auth_verifier(["write:alert"])
    ),
):
    tenant_id = authenticated_entity.tenant_id
    created_by = authenticated_entity.email or "unknown"

    request_payload = payload.dict(exclude_none=True)
    request_payload["tenant_id"] = tenant_id
    request_payload["created_by"] = created_by

    client = get_local_kb_sync_client()
    try:
        result = client.create_example(request_payload)
    except LocalKBSyncError as exc:
        _raise_local_kb_http_error(exc)
    return TriageKBExampleResponse(**result)


@router.put(
    "/examples/{example_id}",
    description="Update a triage knowledge base example",
    response_model=TriageKBExampleResponse,
)
def update_example(
    example_id: UUID,
    payload: TriageKBExampleUpdateRequest,
    authenticated_entity: AuthenticatedEntity = Depends(
        IdentityManagerFactory.get_auth_verifier(["write:alert"])
    ),
):
    tenant_id = authenticated_entity.tenant_id
    update_payload = payload.dict(exclude_none=True)
    if not update_payload:
        raise HTTPException(status_code=400, detail="No fields supplied for update")

    client = get_local_kb_sync_client()
    try:
        result = client.update_example(
            example_id=str(example_id),
            tenant_id=tenant_id,
            body=update_payload,
        )
    except LocalKBSyncError as exc:
        _raise_local_kb_http_error(exc)
    return TriageKBExampleResponse(**result)


@router.delete(
    "/examples/{example_id}",
    description="Delete a triage knowledge base example",
    response_model=TriageKBExampleDeleteResponse,
)
def delete_example(
    example_id: UUID,
    authenticated_entity: AuthenticatedEntity = Depends(
        IdentityManagerFactory.get_auth_verifier(["write:alert"])
    ),
):
    tenant_id = authenticated_entity.tenant_id
    client = get_local_kb_sync_client()
    try:
        result = client.delete_example(
            example_id=str(example_id),
            tenant_id=tenant_id,
        )
    except LocalKBSyncError as exc:
        _raise_local_kb_http_error(exc)
    return TriageKBExampleDeleteResponse(**result)


@router.get(
    "/logs",
    description="List local triage run logs",
    response_model=TriageRunsListResponse,
)
def list_triage_logs(
    limit: int = Query(default=100, ge=1, le=500),
    incident_id: str | None = Query(default=None),
    mode: TriageRunMode | None = Query(default=None),
    authenticated_entity: AuthenticatedEntity = Depends(
        IdentityManagerFactory.get_auth_verifier(["read:alert"])
    ),
):
    tenant_id = authenticated_entity.tenant_id
    client = get_local_kb_sync_client()
    try:
        payload = client.list_triage_runs(
            tenant_id=tenant_id,
            limit=limit,
            incident_id=incident_id,
            mode=mode.value if mode else None,
        )
    except LocalKBSyncError as exc:
        _raise_local_kb_http_error(exc)
    return TriageRunsListResponse(**payload)


@router.get(
    "/logs/{run_id}",
    description="Get local triage run log details",
    response_model=TriageRunDetailResponse,
)
def get_triage_log(
    run_id: UUID,
    authenticated_entity: AuthenticatedEntity = Depends(
        IdentityManagerFactory.get_auth_verifier(["read:alert"])
    ),
):
    tenant_id = authenticated_entity.tenant_id
    client = get_local_kb_sync_client()
    try:
        payload = client.get_triage_run(run_id=str(run_id), tenant_id=tenant_id)
    except LocalKBSyncError as exc:
        _raise_local_kb_http_error(exc)
    return TriageRunDetailResponse(**payload)
