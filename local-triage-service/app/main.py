import logging
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Query

from app.config import get_settings
from app.db import init_schema
from app.ollama_client import OllamaClient
from app.repository import KnowledgeBaseRepository
from app.schemas import (
    KBExampleCreate,
    KBExampleOut,
    KBExamplesListResponse,
    KBExampleUpdate,
    TriageRequest,
    TriageResponse,
)
from app.triage import TriageEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("local-triage-service")

settings = get_settings()
repo = KnowledgeBaseRepository(settings)
ollama = OllamaClient(settings)
triage_engine = TriageEngine(settings, repo, ollama)

app = FastAPI(title="Local Incident Triage Service", version="1.0.0")


@app.on_event("startup")
def startup_event():
    init_schema(settings)
    logger.info("Schema initialized")


@app.on_event("shutdown")
def shutdown_event():
    ollama.close()


def _require_api_token(authorization: str | None):
    expected_token = settings.api_token
    if not expected_token:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    presented_token = authorization[len("Bearer ") :].strip()
    if presented_token != expected_token:
        raise HTTPException(status_code=401, detail="Invalid bearer token")


@app.get("/health")
def health():
    try:
        tags = ollama.health()
        model_names = [m.get("name") for m in tags.get("models", [])]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Ollama health failed: {exc}") from exc
    return {
        "status": "ok",
        "chat_model": settings.ollama_chat_model,
        "embed_model": settings.ollama_embed_model,
        "ollama_models": model_names,
    }


@app.post("/v1/kb/examples", response_model=KBExampleOut)
def create_kb_example(
    payload: KBExampleCreate,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    _require_api_token(authorization)
    try:
        embedding = ollama.embed(payload.alert_text)
        record = repo.create_or_get(payload, embedding)
        return KBExampleOut(**record.__dict__)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/v1/kb/examples", response_model=KBExamplesListResponse)
def list_kb_examples(
    tenant_id: str = Query(..., min_length=1),
    scope: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    _require_api_token(authorization)
    items = repo.list_examples(tenant_id=tenant_id, scope=scope, limit=limit)
    return KBExamplesListResponse(
        items=[KBExampleOut(**item.__dict__) for item in items],
        count=len(items),
    )


@app.put("/v1/kb/examples/{example_id}", response_model=KBExampleOut)
def update_kb_example(
    example_id: UUID,
    tenant_id: str,
    payload: KBExampleUpdate,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    _require_api_token(authorization)
    try:
        embedding = ollama.embed(payload.alert_text) if payload.alert_text else None
        updated = repo.update(tenant_id=tenant_id, example_id=example_id, payload=payload, embedding=embedding)
        if not updated:
            raise HTTPException(status_code=404, detail="Example not found")
        return KBExampleOut(**updated.__dict__)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/v1/kb/examples/{example_id}")
def delete_kb_example(
    example_id: UUID,
    tenant_id: str,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    _require_api_token(authorization)
    ok = repo.soft_delete(tenant_id=tenant_id, example_id=example_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Example not found")
    return {"status": "deleted", "id": str(example_id)}


@app.post("/v1/triage/incident", response_model=TriageResponse)
def triage_incident(
    payload: TriageRequest,
    authorization: str | None = Header(default=None, alias="Authorization"),
):
    _require_api_token(authorization)
    try:
        return triage_engine.triage(payload)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
