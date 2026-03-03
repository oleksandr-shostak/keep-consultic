# Local Incident Triage Service

Локальний сервіс, що замінює OpenAI-залежний retriage для Keep:
- локальна LLM через Ollama (`qwen2.5:7b`)
- локальні embeddings через Ollama (`nomic-embed-text`)
- локальна векторна база на PostgreSQL + pgvector
- контракт triage сумісний з вашими workflow (`incident_id`, `recommended_severity`, `reason`, `validated_fingerprints`, `matched_rules`)

## Чому ця LLM
`qwen2.5:7b` — найкращий баланс якості/швидкості для CPU-only сервера з ~30 GB RAM.
- краще міркування ніж 3B-клас
- стабільна JSON-відповідь при низькій температурі
- працює без GPU

## Швидкий старт

1. Підняти infra:
```bash
docker run -d --name ollama-local -p 127.0.0.1:11434:11434 -v ollama_local_data:/root/.ollama ollama/ollama:latest
docker exec -it ollama-local ollama pull qwen2.5:7b
docker exec -it ollama-local ollama pull nomic-embed-text

docker run -d --name pgvector-local \
  -e POSTGRES_USER=triage \
  -e POSTGRES_PASSWORD=triagepass \
  -e POSTGRES_DB=triage_kb \
  -p 5439:5432 pgvector/pgvector:pg16
```

2. Запустити сервіс:
```bash
cd /opt/keep/local-triage-service
cp .env.example .env
set -a && source .env && set +a
/opt/keep/venv/bin/uvicorn app.main:app --host "$TRIAGE_API_HOST" --port "$TRIAGE_API_PORT"
```

3. Health-check:
```bash
curl -s http://127.0.0.1:8099/health | jq .
```

## API

### 1) CRUD knowledge base
- `POST /v1/kb/examples`
- `GET /v1/kb/examples?tenant_id=<id>&scope=alert|incident&limit=50`
- `PUT /v1/kb/examples/{example_id}`
- `DELETE /v1/kb/examples/{example_id}`

Auth:
- якщо задано `TRIAGE_API_TOKEN`, для всіх `/v1/*` запитів потрібен
  `Authorization: Bearer <TRIAGE_API_TOKEN>`.

### 2) Incident triage
- `POST /v1/triage/incident`

Body:
```json
{
  "tenant_id": "keep",
  "incident_id": "inc-123",
  "mode": "single",
  "alerts": [
    {
      "fingerprint": "fp-1",
      "name": "Disk full",
      "message": "pool usage is 92%",
      "severity": "warning",
      "status": "firing",
      "source": ["truenas"],
      "provider_id": "provider-x"
    }
  ]
}
```

Response (контракт):
```json
{
  "incident_id": "inc-123",
  "recommended_severity": "high",
  "reason": "...",
  "validated_fingerprints": ["fp-1"],
  "matched_rules": ["<kb-example-id>"]
}
```

### 3) Triage run logs (request/retrieval/LLM/response)
- `GET /v1/triage/runs?tenant_id=<id>&limit=100&incident_id=<optional>&mode=single|batch`
- `GET /v1/triage/runs/{run_id}?tenant_id=<id>`

## Режими
- `mode=single`: аналіз кожного алерта окремо + агрегування максимуму severity.
- `mode=batch`: аналіз всіх алертів інцидента одним запитом в LLM.

## Налаштування консервативності
Сервіс **ніколи не ескалює** без matched KB examples.
Якщо немає достатньо релевантних прикладів — повертає `warning`.

## Тести
```bash
cd /opt/keep/local-triage-service
/opt/keep/venv/bin/pytest -q
bash scripts/e2e_demo.sh
```
