#!/bin/bash
set -euo pipefail

echo "════════════════════════════════════════"
echo "  Starting Keep Services"
echo "════════════════════════════════════════"

cd /opt/keep
mkdir -p logs state

# ============================================================================
# STOP EXISTING SERVICES
# ============================================================================
echo "Stopping existing services..."
pkill -f "keep api" 2>/dev/null || true
pkill -f "npm run dev" 2>/dev/null || true
pkill -f "next dev" 2>/dev/null || true
pkill -f "uvicorn app.main:app.*8099" 2>/dev/null || true
docker rm -f keep-websocket 2>/dev/null || true
tmux kill-session -t keep 2>/dev/null || true

# Kill any process on port 3000 (frontend), 8080 (backend), 6001 (soketi), 8099 (local triage)
lsof -ti:3000 | xargs -r kill -9 2>/dev/null || true
lsof -ti:8080 | xargs -r kill -9 2>/dev/null || true
lsof -ti:6001 | xargs -r kill -9 2>/dev/null || true
lsof -ti:8099 | xargs -r kill -9 2>/dev/null || true

sleep 2

# ============================================================================
# LOAD BACKEND ENVIRONMENT FROM .env
# ============================================================================
if [[ ! -f .env ]]; then
  echo "✗ ERROR: /opt/keep/.env not found!"
  exit 1
fi

echo "Loading backend variables from .env..."
set -a
source .env
set +a
echo "✓ Loaded /opt/keep/.env"

# Local triage env (separate from Keep .env)
TRIAGE_ENV_FILE="/opt/keep/local-triage-service/.env"
TRIAGE_ENABLED=false
TRIAGE_API_HOST_VALUE="127.0.0.1"
TRIAGE_API_PORT_VALUE="8099"
if [[ -f "$TRIAGE_ENV_FILE" ]]; then
  TRIAGE_ENABLED=true
  TRIAGE_API_PORT_VALUE="$(grep -E '^TRIAGE_API_PORT=' "$TRIAGE_ENV_FILE" | tail -n1 | cut -d= -f2- || echo "8099")"
  TRIAGE_API_PORT_VALUE="${TRIAGE_API_PORT_VALUE:-8099}"
  echo "✓ Found $TRIAGE_ENV_FILE"
else
  echo "⚠ Local triage env not found at $TRIAGE_ENV_FILE (triage UI/LLM logs will be unavailable)"
fi

# ============================================================================
# CHECK FRONTEND .env.local EXISTS
# ============================================================================
FRONTEND_ENV="keep-ui/.env.local"
if [[ ! -f "$FRONTEND_ENV" ]]; then
  echo "✗ ERROR: $FRONTEND_ENV not found!"
  echo "Create it first."
  exit 1
fi
echo "✓ Found $FRONTEND_ENV (will be used by Next.js)"

# ============================================================================
# DISPLAY CONFIGURATION
# ============================================================================
echo ""
echo "════════════════════════════════════════"
echo "Configuration:"
echo "════════════════════════════════════════"
echo "Backend Config (.env):"
echo "  Auth Type:     ${AUTH_TYPE:-not set}"
echo "  Port:          ${PORT}"
echo "  Database:      ${DATABASE_CONNECTION_STRING:-not set}"
echo "  Pusher Host:   ${PUSHER_HOST}:${PUSHER_PORT}"
echo ""
echo "Frontend Config (.env.local):"
grep -E "^(NEXTAUTH_URL|NEXT_PUBLIC_API_URL|API_URL|PUSHER_HOST)=" "$FRONTEND_ENV" 2>/dev/null | sed 's/^/  /' || echo "  (variables in $FRONTEND_ENV)"
echo ""
echo "Internal Services:"
echo "  Backend:       http://127.0.0.1:${PORT}"
echo "  Frontend:      http://127.0.0.1:3000"
echo "  Soketi:        http://${PUSHER_HOST}:${PUSHER_PORT}"
echo "  Local Triage:  http://${TRIAGE_API_HOST_VALUE}:${TRIAGE_API_PORT_VALUE}"
echo "  Ollama API:    http://127.0.0.1:11434"
echo "════════════════════════════════════════"
echo ""

# ============================================================================
# ENSURE LOCAL OLLAMA CONTAINER (LOCALHOST ONLY)
# ============================================================================
echo "1) Ensuring local Ollama container (localhost only)..."
OLLAMA_BIND_EXPECTED="127.0.0.1:11434"
OLLAMA_EXISTS=false
OLLAMA_RUNNING=false

if docker ps -a --format '{{.Names}}' | grep -qx "ollama-local"; then
  OLLAMA_EXISTS=true
fi
if docker ps --format '{{.Names}}' | grep -qx "ollama-local"; then
  OLLAMA_RUNNING=true
fi

if [[ "$OLLAMA_EXISTS" == "true" ]]; then
  OLLAMA_BIND_CURRENT="$(docker inspect -f '{{range (index .HostConfig.PortBindings "11434/tcp")}}{{.HostIp}}:{{.HostPort}}{{end}}' ollama-local 2>/dev/null || true)"
  if [[ "$OLLAMA_BIND_CURRENT" != "$OLLAMA_BIND_EXPECTED" ]]; then
    echo "  Recreating ollama-local to enforce localhost bind (${OLLAMA_BIND_EXPECTED})..."
    docker rm -f ollama-local >/dev/null 2>&1 || true
    OLLAMA_EXISTS=false
    OLLAMA_RUNNING=false
  fi
fi

if [[ "$OLLAMA_EXISTS" == "false" ]]; then
  docker run -d --name ollama-local \
    --restart unless-stopped \
    -p 127.0.0.1:11434:11434 \
    -v ollama_local_data:/root/.ollama \
    -e OLLAMA_HOST=0.0.0.0:11434 \
    ollama/ollama:latest >/dev/null
  OLLAMA_RUNNING=true
else
  if [[ "$OLLAMA_RUNNING" == "false" ]]; then
    docker start ollama-local >/dev/null
  fi
fi

echo "Waiting for Ollama API to become ready..."
for i in {1..30}; do
  if curl -sS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    echo "✓ Ollama is UP at 127.0.0.1:11434"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo "✗ Ollama failed to start after 30s"
    exit 1
  fi
  sleep 1
done

# ============================================================================
# START SOKETI (WEBSOCKET) IN DOCKER
# ============================================================================
echo "2) Starting Soketi WebSocket in Docker..."
docker run -d --rm \
  --name keep-websocket \
  -p ${PUSHER_PORT}:6001 \
  -e SOKETI_DEFAULT_APP_ID=${PUSHER_APP_ID} \
  -e SOKETI_DEFAULT_APP_KEY=${PUSHER_APP_KEY} \
  -e SOKETI_DEFAULT_APP_SECRET=${PUSHER_APP_SECRET} \
  quay.io/soketi/soketi:1.4-16-debian >/dev/null 2>&1

echo "Waiting for Soketi to start..."
for i in {1..10}; do
  if timeout 3 bash -c "</dev/tcp/127.0.0.1/${PUSHER_PORT}" >/dev/null 2>&1; then
    echo "✓ Soketi is UP at 127.0.0.1:${PUSHER_PORT} (Docker)"
    break
  fi
  if [[ $i -eq 10 ]]; then
    echo "✗ Soketi failed to start after 10s"
    echo "Check with: docker logs keep-websocket"
    exit 1
  fi
  sleep 1
done

# ============================================================================
# ENSURE TMUX
# ============================================================================
if ! command -v tmux >/dev/null 2>&1; then
  echo "Installing tmux..."
  apt-get update -y >/dev/null 2>&1 && apt-get install -y tmux >/dev/null 2>&1
fi

# ============================================================================
# START BACKEND IN TMUX
# ============================================================================
echo "3) Starting Backend in tmux..."
tmux new-session -d -s keep -n backend

# Load environment and start
tmux send-keys -t keep:backend "cd /opt/keep" Enter
tmux send-keys -t keep:backend "source venv/bin/activate" Enter
tmux send-keys -t keep:backend "set -a && source .env && set +a" Enter
tmux send-keys -t keep:backend "poetry run keep api 2>&1 | tee logs/backend.log" Enter

# Wait for backend to be ready
echo "Waiting for backend to start..."
BACKEND_STARTED=false
for i in {1..45}; do
  if curl -s http://127.0.0.1:${PORT}/ >/dev/null 2>&1; then
    echo "✓ Backend is UP (took ${i}s)"
    BACKEND_STARTED=true
    break
  fi
  if [[ $i -eq 45 ]]; then
    echo "✗ Backend failed to start after 45s"
    echo ""
    echo "Check logs with:"
    echo "  tmux attach -t keep"
    echo "  tail -f /opt/keep/logs/backend.log"
    BACKEND_STARTED=false
  fi
  sleep 1
  [[ $((i % 5)) -eq 0 ]] && echo "  Still waiting... (${i}s)"
done

# ============================================================================
# START LOCAL TRIAGE IN TMUX (LOCALHOST ONLY)
# ============================================================================
if [[ "$TRIAGE_ENABLED" == "true" ]]; then
  echo "4) Starting Local Triage in tmux (localhost only)..."
  tmux new-window -t keep -n triage
  tmux send-keys -t keep:triage "cd /opt/keep/local-triage-service" Enter
  tmux send-keys -t keep:triage "set -a && source .env && set +a" Enter
  tmux send-keys -t keep:triage "export TRIAGE_API_HOST=127.0.0.1" Enter
  tmux send-keys -t keep:triage "/opt/keep/venv/bin/uvicorn app.main:app --host \"\${TRIAGE_API_HOST}\" --port \"\${TRIAGE_API_PORT:-8099}\" 2>&1 | tee /opt/keep/logs/local-triage-service.log" Enter

  echo "Waiting for local triage to start..."
  TRIAGE_STARTED=false
  for i in {1..30}; do
    if curl -sS "http://127.0.0.1:${TRIAGE_API_PORT_VALUE}/health" >/dev/null 2>&1; then
      echo "✓ Local triage is UP at 127.0.0.1:${TRIAGE_API_PORT_VALUE}"
      TRIAGE_STARTED=true
      break
    fi
    if [[ $i -eq 30 ]]; then
      echo "⚠ Local triage did not report ready after 30s (continuing Keep start)"
    fi
    sleep 1
  done
else
  echo "⚠ Skipping local triage start (no env file)"
fi

# ============================================================================
# START FRONTEND IN TMUX
# ============================================================================
if [[ "$BACKEND_STARTED" == "true" ]]; then
  echo "5) Starting Frontend in tmux..."
  # Clean .next directory before starting (do it synchronously, not in tmux)
  rm -rf /opt/keep/keep-ui/.next 2>/dev/null || true
  sleep 1

  tmux new-window -t keep -n frontend
  tmux send-keys -t keep:frontend "cd /opt/keep/keep-ui" Enter
  # Keep OpenAI credentials available for backend, but hide them from frontend runtime.
  tmux send-keys -t keep:frontend "unset OPEN_AI_API_KEY OPENAI_API_KEY OPEN_AI_ORGANIZATION_ID" Enter
  tmux send-keys -t keep:frontend "npm run dev 2>&1 | tee ../logs/frontend.log" Enter
else
  echo "⚠ Skipping frontend start (backend not running)"
fi

# ============================================================================
# CREATE MONITOR WINDOW
# ============================================================================
tmux new-window -t keep -n monitor
tmux send-keys -t keep:monitor "clear" Enter

# Get URLs from frontend .env.local for display
DISPLAY_UI_URL=$(grep "^NEXTAUTH_URL=" "$FRONTEND_ENV" 2>/dev/null | cut -d= -f2 || echo "Not configured")
DISPLAY_API_URL=$(grep "^NEXT_PUBLIC_API_URL=" "$FRONTEND_ENV" 2>/dev/null | cut -d= -f2 || echo "Not configured")

tmux send-keys -t keep:monitor "cat << 'MONEOF'
════════════════════════════════════════
  Keep Services Running
════════════════════════════════════════

Public URLs (from .env.local):
  UI:        ${DISPLAY_UI_URL}
  API:       ${DISPLAY_API_URL}

Internal Services:
  Backend:   http://127.0.0.1:${PORT}
  Frontend:  http://127.0.0.1:3000
  Soketi:    http://${PUSHER_HOST}:${PUSHER_PORT}

Configuration Files:
  Backend:   /opt/keep/.env
  Frontend:  /opt/keep/keep-ui/.env.local

Tmux Commands:
  Ctrl+B then w  → List windows
  Ctrl+B then n  → Next window
  Ctrl+B then p  → Previous window
  Ctrl+B then d  → Detach (keeps running)
  Ctrl+C         → Stop current process

Logs:
  tail -f /opt/keep/logs/backend.log
  tail -f /opt/keep/logs/local-triage-service.log
  tail -f /opt/keep/logs/frontend.log

════════════════════════════════════════
MONEOF" Enter

tmux select-window -t keep:backend

# ============================================================================
# WAIT FOR FRONTEND
# ============================================================================
if [[ "$BACKEND_STARTED" == "true" ]]; then
  echo ""
  echo "Waiting for frontend to start..."
  sleep 15
fi

# ============================================================================
# HEALTH CHECK
# ============================================================================
echo ""
echo "════════════════════════════════════════"
echo "Health Check:"
echo "════════════════════════════════════════"

# Backend
echo -n "Backend (${PORT}):  "
if curl -s http://127.0.0.1:${PORT}/ >/dev/null 2>&1; then
  echo "✓ OK"
else
  echo "✗ FAIL"
fi

# Frontend
echo -n "Frontend (3000): "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3000 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" =~ ^(200|304|307)$ ]]; then
  echo "✓ OK (${HTTP_CODE})"
else
  echo "⚠ Response: ${HTTP_CODE}"
fi

# Soketi
echo -n "Soketi (${PUSHER_PORT}):   "
if timeout 3 bash -c "</dev/tcp/${PUSHER_HOST}/${PUSHER_PORT}" >/dev/null 2>&1; then
  echo "✓ Reachable"
else
  echo "✗ Not reachable"
fi

# Ollama
echo -n "Ollama (127.0.0.1:11434): "
if curl -sS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  echo "✓ OK"
else
  echo "✗ FAIL"
fi

# Local triage
echo -n "Local Triage (${TRIAGE_API_PORT_VALUE}): "
if [[ "$TRIAGE_ENABLED" == "true" ]]; then
  if curl -sS "http://127.0.0.1:${TRIAGE_API_PORT_VALUE}/health" >/dev/null 2>&1; then
    echo "✓ OK"
  else
    echo "✗ FAIL"
  fi
else
  echo "⚠ Disabled (missing local-triage-service/.env)"
fi

# Tmux
echo -n "Tmux Session:    "
if tmux has-session -t keep 2>/dev/null; then
  echo "✓ Active"
else
  echo "✗ Not found"
fi

echo "════════════════════════════════════════"
echo ""
if [[ "$BACKEND_STARTED" == "true" ]]; then
  echo "✓ Keep is starting!"
  echo ""
  echo "Access your UI at: ${DISPLAY_UI_URL}"
  echo ""
else
  echo "⚠ Keep started with issues - check logs"
  echo ""
fi
echo "Attach to see logs: tmux attach -t keep"
echo "Detach from tmux:   Ctrl+B then d"
echo ""

# ============================================================================
# KEEP SCRIPT RUNNING (for systemd)
# ============================================================================
# Wait for tmux session to exit (keeps systemd service active)
echo "Script will monitor tmux session..."
while tmux has-session -t keep 2>/dev/null; do
  sleep 10
done

echo "Tmux session ended - shutting down"
