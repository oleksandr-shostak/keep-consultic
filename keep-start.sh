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
docker rm -f keep-websocket 2>/dev/null || true
tmux kill-session -t keep 2>/dev/null || true
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
echo "════════════════════════════════════════"
echo ""

# ============================================================================
# START SOKETI (WEBSOCKET) IN DOCKER
# ============================================================================
echo "1) Starting Soketi WebSocket in Docker..."
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
echo "2) Starting Backend in tmux..."
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
# START FRONTEND IN TMUX
# ============================================================================
if [[ "$BACKEND_STARTED" == "true" ]]; then
  echo "3) Starting Frontend in tmux..."
  tmux new-window -t keep -n frontend
  tmux send-keys -t keep:frontend "cd /opt/keep/keep-ui" Enter
  tmux send-keys -t keep:frontend "rm -rf .next" Enter
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
  Ctrl+B then 0  → Backend window
  Ctrl+B then 1  → Frontend window
  Ctrl+B then 2  → This monitor
  Ctrl+B then d  → Detach (keeps running)
  Ctrl+C         → Stop current process

Logs:
  tail -f /opt/keep/logs/backend.log
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
