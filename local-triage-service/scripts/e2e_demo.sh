#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8099}"
TENANT_ID="${TENANT_ID:-keep}"
API_TOKEN="${TRIAGE_API_TOKEN:-}"

auth_header=()
if [[ -n "$API_TOKEN" ]]; then
  auth_header=(-H "Authorization: Bearer ${API_TOKEN}")
fi

health=$(curl -sS "$BASE_URL/health")
echo "Health: $health"

# create warning example
ex_warning=$(curl -sS -X POST "$BASE_URL/v1/kb/examples" \
  "${auth_header[@]}" \
  -H 'Content-Type: application/json' \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"scope\": \"alert\",
    \"proposed_severity\": \"warning\",
    \"reason\": \"Intermittent single backup file warning\",
    \"alert_text\": \"Failed to open one source object; retry succeeded\",
    \"created_by\": \"codex\",
    \"fingerprint\": \"kb-warning-1\"
  }")
echo "Created warning example: $ex_warning"

# create critical example
ex_critical=$(curl -sS -X POST "$BASE_URL/v1/kb/examples" \
  "${auth_header[@]}" \
  -H 'Content-Type: application/json' \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"scope\": \"alert\",
    \"proposed_severity\": \"critical\",
    \"reason\": \"Pool space exceeded 95%\",
    \"alert_text\": \"Space usage for pool VOL0 is 95%\",
    \"created_by\": \"codex\",
    \"fingerprint\": \"kb-critical-1\"
  }")
echo "Created critical example: $ex_critical"

triage_single=$(curl -sS -X POST "$BASE_URL/v1/triage/incident" \
  "${auth_header[@]}" \
  -H 'Content-Type: application/json' \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"incident_id\": \"inc-e2e-single\",
    \"mode\": \"single\",
    \"alerts\": [
      {
        \"fingerprint\": \"fp-e2e-1\",
        \"name\": \"TrueNAS alert\",
        \"status\": \"firing\",
        \"severity\": \"warning\",
        \"message\": \"Space usage for pool VOL0 is 95%\",
        \"description\": \"Space usage for pool VOL0 is 95%\",
        \"source\": [\"truenas\"],
        \"provider_id\": \"provider-truenas\"
      }
    ]
  }")

echo "Single triage response: $triage_single"

triage_batch=$(curl -sS -X POST "$BASE_URL/v1/triage/incident" \
  "${auth_header[@]}" \
  -H 'Content-Type: application/json' \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"incident_id\": \"inc-e2e-batch\",
    \"mode\": \"batch\",
    \"alerts\": [
      {
        \"fingerprint\": \"fp-e2e-2\",
        \"name\": \"TrueNAS alert\",
        \"status\": \"firing\",
        \"severity\": \"warning\",
        \"message\": \"Space usage for pool VOL0 is 95%\",
        \"description\": \"Space usage for pool VOL0 is 95%\",
        \"source\": [\"truenas\"],
        \"provider_id\": \"provider-truenas\"
      },
      {
        \"fingerprint\": \"fp-e2e-3\",
        \"name\": \"TrueNAS alert 2\",
        \"status\": \"firing\",
        \"severity\": \"warning\",
        \"message\": \"Space usage for pool VOL0 is 95%\",
        \"description\": \"Space usage for pool VOL0 is 95%\",
        \"source\": [\"truenas\"],
        \"provider_id\": \"provider-truenas\"
      }
    ]
  }")

echo "Batch triage response: $triage_batch"
