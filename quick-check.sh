#!/bin/bash
# Quick health check for Keep server

SSH_KEY="/Users/oleksandr.shostak/Documents/SSH/ED25519-openssh"
SSH_CERT="/Users/oleksandr.shostak/Documents/SSH/cert.pub"
SERVER="root@keephq-cjm9.consultic.tech"
SSH_CMD="ssh -i $SSH_KEY -i $SSH_CERT $SERVER"

echo "Quick Keep Server Check"
echo "======================="
echo ""

echo "1. Backend API Response:"
$SSH_CMD "curl -s -o /dev/null -w 'Status: %{http_code}, Time: %{time_total}s\n' http://127.0.0.1:8080/ 2>&1"
echo ""

echo "2. Backend Process:"
$SSH_CMD "ps aux | grep 'keep api' | grep -v grep | awk '{print \"PID:\", \$2, \"CPU:\", \$3\"%\", \"MEM:\", \$4\"%\", \"TIME:\", \$10}'"
echo ""

echo "3. Last 10 lines of log:"
$SSH_CMD "tail -10 /opt/keep/logs/backend.log"
echo ""

echo "4. Check for recent errors:"
$SSH_CMD "grep -i 'error\|exception\|timeout' /opt/keep/logs/backend.log | tail -5 || echo 'No recent errors'"
echo ""

echo "5. PagerDuty provider status:"
$SSH_CMD "mysql keepdb_unicode -e \"SELECT name, pulling_enabled, last_pull_time FROM provider WHERE type='pagerduty';\" 2>/dev/null || echo 'Could not query'"
echo ""

echo "6. Incident count:"
$SSH_CMD "mysql keepdb_unicode -e \"SELECT COUNT(*) as total FROM incident;\" 2>/dev/null"
echo ""

echo "7. Check for malicious processes:"
$SSH_CMD "ps aux | grep -E '176.117.107.158|wget.*r.sh|curl.*r.sh' | grep -v grep || echo 'No malicious processes found'"
