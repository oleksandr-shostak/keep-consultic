#!/bin/bash
# Comprehensive Keep diagnostics

SSH_KEY="/Users/oleksandr.shostak/Documents/SSH/ED25519-openssh"
SSH_CERT="/Users/oleksandr.shostak/Documents/SSH/cert.pub"
SERVER="root@keephq-cjm9.consultic.tech"
SSH_CMD="ssh -i $SSH_KEY -i $SSH_CERT $SERVER"

echo "============================================"
echo "Keep Server Diagnostics"
echo "============================================"
echo ""

echo "1. Check if backend process is running:"
echo "----------------------------------------"
$SSH_CMD "ps aux | grep 'keep api' | grep -v grep || echo 'Backend process NOT RUNNING'"
echo ""

echo "2. Check backend service status (last 5 minutes):"
echo "------------------------------------------------"
$SSH_CMD "tail -200 /opt/keep/logs/backend.log | grep -E '(error|Error|ERROR|exception|Exception|EXCEPTION|timeout|Timeout|TIMEOUT|fail|Fail|FAIL)' | tail -20 || echo 'No recent errors found'"
echo ""

echo "3. Last 30 lines of backend log:"
echo "--------------------------------"
$SSH_CMD "tail -30 /opt/keep/logs/backend.log"
echo ""

echo "4. Check for any PagerDuty pulling activity:"
echo "--------------------------------------------"
$SSH_CMD "grep -i 'pulling.*pagerduty\|pagerduty.*pulling\|getting incidents' /opt/keep/logs/backend.log | tail -10 || echo 'No PagerDuty pulling activity found'"
echo ""

echo "5. System resources:"
echo "-------------------"
$SSH_CMD "echo 'Memory:' && free -h && echo '' && echo 'CPU & Load:' && uptime && echo '' && echo 'Disk:' && df -h / | grep -v tmpfs"
echo ""

echo "6. Check if port 8080 is listening:"
echo "-----------------------------------"
$SSH_CMD "netstat -tlnp | grep 8080 || lsof -i :8080 || echo 'Port 8080 not listening'"
echo ""

echo "7. Check tmux session:"
echo "---------------------"
$SSH_CMD "tmux ls 2>/dev/null || echo 'No tmux sessions'"
echo ""

echo "8. Try to access backend API:"
echo "----------------------------"
$SSH_CMD "curl -s -o /dev/null -w 'HTTP Status: %{http_code}\nTime: %{time_total}s\n' http://127.0.0.1:8080/ || echo 'Backend API not responding'"
echo ""

echo "9. Check for stuck processes:"
echo "----------------------------"
$SSH_CMD "ps aux | grep python | grep -v grep | awk '{print \$2, \$3, \$4, \$11}' | head -10"
echo ""

echo "10. PagerDuty provider status:"
echo "-----------------------------"
$SSH_CMD "mysql keepdb_unicode -e \"SELECT name, pulling_enabled, last_pull_time FROM provider WHERE type='pagerduty';\""
echo ""

echo "11. Incident statistics:"
echo "-----------------------"
$SSH_CMD "mysql keepdb_unicode -e \"SELECT COUNT(*) as total, MAX(creation_time) as latest FROM incident;\""
echo ""

echo "12. Check for malicious processes:"
echo "---------------------------------"
$SSH_CMD "ps aux | grep -E '176.117.107.158|wget.*r.sh|curl.*r.sh|kdevtmpfsi|kinsing|xmrig' | grep -v grep || echo 'No malicious processes found'"
echo ""

echo "============================================"
echo "Diagnostics complete"
echo "============================================"
