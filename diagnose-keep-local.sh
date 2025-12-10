#!/bin/bash
# Comprehensive Keep diagnostics - Run this ON the Keep server

echo "============================================"
echo "Keep Server Diagnostics (Local)"
echo "============================================"
echo ""

echo "1. Check if backend process is running:"
echo "----------------------------------------"
ps aux | grep 'keep api' | grep -v grep || echo 'Backend process NOT RUNNING'
echo ""

echo "2. Check backend errors (last 20):"
echo "-----------------------------------"
tail -200 /opt/keep/logs/backend.log | grep -E '(error|Error|ERROR|exception|Exception|EXCEPTION|timeout|Timeout|TIMEOUT|fail|Fail|FAIL)' | tail -20 || echo 'No recent errors found'
echo ""

echo "3. Last 30 lines of backend log:"
echo "--------------------------------"
tail -30 /opt/keep/logs/backend.log
echo ""

echo "4. Check for PagerDuty pulling activity:"
echo "----------------------------------------"
grep -i 'pulling.*pagerduty\|pagerduty.*pulling\|getting incidents' /opt/keep/logs/backend.log | tail -10 || echo 'No PagerDuty pulling activity found'
echo ""

echo "5. System resources:"
echo "-------------------"
echo 'Memory:'
free -h
echo ''
echo 'CPU & Load:'
uptime
echo ''
echo 'Disk:'
df -h / | grep -v tmpfs
echo ""

echo "6. Check if port 8080 is listening:"
echo "-----------------------------------"
netstat -tlnp | grep 8080 || lsof -i :8080 || ss -tlnp | grep 8080 || echo 'Port 8080 not listening'
echo ""

echo "7. Check tmux session:"
echo "---------------------"
tmux ls 2>/dev/null || echo 'No tmux sessions'
echo ""

echo "8. Try to access backend API:"
echo "----------------------------"
curl -s -o /dev/null -w 'HTTP Status: %{http_code}\nTime: %{time_total}s\n' http://127.0.0.1:8080/ 2>&1 || echo 'Backend API not responding'
echo ""

echo "9. Check for stuck Python processes:"
echo "------------------------------------"
ps aux | grep python | grep -v grep | awk '{print $2, $3, $4, $11}' | head -10
echo ""

echo "10. Check PagerDuty provider status in database:"
echo "------------------------------------------------"
sqlite3 /opt/keep/state/keep.db "SELECT name, type, pulling_enabled, last_pull_time FROM provider WHERE type='pagerduty';" 2>/dev/null || echo 'Could not query database'
echo ""

echo "============================================"
echo "Diagnostics complete"
echo "============================================"
