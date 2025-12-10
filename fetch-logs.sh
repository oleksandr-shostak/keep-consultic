#!/bin/bash
# Script to fetch Keep logs from remote server

SSH_KEY="/Users/oleksandr.shostak/Documents/SSH/ED25519-openssh"
SERVER="root@keephq-cjm9.consultic.tech"

echo "Fetching Keep logs from server..."
echo "=================================="
echo ""

echo "1. Backend Process Status:"
ssh -i "$SSH_KEY" "$SERVER" "ps aux | grep 'keep api' | grep -v grep"
echo ""

echo "2. Last 100 lines of backend log:"
ssh -i "$SSH_KEY" "$SERVER" "tail -100 /opt/keep/logs/backend.log"
echo ""

echo "3. PagerDuty-related logs:"
ssh -i "$SSH_KEY" "$SERVER" "grep -i 'pagerduty' /opt/keep/logs/backend.log | tail -50"
echo ""

echo "4. System Resources:"
ssh -i "$SSH_KEY" "$SERVER" "free -h && echo '' && top -b -n 1 | head -20"
echo ""

echo "5. Recent errors:"
ssh -i "$SSH_KEY" "$SERVER" "grep -i 'error\|exception\|timeout' /opt/keep/logs/backend.log | tail -30"
