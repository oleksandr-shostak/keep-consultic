#!/bin/bash
# Security check and malware cleanup for Keep server
# Run this script ON the Keep server to detect and remove malware

echo "========================================"
echo "Keep Server Security Check & Cleanup"
echo "========================================"
echo ""

# Kill malicious processes
echo "1. Killing malicious processes..."
pkill -9 -f '176.117.107.158' 2>/dev/null
pkill -9 -f 'wget.*r\.sh' 2>/dev/null
pkill -9 -f 'curl.*r\.sh' 2>/dev/null
pkill -9 -f 'kdevtmpfsi' 2>/dev/null
pkill -9 -f 'kinsing' 2>/dev/null
pkill -9 -f 'xmrig' 2>/dev/null
echo "✓ Malicious processes killed"
echo ""

# Check for remaining malicious processes
echo "2. Checking for remaining malicious processes..."
MALICIOUS=$(ps aux | grep -E '176.117.107.158|wget.*r\.sh|curl.*r\.sh|kdevtmpfsi|kinsing|xmrig' | grep -v grep)
if [ -z "$MALICIOUS" ]; then
    echo "✓ No malicious processes found"
else
    echo "⚠ WARNING: Malicious processes still running:"
    echo "$MALICIOUS"
fi
echo ""

# Remove malicious scripts
echo "3. Removing malicious scripts..."
rm -f /tmp/r.sh /var/tmp/r.sh 2>/dev/null
echo "✓ Malicious scripts removed"
echo ""

# Check for suspicious cron jobs
echo "4. Checking cron jobs..."
CRON=$(crontab -l 2>/dev/null | grep -E '176.117.107.158|wget.*r\.sh|curl.*r\.sh')
if [ -z "$CRON" ]; then
    echo "✓ No suspicious cron jobs"
else
    echo "⚠ WARNING: Suspicious cron jobs found:"
    echo "$CRON"
fi
echo ""

# Check for suspicious network connections
echo "5. Checking network connections..."
SUSPICIOUS_CONN=$(netstat -tunap 2>/dev/null | grep -E '176.117.107.158' | grep -v grep)
if [ -z "$SUSPICIOUS_CONN" ]; then
    echo "✓ No suspicious network connections"
else
    echo "⚠ WARNING: Suspicious connections found:"
    echo "$SUSPICIOUS_CONN"
fi
echo ""

# Check frontend log for malware triggers
echo "6. Checking frontend logs for malware triggers..."
MALWARE_COUNT=$(grep -c '176.117.107.158' /opt/keep/logs/frontend.log 2>/dev/null || echo 0)
if [ "$MALWARE_COUNT" -eq 0 ]; then
    echo "✓ No malware activity found in logs"
else
    RECENT_MALWARE=$(grep '176.117.107.158' /opt/keep/logs/frontend.log 2>/dev/null | tail -1)
    LAST_TIME=$(echo "$RECENT_MALWARE" | grep -oP '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}' | head -1)
    echo "⚠ WARNING: Malware activity detected"
    echo "   Total occurrences: $MALWARE_COUNT"
    echo "   Last activity: ${LAST_TIME:-unknown}"
    echo "   Context (last 5 lines before malware):"
    grep -B5 '176.117.107.158' /opt/keep/logs/frontend.log 2>/dev/null | tail -10
fi
echo ""

# Check Keep processes
echo "7. Keep service status..."
if systemctl is-active --quiet keep.service; then
    echo "✓ Keep service is running"
    KEEP_PROC=$(ps aux | grep 'keep.cli.cli' | grep -v grep)
    if [ -n "$KEEP_PROC" ]; then
        echo "✓ Backend process is running"
        API_TEST=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ 2>/dev/null)
        if [ "$API_TEST" = "200" ]; then
            echo "✓ Backend API responding (HTTP $API_TEST)"
        else
            echo "⚠ WARNING: Backend process running but API not responding (HTTP $API_TEST)"
        fi
    else
        echo "⚠ WARNING: Keep service active but backend not running"
    fi
else
    echo "⚠ WARNING: Keep service is not running"
fi
echo ""

echo "========================================"
echo "Security check complete"
echo "========================================"
echo ""
echo "Recommendations:"
echo "1. Monitor /opt/keep/logs/frontend.log for recurring malware"
echo "2. If malware persists, rebuild Keep frontend from clean source"
echo "3. Check /opt/keep/.env for suspicious environment variables"
echo "4. Consider restarting Keep service: sudo systemctl restart keep.service"
