#!/bin/bash
# Script to check webhook installation errors in Keep logs

echo "Checking for webhook installation errors in Keep backend logs..."
echo ""
echo "Looking for errors from the last 1000 lines..."
echo "================================================================"
echo ""

# Check for webhook installation attempts
echo "1. Webhook Installation Attempts:"
grep -i "install.*webhook\|setup.*webhook" /opt/keep/logs/backend.log | tail -20
echo ""

# Check for PagerDuty webhook errors
echo "2. PagerDuty Webhook Errors:"
grep -i "pagerduty.*webhook\|Could not.*webhook" /opt/keep/logs/backend.log | tail -20
echo ""

# Check for HTTPException errors (400 status)
echo "3. Recent HTTP 400 Errors:"
grep -i "HTTPException\|status.*400" /opt/keep/logs/backend.log | tail -20
echo ""

# Check for provider installation errors
echo "4. Provider Installation Errors:"
grep -i "error.*provider\|exception.*provider" /opt/keep/logs/backend.log | tail -20
echo ""

echo "================================================================"
echo "To see more context around errors, run:"
echo "  grep -B 10 -A 10 'Could not create webhook' /opt/keep/logs/backend.log | tail -50"
