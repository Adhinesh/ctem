# CTEM Platform - UEBA Victim Machine Setup & Testing Guide

This guide provides step-by-step instructions on connecting your victim machine's authentication logs to the **CTEM UEBA (User and Entity Behavior Analytics)** engine and simulating attacks to verify anomaly detection.

---

## Architecture Overview

```
 ┌───────────────────────────────────────┐
 │       VICTIM MACHINE (Linux / Win)    │
 │  - SSH / PAM / Auth Logs              │
 │  - Running: ueba_forwarder.py         │
 └───────────────────┬───────────────────┘
                     │ HTTP POST /ueba/events
                     ▼
 ┌───────────────────────────────────────┐
 │         CTEM BACKEND (:8000)          │
 │  - ueba_service.py (Rules Engine)     │
 │  - Ingests to user_behavior_events    │
 │  - Triggers High/Med/Low Alerts       │
 └───────────────────┬───────────────────┘
                     │
                     ▼
 ┌───────────────────────────────────────┐
 │         CTEM FRONTEND (:3000)         │
 │  - Active Alerts & Anomaly Feed       │
 │  - Monitoring & Logs -> UEBA Tab      │
 └───────────────────────────────────────┘
```

---

## Step 1: Register the Victim Machine in CTEM

1. Open the CTEM web dashboard: **[http://localhost:3000/assets](http://localhost:3000/assets)**.
2. Click **"+ Declare Asset"** and fill in the details:
   - **Hostname**: e.g. `victim-node` or `ubuntu-target`
   - **IP Address**: e.g. `192.168.1.150` (the LAN or VM IP of your victim machine)
   - **Zone**: `internal` (or `external` if publicly routed)
   - **Criticality**: `high`
   - **Asset Type**: `server`
3. Click **Add Asset**.
4. *(Optional Recon Scan)*: Navigate to **[http://localhost:3000/scans](http://localhost:3000/scans)**, start a scan against the victim's IP to discover open ports (SSH `22`, HTTP `80`), map vulnerabilities, and calculate its risk score on the Heatmap.

---

## Step 2: Deploy the Auth Log Forwarder on the Victim Machine

The CTEM platform includes a ready-to-use log streamer located at:
`ctem-backend/scripts/ueba_forwarder.py`

### A. For Linux Victim Machines (Ubuntu, Debian, Kali, CentOS, Rocky)

1. **Find your CTEM Server Host IP** (the IP of the machine running CTEM backend):
   ```bash
   # On macOS:
   ipconfig getifaddr en0
   # On Linux:
   hostname -I | awk '{print $1}'
   ```
   *Assume your CTEM server IP is `192.168.1.50`.*

2. **Copy the forwarder to the victim machine**:
   ```bash
   scp ctem-backend/scripts/ueba_forwarder.py <username>@<VICTIM_IP>:~/
   ```

3. **Run the forwarder on the victim machine**:
   SSH into your victim machine and start the forwarder with root privileges (required to read `/var/log/auth.log` or `/var/log/secure`):
   ```bash
   sudo python3 ueba_forwarder.py http://192.168.1.50:8000
   ```
   *Expected terminal output:*
   ```text
   [*] CTEM UEBA Forwarder started.
   [*] Monitoring log file: /var/log/auth.log
   [*] Target CTEM Backend: http://192.168.1.50:8000/ueba/events
   [*] Waiting for authentication events (Ctrl+C to stop)...
   ```

---

### B. For Windows Victim Machines

Run this PowerShell command as **Administrator** on the Windows victim machine (streams Windows Security Event IDs `4625` for failed logins and `4624` for successful logins):

```powershell
$ctemServer = "http://192.168.1.50:8000/ueba/events"

Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4625 or EventID=4624)]]" -MaxEvents 1 | ForEach-Object {
    $type = if ($_.Id -eq 4625) { "failed_login" } else { "login" }
    $user = $_.Properties[5].Value
    $ip = $_.Properties[19].Value
    $body = @{ username = $user; event_type = $type; source_ip = $ip } | ConvertTo-Json
    Invoke-RestMethod -Uri $ctemServer -Method Post -Body $body -ContentType "application/json"
}
```

---

## Step 3: Run the Attack & Trigger Anomaly Detection

### Test Case 1: Brute-Force Attack (Rule 1: Failed Login Burst)

Simulate a password guessing attack against the victim machine's SSH service:

```bash
# From an attacker machine or terminal, run 6 rapid failed attempts:
for i in {1..6}; do
  sshpass -p "WrongPassword123!" ssh -o StrictHostKeyChecking=no admin@<VICTIM_IP>
done

# Or using Hydra:
hydra -l admin -P /usr/share/wordlists/rockyou.txt <VICTIM_IP> ssh
```

**Expected Detection Result**:
1. `ueba_forwarder.py` captures the auth failure events in real time:
   ```text
   [+] Forwarded to CTEM: failed_login | User: admin | IP: 192.168.1.80
   [+] Forwarded to CTEM: failed_login | User: admin | IP: 192.168.1.80
   ... (5th attempt)
   ```
2. The CTEM backend triggers:
   - **Alert Type**: `ueba_anomaly`
   - **Severity**: `HIGH`
   - **Title**: `Repeated failed logins for admin`
   - **Description**: `5 failed logins in the last 15 minutes`

---

### Test Case 2: New / Rogue Source IP (Rule 2: Geographic & Origin Drift)

Simulate a successful login originating from an IP address the user has never logged in from before:

```bash
curl -X POST http://192.168.1.50:8000/ueba/events \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "event_type": "login",
    "source_ip": "203.0.113.88"
  }'
```

**Expected Detection Result**:
- **Severity**: `MEDIUM`
- **Title**: `Login from new source IP for admin`
- **Description**: `First observed login from 203.0.113.88`

---

### Test Case 3: Off-Hours Activity (Rule 3: Temporal Anomaly)

Simulate a login occurring outside normal operating hours (between 22:00 and 06:00 UTC):

```bash
curl -X POST http://192.168.1.50:8000/ueba/events \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jdoe@corp.internal",
    "event_type": "login",
    "source_ip": "10.0.1.25",
    "occurred_at": "2026-09-17T03:30:00Z"
  }'
```

**Expected Detection Result**:
- **Severity**: `LOW`
- **Title**: `Off-hours login for jdoe@corp.internal`
- **Description**: `Login at 3:00 UTC, outside normal hours`

---

## Step 4: Monitor & Triage in the CTEM Dashboard

1. **Active Alerts Feed**: Open **[http://localhost:3000](http://localhost:3000)** (or **[http://localhost:3000/alerts](http://localhost:3000/alerts)**):
   - The high-severity brute-force incident will appear immediately in the alert table.
   - Operators can click **Ack** to acknowledge or **Resolve** to close the ticket.
2. **UEBA Identity Analytics Stream**: Open **[http://localhost:3000/monitoring](http://localhost:3000/monitoring)**:
   - Click the **"UEBA Analytics"** tab.
   - Inspect the table for real-time authentication events, usernames, source IPs, and timestamps.
