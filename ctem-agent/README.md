# CTEM Platform - Continuous Asset Monitoring & Log Forwarding Agent

The **CTEM Agent** (`ctem-agent`) is a lightweight, cross-platform, enterprise-grade endpoint security daemon designed to monitor host assets continuously and forward telemetry, security logs, authentication events, and drift anomalies to your central CTEM Platform backend and database.

---

## 🏛 Architecture Overview

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      MONITORED ASSET / ENDPOINT                        │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                      CTEM AGENT DAEMON                         │   │
│   │                                                                │   │
│   │  - SystemCollector   : CPU, RAM, Disk, Uptime, OS, Hardware    │   │
│   │  - PortMonitor       : Listening ports & Attack Surface Drift  │   │
│   │  - LogMonitor        : System logs, syslog, audit logs         │   │
│   │  - UebaMonitor       : Auth logins, failed logins, sudo        │   │
│   │  - ProcessMonitor    : Webshells, reverse shells, tools        │   │
│   │  - PeripheralMonitor : USB devices & authorization check       │   │
│   │  - OfflineQueue      : SQLite buffer for zero log loss         │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
└───────────────────────────────────┼────────────────────────────────────┘
                                    │ HTTP REST API
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   CTEM PLATFORM BACKEND (:8000)                        │
│                                                                        │
│  - POST /agent/register     -> Auto-registers host into assets table   │
│  - POST /agent/heartbeat    -> Updates telemetry & detects port drift  │
│  - POST /logs/events        -> Ingests SIEM/Security events            │
│  - POST /ueba/events        -> Evaluates UEBA Anomaly Rules Engine     │
│  - POST /peripherals/check  -> Checks hardware allowlist               │
│                                   │                                    │
│                                   ▼                                    │
│                    CENTRAL SUPABASE / POSTGRES DB                      │
│        (assets, open_ports, security_events, alerts, ueba)             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   CTEM PLATFORM FRONTEND (:3000)                       │
│                                                                        │
│  - Asset Inventory (/assets)     : Live status, ports, criticality     │
│  - Monitoring Feed (/monitoring) : Real-time logs, UEBA & port drift   │
│  - Active Alerts (/alerts)       : High/Critical severity detections   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Capabilities

1. **Host Auto-Discovery & Self-Registration**:
   - Gathers hostname, primary IP, MAC address, OS name, version, architecture, CPU count, and RAM size.
   - Self-registers with the CTEM platform and persists its assigned `asset_id` in `.agent_state.json`.

2. **System Health & Continuous Heartbeat**:
   - Continuously samples CPU usage, memory utilization, disk space, load averages, and uptime.
   - Emits critical alerts if disk or CPU utilization exceeds 95%.

3. **Attack Surface & Port Drift Detection**:
   - Continuously monitors active listening TCP ports.
   - Detects newly opened ports (e.g., unauthorized backdoor, unexpected service) or closed ports.
   - Automatically synchronizes with the CTEM platform's `open_ports` and `asset_change_log` tables, triggering alerts in the Exposure & Drift Engine.

4. **Continuous UEBA (User & Entity Behavior Analytics)**:
   - Streams SSH/PAM logins, failed login bursts (brute-force attacks), and privilege escalations (`sudo`/`su`) to `/ueba/events`.
   - Triggers automated alerts:
     - **High Severity**: 5+ failed logins within 15 minutes.
     - **Medium Severity**: First-time login from an unknown source IP.
     - **Low Severity**: Off-hours login (22:00 - 06:00 UTC).

5. **Threat & Process Anomaly Detection**:
   - Periodically scans the process table for offensive intrusion tools (`nc`, `netcat`, `ncat`, `socat`, `hydra`, `mimikatz`, `chisel`, `msfconsole`, `xmrig`).
   - Detects webshells (interactive shells spawned under `www-data`, `nobody`, `nginx`, `apache`).
   - Forwards critical severity events directly to `/logs/events`.

6. **Hardware & USB Peripheral Monitoring**:
   - Discovers connected USB devices and queries CTEM's peripheral allowlist (`/peripherals/check`).
   - Emits alerts if unauthorized removable media is plugged in.

7. **Zero-Loss Offline Resilient Buffer**:
   - If the CTEM server or network drops, all events and logs are queued locally in an SQLite buffer (`.agent_buffer.db`).
   - Automatically drains and flushes queued events when connectivity is restored.

---

## ⚡ Quickstart

### 1. Requirements
- Python 3.9+ (Works out of the box with standard library; no extra packages required!)
- Optional: `pip install -r requirements.txt` (installs `psutil` for enhanced metric precision)

### 2. Inspect Host Status
```bash
python3 agent.py status
```
*Displays system hardware, resource utilization, registered asset ID, and CTEM server connectivity.*

### 3. Run End-to-End Diagnostic Test
```bash
python3 agent.py test
```
*Tests API health, host discovery, asset registration, telemetry heartbeat, log forwarding, and UEBA event streaming.*

### 4. Inspect Listening Ports
```bash
python3 agent.py scan-ports
```

### 5. Start Continuous Monitoring Daemon
```bash
python3 agent.py run
```
*To specify a custom CTEM server:*
```bash
python3 agent.py run --server http://192.168.1.50:8000
```

---

## 🧪 Simulating Attacks & Verifying Alerts

To test that alerts flow from the agent to the central database and dashboard:

### Test Case 1: Brute-Force Password Guessing (UEBA Burst)
```bash
python3 agent.py simulate --attack bruteforce
```
- Sends 6 rapid failed logins for `victim_admin`.
- **Expected Alert**: `Repeated failed logins for victim_admin` (**HIGH** severity) on `http://localhost:3000/alerts`.

### Test Case 2: Web Shell Execution
```bash
python3 agent.py simulate --attack webshell
```
- Simulates detection of `/bin/bash` spawned by `www-data`.
- **Expected Alert**: `critical severity event: webshell_spawned` (**CRITICAL** severity).

### Test Case 3: Rogue Source IP Login
```bash
python3 agent.py simulate --attack rogue_ip
```
- Simulates user login from an unfamiliar external IP (`203.0.113.77`).
- **Expected Alert**: `Login from new source IP for analyst_jane` (**MEDIUM** severity).

### Test Case 4: Suspicious Backdoor Port
```bash
python3 agent.py simulate --attack suspicious_port
```
- Simulates opening port 4444/tcp (Metasploit handler).
- **Expected Alert**: `New port opened on asset: 4444/tcp` (**HIGH** severity).

---

## ⚙️ Configuration Options

The agent can be configured via `config.json`, environment variables, or CLI arguments:

| Setting | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `server_url` | `CTEM_SERVER_URL` | `http://127.0.0.1:8000` | Target CTEM backend endpoint |
| `asset_id` | `CTEM_ASSET_ID` | *Auto-assigned* | Fixed UUID of the asset (or cached from state) |
| `hostname` | `CTEM_HOSTNAME` | System Hostname | Machine identifier |
| `asset_type` | `CTEM_ASSET_TYPE` | `endpoint` | `endpoint`, `server`, `vps`, `computer`, `laptop` |
| `zone` | `CTEM_ZONE` | `internal` | `internal` or `external` |
| `criticality` | `CTEM_CRITICALITY` | `medium` | `low`, `medium`, `high`, `critical` |
| `heartbeat_interval`| `CTEM_HEARTBEAT_INTERVAL`| `30` | Seconds between telemetry heartbeats |
| `port_scan_interval`| `CTEM_PORT_SCAN_INTERVAL`| `60` | Seconds between open port scans |
| `process_scan_interval`| `CTEM_PROCESS_SCAN_INTERVAL`| `30` | Seconds between suspicious process scans |
| `enable_logs` | `CTEM_ENABLE_LOGS` | `true` | Enable/disable auth and syslog tailing |
| `enable_ueba` | `CTEM_ENABLE_UEBA` | `true` | Enable/disable UEBA anomaly streaming |
| `enable_ports` | `CTEM_ENABLE_PORTS` | `true` | Enable/disable open port drift detection |
| `enable_processes` | `CTEM_ENABLE_PROCESSES` | `true` | Enable/disable process threat detection |
| `custom_log_paths`| - | `[]` | Extra custom log files to tail |

---

## 📦 Deployment as a System Service

To run the agent continuously in the background on boot:

### On Linux (Ubuntu / Debian / RHEL / CentOS)
```bash
sudo python3 agent.py install-service
sudo systemctl daemon-reload
sudo systemctl enable --now ctem-agent
sudo systemctl status ctem-agent
```

### On macOS
```bash
python3 agent.py install-service
launchctl load -w ~/Library/LaunchAgents/com.ctem.agent.plist
```

---

## 📊 Viewing Telemetry in CTEM Web Dashboard

1. **Assets View** (`http://localhost:3000/assets`):
   - Your monitored machine will appear with its Hostname, IP, Asset Type, Zone, Criticality, and status `confirmed`.
   - Click on the asset to view its discovered open ports.

2. **Monitoring Logs & UEBA** (`http://localhost:3000/monitoring`):
   - **Tab 1 (Security Logs)**: Real-time heartbeats, system alerts, and suspicious process detections.
   - **Tab 2 (UEBA Identity Analytics)**: Real-time authentication events, logins, and failed attempts.
   - **Tab 3 (Exposure & Drift Engine)**: Track newly opened or closed network ports.

3. **Active Alerts** (`http://localhost:3000/alerts`):
   - Triage high/critical incidents, acknowledge alerts, or mark them resolved.
