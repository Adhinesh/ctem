# CTEM Platform - Ubuntu & Windows VM Multi-Node Monitoring Guide

This guide explains how to connect your **Ubuntu VM** and **Windows VM** to your host machine running the **CTEM Platform**, forward real operating system authentication and security logs, and trigger **predefined alert rules** based on real activities (not simulations).

---

## 🏛 Network Architecture

```text
  ┌─────────────────────────────────┐           ┌─────────────────────────────────┐
  │           UBUNTU VM             │           │           WINDOWS VM            │
  │  - Real /var/log/auth.log       │           │  - Real Windows Security Log    │
  │  - Real SSH / PAM authentication│           │  - Event IDs 4625, 4624, 4720   │
  │  - Open ports & drift detection │           │  - Open TCP listening ports     │
  │  - Running: ctem-agent (daemon) │           │  - Running: windows_agent.ps1   │
  └────────────────┬────────────────┘           └────────────────┬────────────────┘
                   │                                             │
                   │ HTTP POST (Telemetry, Logs & UEBA)          │ HTTP POST (Telemetry, Logs & UEBA)
                   ▼                                             ▼
  ┌───────────────────────────────────────────────────────────────────────────────┐
  │                         HOST MACHINE RUNNING CTEM                             │
  │                                                                               │
  │   - CTEM Backend API  : http://<HOST_IP>:8000                                 │
  │   - Rules Engine      : UEBA, Exposure & Port Drift, Threat Process Engine    │
  │   - Central Database  : Supabase (assets, open_ports, security_events, alerts)│
  │   - Web Dashboard     : http://localhost:3000                                 │
  └───────────────────────────────────────────────────────────────────────────────┘
```

---

## 🌐 Step 1: Network Setup between Host & VMs

To allow your VMs to connect to the CTEM backend running on your host machine:

### 1. Ensure the CTEM Backend is Listening on All Interfaces (`0.0.0.0`)
On your host terminal:
```bash
cd ctem-backend
venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```
*(The backend is already running on `0.0.0.0:8000`)*

### 2. Identify the Host IP Address Accessible by the VMs
Check the network adapter of your virtualization software (VirtualBox, VMware, Hyper-V, UTM, or Parallels):

| VM Network Mode | What Host URL to Use from Inside the VM |
| :--- | :--- |
| **VirtualBox NAT (Default)** | `http://10.0.2.2:8000` |
| **VMware NAT** | `http://192.168.x.1:8000` *(Run `ipconfig` / `ifconfig` on host to find vmnet IP)* |
| **Bridged Adapter** *(Recommended)* | `http://<HOST_LAN_IP>:8000` *(e.g. `http://192.168.1.50:8000`)* |
| **Host-Only Adapter** | `http://<HOST_ONLY_IP>:8000` *(e.g. `http://192.168.56.1:8000`)* |

> **Quick Connectivity Test from any VM terminal:**
> - Linux / macOS: `curl -s http://<HOST_IP>:8000/health`
> - Windows PowerShell: `Invoke-RestMethod http://<HOST_IP>:8000/health`
> *Expected response:* `{"status":"ok"}`

---

## 🐧 Step 2: Deploy on Ubuntu VM (Linux Node)

### A. Copy the Agent to the Ubuntu VM
From your host machine, copy the `ctem-agent` directory to your Ubuntu VM:
```bash
scp -r ctem-agent <username>@<UBUNTU_VM_IP>:~/
```

### B. Run the Automated Ubuntu Deployment Script
SSH into your Ubuntu VM and run:
```bash
cd ~/ctem-agent
sudo ./scripts/deploy_ubuntu.sh http://<HOST_IP>:8000
```
*(Replace `<HOST_IP>` with your host IP, e.g., `10.0.2.2` for VirtualBox NAT or `192.168.1.50` for Bridged)*

**What this automatically does:**
1. Connects to the CTEM host and discovers host metadata.
2. Auto-registers the Ubuntu VM into the CTEM Platform as a **Server / Endpoint**.
3. Automatically tails `/var/log/auth.log` and `/var/log/syslog` for real-time authentication events.
4. Scans listening ports and establishes the open-port baseline.
5. Installs and starts a persistent **systemd background service** (`ctem-agent.service`).

---

## 🪟 Step 3: Deploy on Windows VM (Windows Node)

On Windows, you can use the lightweight, zero-dependency **PowerShell Agent** (`windows_agent.ps1`) pre-packaged in `ctem-agent`:

### A. Copy the Windows Agent Script to the Windows VM
Copy `ctem-agent/windows_agent.ps1` to your Windows VM (e.g. using Shared Folders, RDP clipboard, or SCP).

### B. Run the Windows Agent as Administrator
Open **PowerShell as Administrator** on your Windows VM and execute:
```powershell
powershell -ExecutionPolicy Bypass -File .\windows_agent.ps1 -CtemServer http://<HOST_IP>:8000
```
*(Example for VirtualBox NAT: `powershell -ExecutionPolicy Bypass -File .\windows_agent.ps1 -CtemServer http://10.0.2.2:8000`)*

**What this automatically does on Windows:**
1. Collects Windows system information (ComputerName, IPv4, Windows OS version, RAM, CPU).
2. Auto-registers the Windows node in the CTEM central database.
3. Subscribes in real-time to the **Windows Security Event Log**:
   - **Event ID 4625**: Failed Logons (brute-force password guessing).
   - **Event ID 4624**: Successful Logons (Interactive, RDP, or Network logons).
   - **Event ID 4672**: Special Administrative Privileges Assigned.
   - **Event ID 4720**: New User Accounts Created.
4. Monitors Windows listening ports (`netstat` / `Get-NetTCPConnection`) and detects port opening anomalies.
5. Scans running processes for hacker tools (`mimikatz`, `nc.exe`, `chisel.exe`, `xmrig.exe`).

---

## 🎯 Step 4: Real-World Attack Scenarios & Verifying Alert Rules

Once your Ubuntu and Windows nodes are connected, perform the following real actions on the VMs to verify that the **predefined rules** raise alerts on your CTEM Platform dashboard:

---

### Test Case 1: Real SSH Brute-Force Password Guessing (Ubuntu Node)
**Predefined Rule**: `ueba_anomaly` - Repeated failed logins (Threshold: 5+ failed attempts in 15 minutes)

1. From your host or attacker machine, run 6 failed SSH login attempts against your Ubuntu VM:
   ```bash
   for i in {1..6}; do
     ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 testuser@<UBUNTU_VM_IP>
   done
   ```
2. **What Happens:**
   - The Ubuntu SSH daemon logs the failed attempts in `/var/log/auth.log`.
   - `ctem-agent` immediately parses each failure and forwards it to `POST /ueba/events`.
   - The backend rule engine reaches the 5-attempt threshold and creates an incident.
3. **Verification in CTEM Web App:**
   - Open **[http://localhost:3000/alerts](http://localhost:3000/alerts)**:
   - **Severity**: `HIGH`
   - **Title**: `Repeated failed logins for testuser`
   - **Description**: `5 failed logins in the last 15 minutes`

---

### Test Case 2: Real Failed Logon Attack on Windows (Windows Node)
**Predefined Rule**: `ueba_anomaly` - Repeated failed logins via Windows Security Event ID 4625

1. On your Windows VM or from a remote terminal, generate 6 failed authentication attempts:
   ```cmd
   net use \\127.0.0.1\IPC$ /user:fakeadmin WrongPassword123!
   net use \\127.0.0.1\IPC$ /user:fakeadmin WrongPassword123!
   net use \\127.0.0.1\IPC$ /user:fakeadmin WrongPassword123!
   net use \\127.0.0.1\IPC$ /user:fakeadmin WrongPassword123!
   net use \\127.0.0.1\IPC$ /user:fakeadmin WrongPassword123!
   net use \\127.0.0.1\IPC$ /user:fakeadmin WrongPassword123!
   ```
2. **What Happens:**
   - Windows writes Event ID `4625` to the Security Event Log.
   - `windows_agent.ps1` detects Event 4625, extracts the username and IP, and forwards it to `/ueba/events`.
3. **Verification in CTEM Web App:**
   - Open **[http://localhost:3000/alerts](http://localhost:3000/alerts)**:
   - **Severity**: `HIGH`
   - **Title**: `Repeated failed logins for fakeadmin`

---

### Test Case 3: Rogue Windows User Account Created (Windows Node)
**Predefined Rule**: `account_created` - Administrative persistence indicator

1. On your Windows VM (in Administrator command prompt), simulate an attacker creating a backdoor user account:
   ```cmd
   net user ctem_backdoor Passw0rd123! /add
   ```
2. **What Happens:**
   - Windows logs Event ID `4720` (A user account was created).
   - `windows_agent.ps1` immediately intercepts Event 4720 and forwards a high-severity security event to `/logs/events`.
3. **Verification in CTEM Web App:**
   - Open **[http://localhost:3000/alerts](http://localhost:3000/alerts)**:
   - **Severity**: `HIGH`
   - **Title**: `high severity event: account_created`
   - **Description**: `New user account created on Windows Node: 'ctem_backdoor' (Event ID 4720)`

---

### Test Case 4: Rogue Backdoor Port Opened (Ubuntu or Windows Node)
**Predefined Rule**: `asset_change` - Attack Surface & Port Drift Detection

1. On your Ubuntu VM, open a listening listener simulating a reverse shell or backdoor:
   ```bash
   nc -lvnp 4444
   ```
2. **What Happens:**
   - The agent's PortMonitor scans listening TCP sockets on the VM.
   - It detects the new port `4444/tcp` (classified as suspicious Metasploit port) and reports it to `/agent/heartbeat`.
   - The platform synchronizes `open_ports` and triggers `change_detection_service`.
3. **Verification in CTEM Web App:**
   - Open **[http://localhost:3000/alerts](http://localhost:3000/alerts)**:
   - **Severity**: `HIGH` / `MEDIUM`
   - **Title**: `New port opened on asset`
   - **Description**: `Port 4444/tcp newly detected`
   - Open **[http://localhost:3000/monitoring](http://localhost:3000/monitoring)** -> **"Exposure & Drift Engine"** tab to see the port timeline.

---

### Test Case 5: Sudo Privilege Escalation (Ubuntu Node)
**Predefined Rule**: `privilege_change` - Administrative command execution tracking

1. On your Ubuntu VM, run a command as root using sudo:
   ```bash
   sudo cat /etc/shadow
   ```
2. **What Happens:**
   - The sudoers session is recorded in `/var/log/auth.log`.
   - The agent detects the privilege escalation command and forwards it to `/ueba/events`.
3. **Verification in CTEM Web App:**
   - Open **[http://localhost:3000/monitoring](http://localhost:3000/monitoring)** -> **"UEBA Identity Analytics"** tab:
   - See the real-time row logged with Event Type `privilege_change`.

---

## 📊 Summary of Active CTEM Views

| Page | URL | What You See From Connected Nodes |
| :--- | :--- | :--- |
| **Assets Inventory** | `http://localhost:3000/assets` | Live list of your Ubuntu VM, Windows VM, and host with status `confirmed`, operating system, IP address, and open ports. |
| **Security Alerts** | `http://localhost:3000/alerts` | Real-time alerts raised by the predefined rules (Brute-force bursts, rogue IPs, webshells, new ports, unauthorized accounts). Supports **Acknowledge** and **Resolve** workflow. |
| **Security Logs Feed** | `http://localhost:3000/monitoring` *(Tab 1)* | Continuous live stream of telemetry heartbeats (CPU, RAM, Disk) and system logs from all connected nodes. |
| **UEBA Identity Analytics** | `http://localhost:3000/monitoring` *(Tab 2)* | Real-time authentication stream of user logins, failed attempts, and privilege escalations. |
| **Exposure & Drift Engine** | `http://localhost:3000/monitoring` *(Tab 3)* | Historical timeline of opened and closed ports across all your VM nodes. |
