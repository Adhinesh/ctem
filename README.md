# 🛡️ Continuous Threat Exposure Management (CTEM) Platform

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-14.2-black?logo=next.js&logoColor=white)](https://nextjs.org/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![PostgreSQL / Supabase](https://img.shields.io/badge/Database-Supabase%20%2F%20PostgreSQL-3ECF8E?logo=supabase&logoColor=white)](https://supabase.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An enterprise-grade, proactive **Continuous Threat Exposure Management (CTEM)** platform designed to discover, contextualize, prioritize, and validate attack surface exposures across distributed hybrid environments.

Unlike traditional, periodic vulnerability scanners that generate unmanageable lists of disconnected CVEs, this platform operationalizes **Gartner's 5-stage CTEM framework**. It combines **automated external attack surface reconnaissance**, **continuous internal endpoint telemetry**, **graph-based blast radius modeling**, **User and Entity Behavior Analytics (UEBA)**, and **real-time attack drift detection** into a single unified security operations cockpit.

---

## 📑 Table of Contents

- [1. Executive Summary & Conceptual Overview](#1-executive-summary--conceptual-overview)
  - [The Shift: Vulnerability Scanning vs. CTEM](#the-shift-vulnerability-scanning-vs-ctem)
  - [The 5 Stages of the CTEM Framework](#the-5-stages-of-the-ctem-framework)
- [2. Platform Architecture & Data Flow](#2-platform-architecture--data-flow)
- [3. Core Subsystems & Technical Features](#3-core-subsystems--technical-features)
  - [Pillar 1: External Attack Surface & Recon Engine](#pillar-1-external-attack-surface--recon-engine)
  - [Pillar 2: Vulnerability Intelligence & Composite Risk Scoring](#pillar-2-vulnerability-intelligence--composite-risk-scoring)
  - [Pillar 3: Blast Radius & Attack Graph Modeling](#pillar-3-blast-radius--attack-graph-modeling)
  - [Pillar 4: Multi-Node Endpoint Monitoring Daemon (Agent Ecosystem)](#pillar-4-multi-node-endpoint-monitoring-daemon-agent-ecosystem)
  - [Pillar 5: Exposure Drift & UEBA Anomaly Engine](#pillar-5-exposure-drift--ueba-anomaly-engine)
  - [Pillar 6: Next.js 14 SOC Visualizer Dashboard](#pillar-6-nextjs-14-soc-visualizer-dashboard)
- [4. Technology Stack](#4-technology-stack)
- [5. Setup & Installation](#5-setup--installation)
  - [Option A: Turnkey Docker Deployment (Recommended)](#option-a-turnkey-docker-deployment-recommended)
  - [Option B: Native Local Development](#option-b-native-local-development)
  - [Database Migrations Guide](#database-migrations-guide)
- [6. Operation & Testing Guide](#6-operation--testing-guide)
  - [Operating the Web Dashboard](#operating-the-web-dashboard)
  - [Deploying Agents to Linux & Windows VMs](#deploying-agents-to-linux--windows-vms)
  - [Simulating Real Threat Scenarios & Testing Predefined Alert Rules](#simulating-real-threat-scenarios--testing-predefined-alert-rules)
- [7. REST API Documentation](#7-rest-api-documentation)
- [8. Current Limitations & Constraints](#8-current-limitations--constraints)
- [9. Future Scope & Roadmap](#9-future-scope--roadmap)
- [10. Project Directory Structure](#10-project-directory-structure)
- [11. Contributors & License](#11-contributors--license)

---

## 1. Executive Summary & Conceptual Overview

### The Shift: Vulnerability Scanning vs. CTEM

Traditional Vulnerability Management (VM) suffers from several systemic weaknesses:
1. **Context Blindness**: Prioritizes CVEs purely on CVSS severity (e.g., CVSS 9.8), ignoring whether the affected machine is Internet-facing, holds sensitive data, or is completely isolated.
2. **Periodic Blindspots**: Scans run on weekly or monthly schedules, creating visibility gaps when zero-day exposures emerge or engineers inadvertently open firewall ports.
3. **Alert Fatigue**: Security teams drown in thousands of theoretical CVEs with no clear insight into which vulnerabilities attackers can realistically chain to compromise crown jewels.

**CTEM solves this by shifting from "What is vulnerable?" to "What is exposed, reachable, and exploitable right now?"**

### The 5 Stages of the CTEM Framework

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      GARTNER CTEM CYCLE IN THIS PLATFORM               │
 │                                                                        │
 │   1. SCOPING       ──►  Domains, CIDRs, Cloud Tenants, Declared Assets │
 │         │                                                              │
 │   2. DISCOVERY     ──►  Subdomains (subfinder), Probing (httpx),       │
 │         │               Port Fingerprinting (nmap), URL Paths (gau)    │
 │         │                                                              │
 │   3. PRIORITIZE    ──►  Composite Score: CVSS + EPSS + Asset           │
 │         │               Criticality + Network Zone Weights             │
 │         │                                                              │
 │   4. VALIDATION    ──►  Blast Radius Reachability Graph, Lateral       │
 │         │               Movement Pivoting, Predefined Threat Rules     │
 │         │                                                              │
 │   5. MOBILIZATION  ──►  Containment Simulation (Subnet/Zone Isolation) │
 │                         Real-time Alerts & Guided Remediation          │
 └────────────────────────────────────────────────────────────────────────┘
```

1. **Scoping**: Define the attack surface perimeter, including external domains, subnets, cloud projects, and internally declared corporate machines.
2. **Discovery**: Rapid multi-engine reconnaissance to identify all active services, endpoints, listening sockets, and software versions.
3. **Prioritization**: Multi-factor risk calculation incorporating CVSS, EPSS (Exploit Prediction Scoring System), asset business criticality, and perimeter exposure.
4. **Validation**: Simulating how an adversary could pivot through the infrastructure using network topology graphs and reachability analysis.
5. **Mobilization**: Providing direct containment simulations (e.g., assessing the impact of isolating a subnet or severing an asset dependency) and actionable remediation workflows.

---

## 2. Platform Architecture & Data Flow

The platform utilizes a modular, decoupled microservices architecture with a shared persistence tier in PostgreSQL / Supabase:

```text
                              INTERNET / PERIMETER
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
        ┌───────────────────────┐             ┌───────────────────────┐
        │   EXTERNAL TARGETS    │             │   HYBRID VM NODES     │
        │   (Domains, IPs)      │             │  (Ubuntu & Windows)   │
        └───────────┬───────────┘             └───────────┬───────────┘
                    │                                     │
         Automated Recon Tools                 Telemetry, Logs, Port Drift,
         (subfinder, httpx, nmap)              UEBA & Process Hunting
                    │                                     │
                    ▼                                     ▼
     ┌───────────────────────────────────────────────────────────────────┐
     │                    FASTAPI BACKEND ENGINE (:8000)                 │
     │                                                                   │
     │  ┌───────────────────────┐             ┌───────────────────────┐  │
     │  │  Recon Runner         │             │  Agent Telemetry Svc  │  │
     │  │  (Subfinder/Nmap/GAU) │             │  (Heartbeat/Events)   │  │
     │  └───────────┬───────────┘             └───────────┬───────────┘  │
     │              │                                     │              │
     │  ┌───────────▼───────────┐             ┌───────────▼───────────┐  │
     │  │  Risk Scoring Engine  │             │  Exposure Drift Engine│  │
     │  │  (CVSS, EPSS, Critical│             │  & UEBA Rules Evaluator│ │
     │  └───────────┬───────────┘             └───────────┬───────────┘  │
     │              │                                     │              │
     │              └─────────────────┬───────────────────┘              │
     │                                │                                  │
     │                  ┌─────────────▼─────────────┐                    │
     │                  │  Blast Radius Graph Engine │                    │
     │                  │  (NetworkX Graph Topology) │                    │
     │                  └─────────────┬─────────────┘                    │
     └────────────────────────────────┼──────────────────────────────────┘
                                      │ REST API / WebSockets
                                      ▼
     ┌───────────────────────────────────────────────────────────────────┐
     │                    SUPABASE / POSTGRESQL DATABASE                 │
     │                                                                   │
     │  - assets            - open_ports        - risk_scores            │
     │  - scans             - security_events   - ueba_events            │
     │  - alerts            - asset_change_log  - asset_dependencies     │
     │  - declared_assets   - peripherals       - peripheral_allowlist   │
     └────────────────────────────────┬──────────────────────────────────┘
                                      │ Real-Time Sync / Queries
                                      ▼
     ┌───────────────────────────────────────────────────────────────────┐
     │                 NEXT.js 14 SOC DASHBOARD (:3000)                  │
     │                                                                   │
     │   [Assets Inventory]       [Interactive Blast Radius Graph]       │
     │   [Recon Scan Trigger]     [Live Exposure & Drift Feed]           │
     │   [Active Alerts Center]   [Hardware USB Authorization]           │
     └───────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Subsystems & Technical Features

### Pillar 1: External Attack Surface & Recon Engine
- **Multi-Vector Scanning**: Supports root domains (`example.com`), specific IP addresses (`192.168.1.10`), CIDR network ranges (`10.0.0.0/24`), and Cloud project accounts (`GCP/AWS`).
- **Orchestrated Reconnaissance Toolchain**:
  - `subfinder`: High-speed passive DNS subdomain enumeration.
  - `httpx`: Probe active HTTP/HTTPS services, gather title headers, TLS certificate details, and web server banners.
  - `nmap`: TCP SYN/Connect port scanning with service version detection (`-sV`).
  - `gau` (GetAllUrls): Discovers historical paths, parameters, and sensitive endpoints via AlienVault OTX, Wayback Machine, and Common Crawl.
- **Deduplication & Asset Life Cycle**: Resolves hosts to canonical IP addresses, reconciles duplicate discoveries, and categorizes network zones (`external`, `dmz`, `internal`, `cloud`).
- **Declared Assets Ingestion**: Dedicated REST endpoints (`POST /assets/declared`) for onboarding corporate workstations, firewalls, and internal servers provided directly by IT.

### Pillar 2: Vulnerability Intelligence & Composite Risk Scoring
- **NVD & Threat Feeds**: Correlates identified service banners with the **National Vulnerability Database (NVD)** API to retrieve known Common Vulnerabilities and Exposures (CVEs).
- **EPSS (Exploit Prediction Scoring System)**: Factors in real-time threat probabilities from FIRST.org to prioritize vulnerabilities actively targeted in the wild over academic flaws.
- **Context-Aware Composite Risk Formula**:
  $$\text{Composite Score} = (\text{Base CVSS} \times 0.4) + (\text{EPSS Probability} \times 10 \times 0.3) + (\text{Asset Criticality} \times 0.2) + (\text{Zone Exposure} \times 0.1)$$
- **Asset Criticality Indexing**: Weights assets based on business function (High: Domain Controllers, Databases; Medium: Application Servers; Low: Test Endpoints).

### Pillar 3: Blast Radius & Attack Graph Modeling
- **Graph Topology (NetworkX)**: Models infrastructure assets as nodes and their communication links (shared subnets, direct API dependencies, port access) as directed edges.
- **Lateral Movement Simulation**: Calculates the "Blast Radius" of every node—the downstream systems an attacker can reach if that specific node is compromised.
- **Interactive Containment Sandbox**:
  - Simulate **Subnet Isolation**: Evaluate how isolating a compromised subnet reduces lateral exposure.
  - Simulate **Severing Dependencies**: Model the security benefit of terminating compromised links before executing changes in production.
  - Simulate **Zone Quarantining**: Restrict traffic between `internal` and `dmz` zones.

### Pillar 4: Multi-Node Endpoint Monitoring Daemon (Agent Ecosystem)
A lightweight daemon designed for physical machines, cloud instances, and virtual machines (Ubuntu, Debian, Windows 10/11/Server):
- **Linux Python Agent (`ctem-agent`)**:
  - Zero external dependencies required (uses Python standard library; optional `psutil` for microsecond metrics).
  - Automatically tails `/var/log/auth.log` and `/var/log/syslog` for real-time PAM authentication, SSH logins, and sudo executions.
- **Windows PowerShell Agent (`windows_agent.ps1`)**:
  - Queries Windows Security Event Log for Event IDs `4624` (Successful Logon), `4625` (Failed Logon), and `4720` (User Account Created).
- **Process Anomaly Hunter**: Continuously scans running processes for penetration testing tools (`nc`, `ncat`, `netcat`, `socat`, `mimikatz`, `hydra`, `chisel`, `msfconsole`, `xmrig`) and webshell processes spawned under web server users (`www-data`, `nobody`, `nginx`).
- **Hardware & USB Peripheral Authorization**:
  - Detects connected USB hardware IDs.
  - Queries the central peripheral allowlist (`/peripherals/check`) to alert on rogue storage devices.
- **Zero-Loss Offline Resilient Buffer**:
  - If network connectivity is lost, events are queued locally in an SQLite buffer (`.agent_buffer.db`).
  - Once the backend is reachable, the queue is drained automatically with zero telemetry loss.

### Pillar 5: Exposure Drift & UEBA Anomaly Engine
- **Port Drift Detection**: Every heartbeat compares open TCP listening sockets against the baseline in `open_ports`. If a new port opens (e.g., an unauthorized backdoor), an immediate **Attack Surface Drift** alert is triggered.
- **Predefined Rule Triggers**:
  - **SSH / RDP Brute Force**: Triggers a **HIGH** severity alert if 5+ failed logins occur within a 15-minute window.
  - **Unknown Source IP**: Triggers a **MEDIUM** severity alert when a user logs in from an IP not previously associated with their profile.
  - **Off-Hours Logins**: Flags logins occurring between 22:00 and 06:00 UTC.
  - **Privilege Escalation**: Flags unauthorized `sudo` or administrator elevation.

### Pillar 6: Next.js 14 SOC Visualizer Dashboard
- **Modern Glassmorphism Interface**: Dark-mode interface designed with Tailwind CSS, Lucide icons, and server/client state management.
- **Real-Time Attack Graph Visualizer**: Interactive network map powered by Cytoscape / custom SVG nodes showing dependencies and lateral movement vectors.
- **Live Ingestion Feed**: Streaming view of heartbeats, process events, UEBA anomalies, and port drift.
- **Alert Triage Console**: High and critical alert triage with **Acknowledge** and **Resolve** action workflows.

---

## 4. Technology Stack

| Layer | Component | Description |
| :--- | :--- | :--- |
| **Frontend** | Next.js 14 (App Router) | Server-side rendered React 18 dashboard |
| | Tailwind CSS | Glassmorphism dark-mode UI design |
| | Lucide React | Clean icon set |
| | TypeScript | Strict end-to-end type safety |
| **Backend** | Python 3.11 + FastAPI | Asynchronous REST API & WebSockets |
| | NetworkX | Graph theory modeling for attack paths & blast radius |
| | Uvicorn | High-performance ASGI web server |
| | Pydantic v2 | Robust request/response schema validation |
| **Reconnaissance** | ProjectDiscovery Subfinder | Passive DNS enumeration |
| | ProjectDiscovery HTTPX | Fast multi-purpose HTTP prober |
| | Nmap | Network exploration and service version scanner |
| | GAU (GetAllUrls) | Historical URL and endpoint discovery |
| **Database** | Supabase / PostgreSQL | Relational storage with JSONB fields and RLS |
| **Agents** | Python 3.9+ Daemon | Linux/macOS cross-platform endpoint monitor |
| | PowerShell 5.1+ / 7+ | Native Windows endpoint monitor |
| | SQLite | Local offline resilience event queue |
| **DevOps** | Docker & Docker Compose | Multi-stage builds, alpine/bookworm slim images |

---

## 5. Setup & Installation

### Option A: Turnkey Docker Deployment (Recommended)

Docker Compose builds and spins up both the **FastAPI Backend** and the **Next.js Frontend** inside isolated network containers:

#### 1. Clone the repository
```bash
git clone https://github.com/your-username/ctem-platform.git
cd ctem-platform
```

#### 2. Configure Environment Variables
Copy the example environment file and customize your secrets:
```bash
cp .env.example .env
```
Ensure your `.env` contains your Supabase credentials:
```ini
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-service-role-key
NVD_API_KEY=your-optional-nvd-key
NEXT_PUBLIC_API_URL=http://localhost:8000
BLAST_RADIUS_REACHABILITY_MODE=same_subnet
```

#### 3. Launch via Docker
Execute the automated launcher:
```bash
chmod +x start.sh
./start.sh
```
*Or execute directly via Docker Compose:*
```bash
docker compose up --build -d
```

#### 4. Access the Platform
- **Frontend Dashboard**: [http://localhost:3000](http://localhost:3000)
- **Blast Radius Visualizer**: [http://localhost:3000/blast-radius](http://localhost:3000/blast-radius)
- **Exposure & Drift Feed**: [http://localhost:3000/monitoring](http://localhost:3000/monitoring)
- **Active Alerts Center**: [http://localhost:3000/alerts](http://localhost:3000/alerts)
- **Backend API & Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Option B: Native Local Development

#### 1. Backend Setup
```bash
cd ctem-backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate       # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 2. Frontend Setup
```bash
cd ctem-frontend

# Install dependencies
npm install

# Start Next.js development server
npm run dev
```

---

### Database Migrations Guide

The platform uses raw, repeatable SQL migrations located in `ctem-backend/migrations/`. Execute these in sequential order inside the **Supabase SQL Editor** or via `psql`:

1. `000_base_schema.sql`: Core tables (`assets`, `open_ports`, `risk_scores`, `asset_dependencies`).
2. `001_scans_and_zone.sql`: Scan tracking and network zone classification.
3. `002_risk_scores_blast_radius.sql`: Blast radius tracking and containment metrics.
4. `003_declared_assets_and_peripherals.sql`: Declared hardware assets and USB allowlists.
5. `004_team4_monitoring.sql`: SIEM logs, UEBA anomaly tracking, and alert lifecycle management.

---

## 6. Operation & Testing Guide

### Operating the Web Dashboard

1. **Triggering a Scan**:
   - Navigate to **Scans** (`/scans`).
   - Enter a target domain (`scanme.nmap.org`), IP, or CIDR block (`192.168.1.0/24`).
   - Select scan depth (Full Recon, Port Scan Only, Quick Probe).
   - Click **Start Scan** to view real-time recon streaming.
2. **Reviewing Asset Inventory**:
   - Navigate to **Assets** (`/assets`).
   - Filter by zone (`external`, `internal`, `dmz`), criticality (`high`, `medium`), or IP.
   - Click any asset to inspect discovered services, CVEs, and blast radius metrics.
3. **Exploring Blast Radius**:
   - Navigate to **Blast Radius** (`/blast-radius`).
   - Select a target node to visualize lateral movement paths.
   - Toggle **Isolate Subnet** to simulate containment effectiveness.

---

### Deploying Agents to Linux & Windows VMs

To test multi-node monitoring, deploy the agent to real virtual machines (Ubuntu, Debian, or Windows in VirtualBox, VMware, or Hyper-V).

#### Network Setup: Connecting VMs to Host
Ensure your VM network adapter allows reaching the host:
- **VirtualBox NAT**: Host is accessible at `http://10.0.2.2:8000`.
- **Bridged Adapter**: Host is accessible via its local LAN IP (e.g., `http://192.168.1.50:8000`).

#### 🐧 Deploy on an Ubuntu VM
```bash
# 1. Copy ctem-agent to the VM
scp -r ctem-agent username@<UBUNTU_VM_IP>:~/

# 2. SSH into the VM and run the automated deployment script
cd ~/ctem-agent
sudo ./scripts/deploy_ubuntu.sh http://<HOST_IP>:8000
```
*The installer automatically configures a background systemd service (`ctem-agent.service`), registers the VM into the database, and begins forwarding `/var/log/auth.log` telemetry.*

#### 🪟 Deploy on a Windows VM
Open PowerShell as Administrator:
```powershell
# Run the Windows agent targeting your host
powershell -ExecutionPolicy Bypass -File .\windows_agent.ps1 -CtemServer "http://<HOST_IP>:8000"
```
*The Windows agent immediately reads Windows Security Event Logs (IDs 4624, 4625, 4720) and streams active listening TCP ports.*

---

### Simulating Real Threat Scenarios & Testing Predefined Alert Rules

You can trigger predefined alert rules using real operating system events:

#### Test 1: SSH Brute-Force Attack (Rule: `brute_force_attack`)
- **Trigger**: Run 5 rapid failed SSH logins against your Ubuntu VM:
  ```bash
  for i in {1..6}; do ssh -o ConnectTimeout=2 invalid_user@<UBUNTU_VM_IP> || true; done
  ```
- **Result**:
  - `UebaMonitor` intercepts the bursts from `/var/log/auth.log`.
  - Backend flags a **HIGH** severity alert: `Brute Force Login Attack: 6 failed attempts`.
  - The alert appears on `/alerts` and under `/monitoring`.

#### Test 2: Rogue Backdoor Port Opening (Rule: `asset_change`)
- **Trigger**: Open an unauthorized listening port on the VM:
  ```bash
  nc -lvnp 4444
  ```
- **Result**:
  - `PortMonitor` detects port `4444/tcp` is newly opened.
  - Generates an **Exposure & Port Drift** alert: `New port opened on asset: 4444/tcp`.

#### Test 3: Sudo Privilege Escalation (Rule: `privilege_change`)
- **Trigger**: Execute a root command via sudo on the Ubuntu VM:
  ```bash
  sudo cat /etc/shadow
  ```
- **Result**:
  - `UebaMonitor` flags the privilege escalation event and streams it to the dashboard.

#### Test 4: Rogue Backdoor User Creation (Windows)
- **Trigger**: On your Windows VM, create an unauthorized user account:
  ```cmd
  net user ctem_backdoor Pass@123456 /add
  ```
- **Result**:
  - Windows Event ID `4720` is captured.
  - Backend logs a **HIGH** severity alert: `New local user account created: ctem_backdoor`.

---

## 7. REST API Documentation

The platform provides a comprehensive OpenAPI-compliant REST API. Full interactive documentation is available at `http://localhost:8000/docs`.

### Key Endpoints

| Category | Method | Endpoint | Description |
| :--- | :--- | :--- | :--- |
| **System** | `GET` | `/health` | Service and database health check |
| **Scans** | `POST` | `/scans` | Create and trigger a new recon scan |
| | `GET` | `/scans` | List all previous and active scans |
| | `GET` | `/scans/{scan_id}` | Get scan status and discovered assets |
| **Assets** | `GET` | `/assets` | Query asset inventory with filters |
| | `GET` | `/assets/{asset_id}` | Retrieve comprehensive asset detail |
| | `POST` | `/assets/declared` | Onboard IT-declared corporate devices |
| **Risk & Graph**| `GET` | `/risk/scores` | List prioritized risk scores |
| | `GET` | `/risk/blast-radius` | Calculate lateral movement reachability |
| | `POST` | `/risk/blast-radius/{id}/simulate` | Simulate containment (subnet/zone isolation) |
| | `GET` | `/risk/graph` | Export full network topology graph |
| **Agent** | `POST` | `/agent/register` | Auto-discovery endpoint registration |
| | `POST` | `/agent/heartbeat` | Health telemetry and port drift check |
| **Telemetry** | `POST` | `/logs/events` | Ingest process and security logs |
| | `POST` | `/ueba/events` | Ingest authentication and privilege events |
| **Alerts** | `GET` | `/alerts` | Query active and resolved security alerts |
| | `PATCH`| `/alerts/{alert_id}` | Acknowledge or resolve an alert |
| **Hardware** | `POST` | `/peripherals/check` | Validate USB device against hardware allowlist |

---

## 8. Current Limitations & Constraints

1. **Subnet-Level Reachability Heuristics**:
   - The blast radius engine assumes full lateral reachability between machines sharing the same `/24` subnet. In enterprise environments with micro-segmentation, Private VLANs (PVLANs), or host firewalls, reachability may be more constrained.
2. **Agent Polling Latency vs. Kernel eBPF**:
   - Sockets and processes are inspected via configurable periodic intervals (default: 30–60s) rather than kernel-level eBPF probes. Ephemeral processes that spawn and terminate in under 5 seconds may evade detection.
3. **Public Vulnerability Feed Rate Limits**:
   - Querying the NVD API without an explicit `NVD_API_KEY` is subject to strict IP rate limits (5 requests per 30-second rolling window). A free NVD API key is recommended for large scan sets.
4. **Single-Tenant Database Model**:
   - Currently, all assets share a single PostgreSQL schema. Multi-tenant segmentation across distinct business units requires separate database instances or tenant IDs.
5. **Recon Binary Dependencies**:
   - Automated recon requires system-level Go binaries (`subfinder`, `httpx`, `nmap`, `gau`). In Docker, these are pre-compiled and bundled, but native setups require manual binary installation.

---

## 9. Future Scope & Roadmap

- [ ] **Kernel-Level eBPF Telemetry**: Replace user-space process sampling on Linux with an eBPF probe (via Cilium Tetragon or BCC) to intercept raw system calls (`execve`, `connect`) in sub-milliseconds with zero CPU overhead.
- [ ] **Active Directory & BloodHound Graph Correlation**: Ingest Active Directory Kerberos and ACL relationships to trace identity-based privilege paths alongside IP reachability.
- [ ] **Automated SOAR Remediation Playbooks**:
  - Implement automated response webhooks that invoke host firewall rules (`iptables` / Windows Defender Firewall) to quarantine compromised endpoints.
- [ ] **Cloud-Native CSPM & Kubernetes Exposure**:
  - Direct connectors for AWS IAM, Google Cloud Asset Inventory, and Kubernetes Kube-apiserver exposure discovery.
- [ ] **Generative AI Threat Copilot**:
  - Fine-tuned LLM assistant to generate custom executive risk summaries and provide step-by-step remediation commands tailored to the operating system.

---

## 10. Project Directory Structure

```text
.
├── docker-compose.yml              # Multi-container orchestration (FastAPI + Next.js)
├── start.sh                        # One-click startup script for Linux/macOS
├── start.bat                       # One-click startup script for Windows
├── .env.example                    # Template configuration file
├── DOCKER_DEPLOYMENT_GUIDE.md      # Comprehensive Docker reference
├── VM_NODES_SETUP_AND_ALERT_GUIDE.md # Turnkey VM multi-node connection guide
├── UEBA_VICTIM_TESTING_GUIDE.md    # Penetration testing & simulation guide
├── QUICKSTART_FOR_FRIEND.txt       # Rapid onboarding guide
│
├── ctem-backend/                   # FastAPI REST API Backend
│   ├── Dockerfile                  # Multi-arch backend container with recon tools
│   ├── requirements.txt            # Python dependencies (FastAPI, NetworkX, etc.)
│   ├── app/
│   │   ├── main.py                 # ASGI entrypoint and router bindings
│   │   ├── config.py               # Environment and settings parser
│   │   ├── routers/                # REST API controllers
│   │   │   ├── scans.py            # Recon orchestration endpoints
│   │   │   ├── assets.py           # Asset inventory & declared device routes
│   │   │   ├── risk.py             # Risk scores, blast radius & simulations
│   │   │   ├── agent.py            # Agent registration and heartbeat
│   │   │   ├── ueba.py             # UEBA event processor & anomaly rules
│   │   │   ├── logs.py             # SIEM log ingestion
│   │   │   ├── alerts.py           # Alert lifecycle management
│   │   │   └── peripherals.py      # USB allowlist validation
│   │   ├── services/               # Core business logic
│   │   │   ├── recon_runner.py     # Subfinder, httpx, nmap execution pipeline
│   │   │   ├── blast_radius_service.py # NetworkX graph reachability algorithms
│   │   │   ├── risk_service.py     # CVSS, EPSS & composite risk calculator
│   │   │   └── nvd_service.py      # Vulnerability database client
│   │   └── db/
│   │       └── supabase_client.py  # Supabase client connector
│   └── migrations/                 # PostgreSQL relational database schemas
│       ├── 000_base_schema.sql
│       ├── 001_scans_and_zone.sql
│       ├── 002_risk_scores_blast_radius.sql
│       ├── 003_declared_assets_and_peripherals.sql
│       └── 004_team4_monitoring.sql
│
├── ctem-frontend/                  # Next.js 14 SOC Dashboard
│   ├── Dockerfile                  # Standalone multi-stage Next.js runner
│   ├── package.json                # React 18, Next.js, Tailwind dependencies
│   ├── app/
│   │   ├── page.tsx                # Dashboard summary & key metrics
│   │   ├── assets/                 # Asset inventory & detailed views
│   │   ├── scans/                  # Scan trigger and real-time streaming view
│   │   ├── blast-radius/           # Interactive attack path graph visualizer
│   │   ├── monitoring/             # Live drift & UEBA log ingestion feed
│   │   ├── alerts/                 # Security alerts triage center
│   │   └── peripherals/            # Hardware USB authorization manager
│   ├── components/                 # Reusable UI components & modals
│   └── lib/                        # API clients and utilities
│
└── ctem-agent/                     # Endpoint Telemetry Daemons
    ├── agent.py                    # Cross-platform Python monitoring daemon
    ├── windows_agent.ps1           # Native Windows PowerShell event monitor
    ├── ctem_agent/
    │   ├── collector.py            # System metrics & hardware collector
    │   ├── offline_queue.py        # SQLite persistent zero-loss buffer
    │   └── monitors/
    │       ├── port_monitor.py     # Active socket & port drift detector
    │       ├── ueba_monitor.py     # PAM & auth.log event parser
    │       ├── process_monitor.py  # Intrusion tool & webshell detector
    │       └── peripheral_monitor.py # USB hardware detector
    └── scripts/
        ├── deploy_ubuntu.sh        # Turnkey systemd service installer
        └── install_service.sh      # Generic daemon installer
```

---

## 11. Contributors, Leadership & License

<p align="center">
  <a href="https://github.com/Adhinesh"><img src="https://github.com/Adhinesh.png" width="52" height="52" alt="Dhinesh" style="border-radius:50%; margin:3px;" title="Dhinesh - Platform Architect & Integration" /></a>
  <a href="https://github.com/himanshdp"><img src="https://github.com/himanshdp.png" width="52" height="52" alt="Himansh Purswani" style="border-radius:50%; margin:3px;" title="Himansh Purswani - Team 1 Lead" /></a>
  <a href="https://github.com/avinashshankarpt"><img src="https://github.com/avinashshankarpt.png" width="52" height="52" alt="Avinash Shankar P T" style="border-radius:50%; margin:3px;" title="Avinash Shankar P T - Team 2 Lead" /></a>
  <a href="https://github.com/aaqibansarii"><img src="https://github.com/aaqibansarii.png" width="52" height="52" alt="Mohd Aaqib" style="border-radius:50%; margin:3px;" title="Mohd Aaqib - Team 3 Lead" /></a>
  <a href="https://github.com/Vijayashree4"><img src="https://github.com/Vijayashree4.png" width="52" height="52" alt="Vijayashree B" style="border-radius:50%; margin:3px;" title="Vijayashree B - Frontend Lead" /></a>
  <a href="https://github.com/yogeshagrahari"><img src="https://github.com/yogeshagrahari.png" width="52" height="52" alt="Yogesh Kumar Agrahari" style="border-radius:50%; margin:3px;" title="Yogesh Kumar Agrahari - Graph Traversal" /></a>
  <a href="https://github.com/Rutuja1025"><img src="https://github.com/Rutuja1025.png" width="52" height="52" alt="Rutuja Utekar" style="border-radius:50%; margin:3px;" title="Rutuja Utekar - Recon Engine" /></a>
  <a href="https://github.com/harvindersingh-cyber"><img src="https://github.com/harvindersingh-cyber.png" width="52" height="52" alt="Harvinder Singh" style="border-radius:50%; margin:3px;" title="Harvinder Singh - Banner Parser & Cloud Recon" /></a>
  <a href="https://github.com/VKAnupama"><img src="https://github.com/VKAnupama.png" width="52" height="52" alt="V K Anupama" style="border-radius:50%; margin:3px;" title="V K Anupama - Database & Drift Engine" /></a>
  <a href="https://github.com/ronak564"><img src="https://github.com/ronak564.png" width="52" height="52" alt="Ronak Sajeev" style="border-radius:50%; margin:3px;" title="Ronak Sajeev - Asset Zones" /></a>
  <a href="https://github.com/vibhuti93"><img src="https://github.com/vibhuti93.png" width="52" height="52" alt="Vibhuti Kumar" style="border-radius:50%; margin:3px;" title="Vibhuti Kumar - CVE Engine & SLAs" /></a>
  <a href="https://github.com/Virus9T"><img src="https://github.com/Virus9T.png" width="52" height="52" alt="Tanay Sengupta" style="border-radius:50%; margin:3px;" title="Tanay Sengupta - CVE Signature Cache" /></a>
  <a href="https://github.com/Aksh465"><img src="https://github.com/Aksh465.png" width="52" height="52" alt="Akash Bangera" style="border-radius:50%; margin:3px;" title="Akash Bangera - Risk Scoring Formula" /></a>
  <a href="https://github.com/dhana2138"><img src="https://github.com/dhana2138.png" width="52" height="52" alt="Dhanavelan" style="border-radius:50%; margin:3px;" title="Dhanavelan - Risk Heatmap Matrix" /></a>
  <a href="https://github.com/rahildudekula"><img src="https://github.com/rahildudekula.png" width="52" height="52" alt="Rahil" style="border-radius:50%; margin:3px;" title="Rahil - SIEM Ingestion & UEBA" /></a>
</p>

- **Platform Architecture & Engineering**: Directed by [Dhinesh](https://github.com/Adhinesh) (`@Adhinesh`) — Supabase client layer, alert engine, agent hardware monitoring & integration.
- **Technical Leadership & Project Supervision**:
  - **Team 1 Lead**: [Himansh Purswani](https://github.com/himanshdp?tab=repositories) (`@himanshdp`) — Attack Surface Discovery & Reconnaissance Engine
  - **Team 2 Lead**: [Avinash Shankar P T](https://github.com/avinashshankarpt) (`@avinashshankarpt`) — Asset Inventory, Database Architecture & Change Detection
  - **Team 3 Lead**: [Mohd Aaqib](https://github.com/aaqibansarii) (`@aaqibansarii`) — Vulnerability Ingestion & Multi-Factor Risk Engine
  - **Team 4 Leadership**: Managed collectively by all Team Leads (*Himansh Purswani, Avinash Shankar P T, Mohd Aaqib*) — Graph Topology, SIEM Ingestion, UEBA Analytics & System Integration
- **Engineering Team**: Built by a collaborative team of security researchers and software engineers across 5 specialized focus areas. See the full breakdown of individual contributions, modules, and code files in [CONTRIBUTORS.md](CONTRIBUTORS.md).
- **License**: Released under the [MIT License](LICENSE). Feel free to use, modify, and distribute for academic, research, or enterprise security operations.
