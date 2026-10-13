# 🐳 CTEM Platform - Docker Containerization & Deployment Guide

This guide provides end-to-end instructions for running the **Continuous Threat Exposure Management (CTEM) Platform** inside Docker containers on any operating system (Windows, macOS, Linux, or a remote Cloud/VPS server).

---

## 🏗️ Architecture Overview

The containerized CTEM platform runs as two connected services orchestrated via Docker Compose:

```
                          ┌────────────────────────────────────────────────────────┐
                          │                   Docker Host Machine                  │
                          │                                                        │
┌──────────────────┐      │  ┌────────────────────────┐  ┌──────────────────────┐  │      ┌─────────────────────────┐
│ User Web Browser │─────┼─▶│     ctem-frontend      │  │     ctem-backend     │◀─┼─────▶│  Supabase Cloud Database│
│  (Port 3000)     │      │  │  (Next.js 14 + React)  │  │  (FastAPI + Python)  │  │      │  (PostgreSQL + Storage) │
└──────────────────┘      │  └────────────────────────┘  └──────────────────────┘  │      └─────────────────────────┘
                          │                ▲                         ▲             │
                          │                │   ctem-network (bridge) │             │
                          │                └─────────────────────────┘             │
                          │                                                        │
                          │   Integrated Recon Tools in Backend:                   │
                          │   • Subfinder • ProjectDiscovery HTTPX • Nmap • GAU    │
                          └────────────────────────────────────────────────────────┘
```

| Service | Technology | Internal Port | Host Port | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **`frontend`** | Next.js 14, React 18, Tailwind CSS | `3000` | `3000` | Web dashboard, interactive Blast Radius visualizer, scans manager |
| **`backend`** | FastAPI, Python 3.11, Nmap, Subfinder, Httpx, GAU | `8000` | `8000` | Recon engine, risk scoring, lateral movement simulation, REST API |
| **`database`** | Supabase (Cloud PostgreSQL) | Cloud | Cloud | Relational persistence for assets, dependencies, risk scores, events |

---

## 📋 System Prerequisites

Install Docker on the target system according to its operating system:

### 1. Windows 10 / 11
- Install **[Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/)**.
- Ensure **WSL 2 (Windows Subsystem for Linux)** is enabled in Docker Desktop settings.
- Hardware virtualization must be enabled in your BIOS/UEFI.

### 2. macOS (Apple Silicon M1/M2/M3/M4 or Intel)
- Install **[Docker Desktop for Mac](https://www.docker.com/products/docker-desktop/)**.
- Start Docker Desktop and verify the whale icon appears in the menu bar.

### 3. Linux (Ubuntu, Debian, Fedora, CentOS)
- Install Docker Engine and the Docker Compose plugin:
  ```bash
  # Example for Ubuntu/Debian:
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker $USER
  newgrp docker
  ```
- Verify installation:
  ```bash
  docker --version
  docker compose version
  ```

---

## 🚀 Step-by-Step Deployment Guide

### Step 1: Set Up the Supabase Database (One-Time Setup)

The CTEM platform uses Supabase for database storage. If you already have a Supabase project, skip to **1.2**.

#### 1.1 Create a Free Supabase Project
1. Go to [https://supabase.com](https://supabase.com) and sign in.
2. Click **"New Project"**.
3. Choose an organization, project name (e.g. `ctem-prod`), database password, and region.
4. Wait 1–2 minutes for the database to provision.

#### 1.2 Run the Consolidated Schema Migration
1. In your Supabase Dashboard, click on **"SQL Editor"** (terminal icon in left menu).
2. Click **"New query"**.
3. Open [`ctem-backend/migrations/000_full_schema_all_migrations.sql`](file:///Users/dhinesh/Downloads/new%2001/ctem-backend/migrations/000_full_schema_all_migrations.sql) from this project.
4. Copy the entire file content, paste it into the Supabase SQL Editor, and click **"Run"**.
5. You should see `Success. No rows returned`. All tables (`assets`, `open_ports`, `risk_scores`, `asset_dependencies`, `scans`, `alerts`, etc.) are now created with proper indexes and permissions!

#### 1.3 Obtain Your API Keys
1. In Supabase, navigate to **Project Settings** (gear icon) → **API**.
2. Copy two values:
   - **Project URL** (e.g. `https://abcdefghijkl.supabase.co`)
   - **Project API Key** (use `service_role` secret key for backend, or `anon` key)

---

### Step 2: Copy the Project to the Other System

Transfer the project directory to the other machine using git, USB drive, or SCP/SFTP:

```bash
# Option A: If using Git
git clone <your-repository-url> ctem-platform
cd ctem-platform

# Option B: If transferring as ZIP or folder
cd /path/to/ctem-platform
```

Ensure the following root structure exists:
```
ctem-platform/
├── docker-compose.yml
├── .env.example
├── start.sh
├── start.bat
├── ctem-backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app/
│   └── migrations/
└── ctem-frontend/
    ├── Dockerfile
    ├── package.json
    ├── app/
    └── components/
```

---

### Step 3: Configure Environment Variables

1. Copy the `.env.example` template to `.env`:
   ```bash
   # On macOS / Linux:
   cp .env.example .env

   # On Windows (PowerShell or CMD):
   copy .env.example .env
   ```

2. Open `.env` in any text editor and paste your Supabase credentials:
   ```env
   # ==============================================================================
   # Supabase Configuration
   # ==============================================================================
   SUPABASE_URL=https://your-project-id.supabase.co
   SUPABASE_KEY=your-supabase-service-role-or-anon-key

   # Optional: NVD API Key for higher rate-limit CVE lookups
   NVD_API_KEY=

   # Optional: Blast Radius Reachability Mode (same_subnet | same_zone | dependency_edges | combined)
   BLAST_RADIUS_REACHABILITY_MODE=same_subnet

   # Frontend API Base URL (leave default for localhost, or change if running on remote server)
   NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
   ```

---

### Step 4: Build and Start Containers

#### Option A: Using the Automated Launch Scripts

- **On macOS / Linux**:
  ```bash
  ./start.sh
  ```
- **On Windows**:
  Double-click `start.bat` or run:
  ```cmd
  start.bat
  ```

#### Option B: Using Standard Docker Compose Commands

Run the following command in the root folder:

```bash
docker compose up --build -d
```

> **Note:** The initial build takes approximately 2–3 minutes because it compiles the Go recon tools (`subfinder`, `httpx`, `gau`) in an isolated builder stage and creates the production Next.js standalone build. Subsequent runs will start in **seconds** using Docker build cache.

---

### Step 5: Verify Running Services

Check the status of both containers:

```bash
docker compose ps
```

You should see both containers in a `healthy` state:

```
NAME            IMAGE                    COMMAND                  SERVICE    STATUS                    PORTS
ctem-backend    ctem-platform-backend    "uvicorn app.main:ap…"   backend    Up (healthy)              0.0.0.0:8000->8000/tcp
ctem-frontend   ctem-platform-frontend   "node server.js"         frontend   Up (healthy)              0.0.0.0:3000->3000/tcp
```

To view live application logs:
```bash
# Stream all logs
docker compose logs -f

# Stream only backend logs
docker compose logs -f backend

# Stream only frontend logs
docker compose logs -f frontend
```

---

### Step 6: Access the Application

Open your browser and navigate to:

| Application View | URL | Description |
| :--- | :--- | :--- |
| **CTEM Dashboard** | `http://localhost:3000` | Executive threat overview, active alerts, host risk matrix |
| **💥 Blast Radius View** | `http://localhost:3000/blast-radius` | Interactive lateral attack graph, containment sandbox, dependency mapper |
| **Scans Management** | `http://localhost:3000/scans` | Launch and track active network recon scans |
| **Assets Inventory** | `http://localhost:3000/assets` | Discovered, declared, and confirmed assets |
| **Backend REST API** | `http://localhost:8000` | FastAPI backend |
| **Interactive API Docs** | `http://localhost:8000/docs` | Swagger UI documentation with testable endpoints |
| **Health Check** | `http://localhost:8000/health` | Service health status (`{"status":"ok"}`) |

---

## 🌐 Deploying to a Remote Server / VM / LAN

If you are running the Docker container on a **remote server** (AWS EC2, DigitalOcean Droplet, Hetzner, or a local server on your office/home network) and accessing it from another computer:

1. In `.env`, set `NEXT_PUBLIC_API_BASE_URL` to the server's public or LAN IP address:
   ```env
   NEXT_PUBLIC_API_BASE_URL=http://192.168.1.50:8000
   # Or for public VPS:
   NEXT_PUBLIC_API_BASE_URL=http://203.0.113.10:8000
   ```
2. Allow incoming traffic on ports `3000` and `8000` in your firewall / security group:
   ```bash
   # On Ubuntu/Debian UFW:
   sudo ufw allow 3000/tcp
   sudo ufw allow 8000/tcp
   ```
3. Rebuild and launch:
   ```bash
   docker compose up --build -d
   ```
4. On any device on the network, access:
   - `http://<SERVER_IP>:3000`

---

## 🛠️ Day-to-Day Maintenance Commands

### Stopping the Platform
```bash
docker compose down
```

### Restarting the Platform
```bash
docker compose restart
```

### Updating Code & Rebuilding
If you modify code or pull git updates:
```bash
docker compose up --build -d
```

### Executing Commands Inside the Containers
```bash
# Open a shell inside the backend container (test nmap, subfinder, python):
docker compose exec backend bash

# Run backend unit tests inside the container:
docker compose exec backend python -m unittest tests/test_api.py

# Check installed recon tools:
docker compose exec backend which subfinder httpx gau nmap
```

### Resetting Docker Cache & Volumes
```bash
# Stop containers and remove volumes:
docker compose down -v

# Clean up dangling images:
docker image prune -f
```

---

## ❓ Troubleshooting & FAQs

### 1. Error: `dial unix /var/run/docker.sock: connect: no such file or directory`
- **Cause**: The Docker daemon is not running.
- **Solution**: Open Docker Desktop (on macOS or Windows) or start the service on Linux (`sudo systemctl start docker`).

### 2. Error: `port is already allocated: 8000` or `3000`
- **Cause**: Another service (like an existing uvicorn or node dev server) is occupying port 8000 or 3000.
- **Solution**:
  - Identify and terminate the process:
    - On macOS/Linux: `lsof -i :8000` and `kill -9 <PID>`
    - On Windows: `netstat -ano | findstr :8000` and `taskkill /F /PID <PID>`
  - Or change the host port in `docker-compose.yml` (e.g. `"8080:8000"` or `"3001:3000"`).

### 3. Backend shows `supabase.exceptions.APIError` or `PostgrestError`
- **Cause**: Invalid Supabase credentials or database tables have not been created yet.
- **Solution**:
  1. Verify `SUPABASE_URL` and `SUPABASE_KEY` in `.env`.
  2. Ensure you have run [`ctem-backend/migrations/000_full_schema_all_migrations.sql`](file:///Users/dhinesh/Downloads/new%2001/ctem-backend/migrations/000_full_schema_all_migrations.sql) in your Supabase SQL Editor.

### 4. Recon scans fail or `nmap` permission error
- **Cause**: Docker container does not have raw socket permissions if running in restricted environments.
- **Solution**: The Dockerfile already configures unprivileged scanning mode (`-Pn -sV -T4`). If raw SYN scanning (`-sS`) is desired, add `cap_add: [NET_RAW, NET_ADMIN]` under `backend` in `docker-compose.yml`.
