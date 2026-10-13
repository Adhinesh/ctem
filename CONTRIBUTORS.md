# 👥 Continuous Threat Exposure Management (CTEM) Platform Contributors

[![Contributors](https://img.shields.io/badge/Contributors-17%20Engineers-blue.svg)](#complete-contributors-directory)
[![Teams](https://img.shields.io/badge/Specialized%20Teams-5%20Modules-emerald.svg)](#-team-by-team-engineering-breakdown)
[![Architecture](https://img.shields.io/badge/Architecture-Gartner%20CTEM-orange.svg)](README.md)
[![Co-Authors](https://img.shields.io/badge/GitHub-Co--Authored-success.svg)](#-master-engineering-attribution-matrix)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

A sincere acknowledgment to all the engineers, researchers, and security analysts whose collective efforts brought the **Continuous Threat Exposure Management (CTEM) Platform** from concept to production-grade deployment.

The platform operationalizes Gartner's 5-stage CTEM cycle across reconnaissance, scoped vulnerability assessment, graph-based blast radius modeling, continuous multi-node endpoint telemetry, and real-time SOC visualization.

<p align="center">
  <a href="https://github.com/Adhinesh"><img src="https://github.com/Adhinesh.png" width="56" height="56" alt="Dhinesh" style="border-radius:50%; margin:3px;" title="Dhinesh - Platform Architect" /></a>
  <a href="https://github.com/himanshdp"><img src="https://github.com/himanshdp.png" width="56" height="56" alt="Himansh Purswani" style="border-radius:50%; margin:3px;" title="Himansh Purswani - Team 1 Lead" /></a>
  <a href="https://github.com/avinashshankarpt"><img src="https://github.com/avinashshankarpt.png" width="56" height="56" alt="Avinash Shankar P T" style="border-radius:50%; margin:3px;" title="Avinash Shankar P T - Team 2 Lead" /></a>
  <a href="https://github.com/aaqibansarii"><img src="https://github.com/aaqibansarii.png" width="56" height="56" alt="Mohd Aaqib" style="border-radius:50%; margin:3px;" title="Mohd Aaqib - Team 3 Lead" /></a>
  <a href="https://github.com/Vijayashree4"><img src="https://github.com/Vijayashree4.png" width="56" height="56" alt="Vijayashree B" style="border-radius:50%; margin:3px;" title="Vijayashree B - Frontend Lead" /></a>
  <a href="https://github.com/yogeshagrahari"><img src="https://github.com/yogeshagrahari.png" width="56" height="56" alt="Yogesh Kumar Agrahari" style="border-radius:50%; margin:3px;" title="Yogesh Kumar Agrahari - Graph Traversal" /></a>
  <a href="https://github.com/Rutuja1025"><img src="https://github.com/Rutuja1025.png" width="56" height="56" alt="Rutuja Utekar" style="border-radius:50%; margin:3px;" title="Rutuja Utekar - Recon Engine" /></a>
  <a href="https://github.com/harvindersingh-cyber"><img src="https://github.com/harvindersingh-cyber.png" width="56" height="56" alt="Harvinder Singh" style="border-radius:50%; margin:3px;" title="Harvinder Singh - Banner Parser & Cloud Recon" /></a>
  <a href="https://github.com/VKAnupama"><img src="https://github.com/VKAnupama.png" width="56" height="56" alt="V K Anupama" style="border-radius:50%; margin:3px;" title="V K Anupama - Database & Drift Engine" /></a>
  <a href="https://github.com/ronak564"><img src="https://github.com/ronak564.png" width="56" height="56" alt="Ronak Sajeev" style="border-radius:50%; margin:3px;" title="Ronak Sajeev - Asset Zones" /></a>
  <a href="https://github.com/vibhuti93"><img src="https://github.com/vibhuti93.png" width="56" height="56" alt="Vibhuti Kumar" style="border-radius:50%; margin:3px;" title="Vibhuti Kumar - CVE Engine & SLAs" /></a>
  <a href="https://github.com/Virus9T"><img src="https://github.com/Virus9T.png" width="56" height="56" alt="Tanay Sengupta" style="border-radius:50%; margin:3px;" title="Tanay Sengupta - CVE Signature Cache" /></a>
  <a href="https://github.com/Aksh465"><img src="https://github.com/Aksh465.png" width="56" height="56" alt="Akash Bangera" style="border-radius:50%; margin:3px;" title="Akash Bangera - Risk Scoring Formula" /></a>
  <a href="https://github.com/dhana2138"><img src="https://github.com/dhana2138.png" width="56" height="56" alt="Dhanavelan" style="border-radius:50%; margin:3px;" title="Dhanavelan - Risk Heatmap Matrix" /></a>
</p>

---

## 📑 Table of Contents

- [🏢 Team-by-Team Engineering Breakdown](#-team-by-team-engineering-breakdown)
  - [Team 1: Attack Surface Reconnaissance & Scan Orchestration](#team-1-attack-surface-reconnaissance--scan-orchestration)
  - [Team 2: Core Database Architecture, Asset Zoning & Platform Foundation](#team-2-core-database-architecture-asset-zoning--platform-foundation)
  - [Team 3: Vulnerability Intelligence, CVE Slurping & Composite Risk Scoring](#team-3-vulnerability-intelligence-cve-slurping--composite-risk-scoring)
  - [Team 4: Attack Path Modeling, Blast Radius Graph & UEBA SIEM Pipeline](#team-4-attack-path-modeling-blast-radius-graph--ueba-siem-pipeline)
  - [Team 5: SOC Visualizer, Frontend Architecture & Design System](#team-5-soc-visualizer-frontend-architecture--design-system)
- [📊 Master Engineering Attribution Matrix](#-master-engineering-attribution-matrix)
- [🌟 Additional Platform Contributors & Security Reviewers](#-additional-platform-contributors--security-reviewers)
- [📖 Complete Contributors Directory](#-complete-contributors-directory)
- [🤝 How to Contribute](#-how-to-contribute)
- [📄 License & Recognition](#-license--recognition)

---

## 🏢 Team-by-Team Engineering Breakdown

### Team 1: Attack Surface Reconnaissance & Scan Orchestration

Team 1 engineered the external reconnaissance ingestion engine, scan worker queuing, target validation filters, and multi-tool scanner orchestration containers.

| Contributor | Profile | Core Module | Key Code Files | Technical Value Delivered |
| :--- | :--- | :--- | :--- | :--- |
| **Rutuja Utekar** | [@Rutuja1025](https://github.com/Rutuja1025) | Subdomain Recon & Tool Orchestration | `recon_runner.py`<br>`target_validation.py`<br>`Dockerfile` | Certificate transparency lookup (`crt.sh`), automated `subfinder` & `gau` execution, and multi-stage ASM containerization. |
| **Mohit** | — | FastAPI Scan Router, Async Tasks & Rate Limiting | `scans.py`<br>`scan_service.py`<br>`target_validation.py` | Asynchronous HTTP/TLS probers, FastAPI `BackgroundTasks` worker queue, per-tenant rate limiters, and scan lifecycle state machines. |
| **Harvinder Singh** | [@harvindersingh-cyber](https://github.com/harvindersingh-cyber) | Nmap XML Parser, Cloud Discovery & Scan Modal UI | `recon_runner.py`<br>`NewScanModal.tsx` | Nmap XML banner version extraction (vsftpd, Apache, Samba), GCP Cloud Asset discovery, and dynamic Next.js Scan configuration modal. |

---

### Team 2: Core Database Architecture, Asset Zoning & Platform Foundation

Team 2 laid the relational schema foundations in PostgreSQL/Supabase, built the drift detection engine, implemented asset zoning, and engineered central alert aggregation with hardware protection.

| Contributor | Profile | Core Module | Key Code Files | Technical Value Delivered |
| :--- | :--- | :--- | :--- | :--- |
| **V K Anupama** | [@VKAnupama](https://github.com/VKAnupama) | Base Database Schema, Validation & Drift Engine | `000_base_schema.sql`<br>`001_scans_and_zone.sql`<br>`change_detection_service.py`<br>`test_api.py` | PostgreSQL DDL migrations, relational foreign-key cascading integrity constraints, automated port state diff engine, and REST integration test suites. |
| **Ronak Sajeev** | [@ronak564](https://github.com/ronak564) | Asset Zones & Active Status Engine | `001_scans_and_zone.sql`<br>`assets/page.tsx`<br>`declared_asset_service.py` | Internal vs. External network perimeter zoning, discovered vs. declared asset reconciliation, and asset lifecycle tracking. |
| **Dhinesh** | [@Adhinesh](https://github.com/Adhinesh) | Supabase Client, Alert Engine & Integration | `supabase_client.py`<br>`alert_service.py`<br>`alerts.py`<br>`peripheral_blocker.py` | Central database client singleton, alert deduplication and dispatch queue, REST API integration, and host-level USB peripheral blocker. |

---

### Team 3: Vulnerability Intelligence, CVE Slurping & Composite Risk Scoring

Team 3 developed the vulnerability pipeline, integrating offline signature caches with live NVD/CIRCL sources, CISA KEV exploit weight multipliers, and mathematical composite risk scoring algorithms.

| Contributor | Profile | Core Module | Key Code Files | Technical Value Delivered |
| :--- | :--- | :--- | :--- | :--- |
| **Vibhuti Kumar** | [@vibhuti93](https://github.com/vibhuti93) | Async CVE Client & Remediation SLAs | `cve_lookup.py`<br>`risk_engine.py`<br>`risk.py` | Asynchronous NVD and CIRCL CVE vulnerability fetcher, remediation priority SLA mappings (P1 to P4), and endpoint risk dispatchers. |
| **Tanay Sengupta** | [@Virus9T](https://github.com/Virus9T) | Curated CVE Signature Cache | `scoring_runner.py`<br>`cve_lookup.py` | High-confidence, air-gapped vulnerability signature cache ensuring continuous offline scoring without external API rate limits. |
| **Akash Bangera** | [@Aksh465](https://github.com/Aksh465) | Multi-Factor Composite Risk Formula | `risk_engine.py`<br>`000_base_schema.sql` | Mathematical scoring algorithm factoring CVSS base score, asset business criticality, exposure posture, and network blast radius impact. |
| **Hasina** | — | CISA KEV Multiplier & Batch Scorer | `risk_engine.py`<br>`scoring_runner.py` | Implemented 1.5x active weaponized exploit weight multiplier for CISA Known Exploited Vulnerabilities and automated batch asset scoring runner. |

---

### Team 4: Attack Path Modeling, Blast Radius Graph & UEBA SIEM Pipeline

Team 4 engineered lateral movement attack graph traversal algorithms, interactive node-link attack path visualizers, risk heatmaps, and host SIEM/UEBA log anomaly pipelines.

| Contributor | Profile | Core Module | Key Code Files | Technical Value Delivered |
| :--- | :--- | :--- | :--- | :--- |
| **Yogesh Kumar Agrahari** | [@yogeshagrahari](https://github.com/yogeshagrahari) | Blast Radius Graph Traversal & Topology UI | `blast_radius_service.py`<br>`BlastRadiusGraph.tsx`<br>`blast-radius/page.tsx` | Subnet-aware Breadth-First Search (BFS) graph traversal algorithm and interactive SVG/Canvas attack cascade visualization cockpit. |
| **Dhanavelan** | [@dhana2138](https://github.com/dhana2138) | Risk Heatmap Grid & Search Filter | `RiskHeatmap.tsx`<br>`risk.py` | Color-coded severity priority matrix (P1 critical to P4 informational) with real-time asset query and exposure filtering. |
| **Rahil** | — | SIEM Ingestion, UEBA Rules & Forwarder | `log_ingestion_service.py`<br>`ueba_service.py`<br>`ueba_forwarder.py` | High-throughput Suricata and Zeek log ingestion pipeline paired with a 3-rule anomaly engine (brute force, off-hours login, privilege escalation). |

---

### Team 5: SOC Visualizer, Frontend Architecture & Design System

Team 5 designed and implemented the Next.js 14 SOC dashboard, delivering dark-mode cyber design tokens, typed REST clients, KPI overview cards, and security analyst alert triage views.

| Contributor | Profile | Core Module | Key Code Files | Technical Value Delivered |
| :--- | :--- | :--- | :--- | :--- |
| **Vijayashree B** | [@Vijayashree4](https://github.com/Vijayashree4) | Frontend Lead, SOC Dashboard, Design System & APIs | `app/page.tsx`<br>`alerts/page.tsx`<br>`monitoring/page.tsx`<br>`lib/api.ts`<br>`Badge.tsx` | Executive KPI metric cards, fully typed TypeScript API client, SOC high-contrast dark theme, reusable badge system, and alert triage dashboard. |

---

## 📊 Master Engineering Attribution Matrix

| Team | Member | GitHub Profile | Core Module | Primary Technologies / Files | Key Technical Contribution |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **1** | Rutuja Utekar | [@Rutuja1025](https://github.com/Rutuja1025) | Subdomain Recon & Tool Orchestration | `recon_runner.py`, `Dockerfile` | crt.sh CT logs, Subfinder/GAU pipeline, Docker runner |
| **1** | Mohit | — | FastAPI Scan Router & Rate Limiting | `scans.py`, `scan_service.py` | Async BackgroundTasks worker queue, rate limiting |
| **1** | Harvinder Singh | [@harvindersingh-cyber](https://github.com/harvindersingh-cyber) | Nmap Parser & Cloud Discovery | `recon_runner.py`, `NewScanModal.tsx` | Nmap XML banner parser, GCP Cloud discovery, Scan UI |
| **2** | V K Anupama | [@VKAnupama](https://github.com/VKAnupama) | Database Schema & Drift Engine | `000_base_schema.sql`, `change_detection_service.py` | PostgreSQL migrations, foreign-key rules, port diff engine |
| **2** | Ronak Sajeev | [@ronak564](https://github.com/ronak564) | Asset Zones & Tracking Engine | `001_scans_and_zone.sql`, `assets/page.tsx` | Internal/External network zoning, asset state machine |
| **2** | Dhinesh | [@Adhinesh](https://github.com/Adhinesh) | Supabase Client & Alert Engine | `supabase_client.py`, `alert_service.py` | Singleton database layer, alert deduplicator, USB blocker |
| **3** | Vibhuti Kumar | [@vibhuti93](https://github.com/vibhuti93) | Async CVE Client & SLA Engine | `cve_lookup.py`, `risk_engine.py` | NVD/CIRCL REST integrations, remediation SLA tiers |
| **3** | Tanay Sengupta | [@Virus9T](https://github.com/Virus9T) | Offline Vulnerability Signature Cache | `scoring_runner.py`, `cve_lookup.py` | Air-gapped CVE signature cache & offline fallback |
| **3** | Akash Bangera | [@Aksh465](https://github.com/Aksh465) | Multi-Factor Composite Risk Formula | `risk_engine.py`, `000_base_schema.sql` | Mathematical risk equation (CVSS × Crit × Exposure × Blast) |
| **3** | Hasina | — | CISA KEV Multiplier & Batch Scorer | `risk_engine.py`, `scoring_runner.py` | 1.5x weaponized threat multiplier, batch risk runner |
| **4** | Yogesh Kumar Agrahari | [@yogeshagrahari](https://github.com/yogeshagrahari) | Blast Radius BFS & Attack Graph UI | `blast_radius_service.py`, `BlastRadiusGraph.tsx` | BFS graph traversal, interactive SVG attack path visualizer |
| **4** | Dhanavelan | [@dhana2138](https://github.com/dhana2138) | Risk Heatmap Grid & Filter System | `RiskHeatmap.tsx`, `risk.py` | 2D priority risk matrix (P1–P4), multi-attribute filter |
| **4** | Rahil | — | SIEM Log Ingestion & UEBA Engine | `log_ingestion_service.py`, `ueba_service.py` | Suricata/Zeek pipeline, UEBA anomaly heuristics |
| **5** | Vijayashree B | [@Vijayashree4](https://github.com/Vijayashree4) | Frontend Lead & Design System | `app/page.tsx`, `lib/api.ts`, `Badge.tsx` | Executive KPI widgets, typed API client, SOC dark mode |

---

## 🎖️ Technical Leadership & Project Supervision

The project engineering and architecture were directed and supervised by the Team Leads:

- **Team 1 Lead**: **Himansh Purswani** ([@himanshdp](https://github.com/himanshdp?tab=repositories)) — Supervised Attack Surface Discovery, reconnaissance engine pipelines (`recon_runner.py`), Go binary tool orchestration (Subfinder, Nmap, httpx), Docker containerization, and DNS/subdomain scanning.
- **Team 2 Lead**: **Avinash Shankar P T** ([@avinashshankarpt](https://github.com/avinashshankarpt)) — Supervised relational database architecture, PostgreSQL/Supabase schema design, internal vs. external asset zoning, asset change/port drift detection, and data persistence integrity.
- **Team 3 Lead**: **Mohd Aaqib** ([@aaqibansarii](https://github.com/aaqibansarii)) — Supervised vulnerability ingestion pipelines, asynchronous NVD/CIRCL API lookups, offline curated CVE signature matching, and mathematical modeling for the multi-factor risk engine.
- **Team 4 Leadership**: **Collective Management by all Team Leads** (*Himansh Purswani, Avinash Shankar P T, Mohd Aaqib*) — Joint technical oversight over Graph Topology & Blast Radius traversal (`blast_radius_service.py`), Security Onion / Suricata SIEM log ingestion, UEBA identity anomaly rules, and end-to-end platform integration.

---

## 📖 Complete Contributors Directory

All individual contributors listed alphabetically:

1. **Akash Bangera** — [@Aksh465](https://github.com/Aksh465)
2. **Avinash Shankar P T** — [@avinashshankarpt](https://github.com/avinashshankarpt)
3. **Dhanavelan** — [@dhana2138](https://github.com/dhana2138)
4. **Dhinesh** — [@Adhinesh](https://github.com/Adhinesh)
5. **Harvinder Singh** — [@harvindersingh-cyber](https://github.com/harvindersingh-cyber)
6. **Hasina** — *Threat Intelligence & Scoring Algorithms*
7. **Himansh Purswani** — [@himanshdp](https://github.com/himanshdp?tab=repositories)
8. **Mohd Aaqib** — [@aaqibansarii](https://github.com/aaqibansarii)
9. **Mohit** — *Async Worker Queues & Scan Services*
10. **Rahil** — *SIEM Ingestion & UEBA Analytics*
11. **Ronak Sajeev** — [@ronak564](https://github.com/ronak564)
12. **Rutuja Utekar** — [@Rutuja1025](https://github.com/Rutuja1025)
13. **Tanay Sengupta** — [@Virus9T](https://github.com/Virus9T)
14. **V K Anupama** — [@VKAnupama](https://github.com/VKAnupama)
15. **Vibhuti Kumar** — [@vibhuti93](https://github.com/vibhuti93)
16. **Vijayashree B** — [@Vijayashree4](https://github.com/Vijayashree4)
17. **Yogesh Kumar Agrahari** — [@yogeshagrahari](https://github.com/yogeshagrahari)

---

## 🤝 How to Contribute

We welcome contributions from the cybersecurity, devops, and software engineering communities!

### Pull Request Workflow
1. **Fork the Repository**: Create your personal branch (`git checkout -b feature/amazing-exposure-detector`).
2. **Adhere to Code Standards**:
   - Python code must follow PEP 8 and use type annotations (`typing`).
   - Frontend code must use TypeScript with strict type checking and Tailwind CSS for styling.
   - Database migrations must be sequentially numbered in `ctem-backend/migrations/`.
3. **Write Unit & Integration Tests**:
   - Backend tests reside in `ctem-backend/tests/test_api.py`.
   - Endpoint agent tests reside in `ctem-agent/tests/test_agent.py`.
4. **Submit a Pull Request**: Provide a detailed description of changes, reproduction steps, and relevant CVE/threat framework references.

---

## 📄 License & Recognition

This project is open-source under the [MIT License](LICENSE). 

We deeply appreciate every contributor who dedicated their time, security domain expertise, and engineering craft to building this end-to-end Continuous Threat Exposure Management platform.
