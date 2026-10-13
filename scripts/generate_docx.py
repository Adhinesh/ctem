import os
import shutil
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
import matplotlib.pyplot as plt
import matplotlib.patches as patches

# -------------------------------------------------------------
# 1. Generate Architecture Diagram Image
# -------------------------------------------------------------
def generate_diagram(image_path="ctem_pipeline_architecture.png"):
    fig, ax = plt.subplots(figsize=(12, 4.8), dpi=300)
    ax.set_facecolor("#0f172a")
    fig.patch.set_facecolor("#0f172a")

    stages = [
        {"title": "Team 1: Discovery\n[Lead: Himansh Purswani]", "sub": "Recon Runner\nSubfinder / crt.sh\nNmap (-Pn, -sV)\nhttpx Web Probing", "color": "#38bdf8", "border": "#0284c7"},
        {"title": "Team 2: Inventory & Drift\n[Lead: Avinash Shankar P T]", "sub": "PostgreSQL / Supabase\nZone (Internal/External)\nPort Drift Engine\nDeclared Assets", "color": "#a855f7", "border": "#7e22ce"},
        {"title": "Team 3: Vuln & Risk\n[Lead: Mohd Aaqib]", "sub": "CVE Ingestion (NVD/CIRCL)\nCurated Offline Cache\nRisk Formula (P1-P4)\nCISA KEV Multiplier", "color": "#f97316", "border": "#c2410c"},
        {"title": "Team 4: Graph & SIEM\n[Collective Lead Council]", "sub": "Blast Radius (BFS Graph)\nSecurity Onion / Suricata\nUEBA Anomaly Engine\nPeripheral Blocker", "color": "#ef4444", "border": "#b91c1c"},
        {"title": "Team 5: SOC Dashboard\n[Executive Oversight]", "sub": "Executive KPI Feed\nRisk Heatmap (P1-P4)\nLive Alert Triage\nDynamic Typed API", "color": "#10b981", "border": "#047857"}
    ]

    box_width = 1.95
    box_height = 2.4
    y_start = 1.2
    spacing = 0.45

    for i, stage in enumerate(stages):
        x = 0.3 + i * (box_width + spacing)
        rect = patches.FancyBboxPatch(
            (x, y_start), box_width, box_height,
            boxstyle="round,pad=0.12,rounding_size=0.15",
            linewidth=2, edgecolor=stage["border"], facecolor="#1e293b"
        )
        ax.add_patch(rect)

        # Header box
        header_rect = patches.FancyBboxPatch(
            (x, y_start + box_height - 0.65), box_width, 0.65,
            boxstyle="round,pad=0.08,rounding_size=0.12",
            linewidth=1, edgecolor=stage["border"], facecolor=stage["color"]
        )
        ax.add_patch(header_rect)

        ax.text(x + box_width/2, y_start + box_height - 0.33, stage["title"],
                color="#0f172a", fontsize=8.5, fontweight="bold", ha="center", va="center")

        ax.text(x + box_width/2, y_start + (box_height - 0.65)/2, stage["sub"],
                color="#f8fafc", fontsize=8.5, ha="center", va="center", linespacing=1.35)

        if i < len(stages) - 1:
            ax.annotate("", xy=(x + box_width + spacing - 0.05, y_start + box_height/2),
                        xytext=(x + box_width + 0.05, y_start + box_height/2),
                        arrowprops=dict(arrowstyle="-|>", color="#94a3b8", lw=2.5, mutation_scale=15))

    ax.set_xlim(0, 12.3)
    ax.set_ylim(0.5, 4.3)
    ax.axis("off")
    plt.tight_layout()
    plt.savefig(image_path, bbox_inches="tight", facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close()
    return image_path

# -------------------------------------------------------------
# 2. Build Document
# -------------------------------------------------------------
def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=140, right=140):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
    tcPr.append(tcMar)

def create_document(doc_path):
    doc = docx.Document()

    # Set 0.75-inch margins for spacious tabular rendering
    for section in doc.sections:
        section.top_margin = Inches(0.75)
        section.bottom_margin = Inches(0.75)
        section.left_margin = Inches(0.75)
        section.right_margin = Inches(0.75)

    # Document Header & Title
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(0)
    title_p.paragraph_format.space_after = Pt(4)
    run_title = title_p.add_run("Continuous Threat Exposure Management (CTEM)")
    run_title.font.name = "Arial"
    run_title.font.size = Pt(22)
    run_title.font.bold = True
    run_title.font.color.rgb = RGBColor(15, 23, 42)

    subtitle_p = doc.add_paragraph()
    subtitle_p.paragraph_format.space_after = Pt(10)
    run_sub = subtitle_p.add_run("Engineering Leadership, Team Attribution & Architecture Breakdown")
    run_sub.font.name = "Arial"
    run_sub.font.size = Pt(12)
    run_sub.font.italic = True
    run_sub.font.color.rgb = RGBColor(71, 85, 105)

    # ---------------------------------------------------------
    # LEADERSHIP & PROJECT SUPERVISION HIGHLIGHT BLOCK
    # ---------------------------------------------------------
    lead_box = doc.add_table(rows=1, cols=1)
    lead_box.alignment = WD_TABLE_ALIGNMENT.CENTER
    lead_box.autofit = False
    lead_cell = lead_box.rows[0].cells[0]
    lead_cell.width = Inches(7.0)
    set_cell_background(lead_cell, "F1F5F9")
    set_cell_margins(lead_cell, top=140, bottom=140, left=180, right=180)

    p_lead = lead_cell.paragraphs[0]
    p_lead.paragraph_format.space_after = Pt(4)
    r_lb_title = p_lead.add_run("★ Project Leadership & Technical Supervisory Council\n")
    r_lb_title.font.name = "Arial"
    r_lb_title.font.size = Pt(11)
    r_lb_title.font.bold = True
    r_lb_title.font.color.rgb = RGBColor(30, 58, 138)

    leads_info = [
        ("Team 1 Lead: ", "Himansh Purswani (@himanshdp)", " — Supervised Attack Surface Discovery, Reconnaissance Pipelines & Tool Orchestration."),
        ("Team 2 Lead: ", "Avinash Shankar P T (@avinashshankarpt)", " — Supervised Asset Inventory, Database Architecture, Zoning & Drift Detection."),
        ("Team 3 Lead: ", "Mohd Aaqib (@aaqibansarii)", " — Supervised Vulnerability Ingestion, Curated CVE Signatures & Risk Scoring Engine."),
        ("Team 4 Lead: ", "Collective Management by all Team Leads", " — Himansh Purswani, Avinash Shankar P T, and Mohd Aaqib collectively supervised Graph Topology, SIEM Log Ingestion, UEBA Analytics, and cross-team platform integration.")
    ]
    for prefix, name, desc in leads_info:
        r_pfx = p_lead.add_run(f"• {prefix}")
        r_pfx.font.name = "Arial"
        r_pfx.font.size = Pt(9.5)
        r_pfx.font.bold = True
        r_pfx.font.color.rgb = RGBColor(15, 23, 42)

        r_nm = p_lead.add_run(name)
        r_nm.font.name = "Arial"
        r_nm.font.size = Pt(9.5)
        r_nm.font.bold = True
        r_nm.font.color.rgb = RGBColor(14, 116, 144)

        r_dsc = p_lead.add_run(f"{desc}\n")
        r_dsc.font.name = "Arial"
        r_dsc.font.size = Pt(9.5)
        r_dsc.font.color.rgb = RGBColor(51, 65, 85)

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # ---------------------------------------------------------
    # PART 1: TABLE ON TOP (Cheatsheet / Summary)
    # ---------------------------------------------------------
    h1 = doc.add_paragraph()
    h1.paragraph_format.space_before = Pt(8)
    h1.paragraph_format.space_after = Pt(6)
    r_h1 = h1.add_run("1. Executive Summary & Team Attribution Matrix")
    r_h1.font.name = "Arial"
    r_h1.font.size = Pt(14)
    r_h1.font.bold = True
    r_h1.font.color.rgb = RGBColor(30, 58, 138)

    table_data = [
        # Team 1
        ["Team 1", "Himansh Purswani [Lead]", "Team 1 Leadership & Recon Supervision", "recon_runner.py, Dockerfile, pipeline", "Supervised Discovery architecture, tool integration & quality assurance"],
        ["Team 1", "Kavita", "Subdomain & DNS Reconnaissance", "recon_runner.py, target_validation.py", "Certificate transparency log lookup & multi-target dispatcher"],
        ["Team 1", "Rutuja", "Tool Orchestration & Dockerization", "recon_runner.py, Dockerfile", "Subprocess execution for subfinder/gau & JSON stream parser"],
        ["Team 1", "Mohit", "FastAPI Scan Router & Web Probing", "scans.py, recon_runner.py, scan_service.py", "Asynchronous HTTP/TLS probe & scan state progression"],
        ["Team 1", "Tanush", "Background Task Queue & Rate Limiting", "scans.py, target_validation.py", "Background task worker management & per-tenant rate limiter"],
        ["Team 1", "Harvinder", "Nmap XML Parser & New Scan Modal", "recon_runner.py, NewScanModal.tsx", "Banner version extraction (vsftpd, Apache, Samba) & Scan UI"],
        # Team 2
        ["Team 2", "Avinash Shankar P T [Lead]", "Team 2 Leadership & Inventory Supervision", "000_base_schema.sql, assets.py", "Supervised Relational Schema, Asset Data Modeling & Integration"],
        ["Team 2", "VK Anupama", "Base Database Schema & Drift Engine", "000_base_schema.sql, change_detection_service.py", "PostgreSQL DDL & automated port state diff change detection"],
        ["Team 2", "Ronak", "Asset Zones & Active Status Engine", "001_scans_and_zone.sql, assets/page.tsx", "Internal vs External zoning & Discovered/Declared asset tracking"],
        ["Team 2", "Chinmay", "Schema Validation & Integrity Rules", "001_scans_and_zone.sql, test_api.py", "Relational foreign-key constraints & database testing"],
        ["Team 2", "Dhinesh", "Supabase Client, Alert Engine & Integration", "supabase_client.py, alert_service.py, alerts.py", "Central database singleton, multi-subsystem alerts & API suite"],
        # Team 3
        ["Team 3", "Mohd Aaqib [Lead]", "Team 3 Leadership & Risk Supervision", "risk_engine.py, scoring_runner.py", "Supervised CVE matching logic, EPSS ingestion & scoring engine"],
        ["Team 3", "Vibhuti", "Async CVE Client & Remediation SLAs", "cve_lookup.py, risk_engine.py, risk.py", "Asynchronous NVD/CIRCL fetcher & P1-P4 SLA mappings"],
        ["Team 3", "Tanay Sengupta", "Curated CVE Signature Cache", "scoring_runner.py, cve_lookup.py", "High-confidence offline vulnerability signatures (Air-gapped)"],
        ["Team 3", "Akash", "Multi-Factor Composite Risk Formula", "risk_engine.py, 000_base_schema.sql", "Math scoring algorithm factoring CVSS, Criticality & Blast Radius"],
        ["Team 3", "Hasina", "CISA KEV Multiplier & Batch Scorer", "risk_engine.py, scoring_runner.py", "1.5x active weaponized exploit weight & batch asset scoring"],
        # Team 4
        ["Team 4", "Collective Lead Council", "Supervised Graph, SIEM & Platform Integration", "blast_radius_service.py, logs.py", "Himansh, Avinash, and Aaqib supervised topology & SIEM pipelines"],
        ["Team 4", "Tanya", "Blast Radius Graph UI Component", "BlastRadiusGraph.tsx, blast-radius/page.tsx", "Interactive visual node-link cascade of asset compromise"],
        ["Team 4", "Yogesh", "Blast Radius Graph Traversal Engine", "blast_radius_service.py, assets.py", "BFS algorithm across subnets, zones & dependency edges"],
        ["Team 4", "Dhanavelan", "Risk Heatmap Grid & Search Filter", "RiskHeatmap.tsx, risk.py", "Color-coded priority matrix (P1-P4) with real-time asset search"],
        ["Team 4", "Rahil", "SIEM Ingestion, UEBA Rules & Forwarder", "log_ingestion_service.py, ueba_service.py", "Suricata/Zeek log pipeline & 3-rule UEBA anomaly engine"],
        # Team 5
        ["Team 5", "Abhishek", "Frontend API Client & Data Types", "lib/api.ts, lib/types.ts", "Central typed client with dynamic IP resolution & error handling"],
        ["Team 5", "Pooja", "Design System, Badges & Styling", "Badge.tsx, globals.css, tailwind.config.js", "Dark-mode SOC theme, semantics & priority status badges"],
        ["Team 5", "Vijayashree", "SOC Executive Dashboard & Alerts UI", "app/page.tsx, alerts/page.tsx, monitoring/page.tsx", "KPI metric overview, one-click alert response & event simulator"]
    ]

    headers = ["Team", "Member / Role", "Core Module", "Key Code Files", "Technical Value Delivered"]
    table = doc.add_table(rows=len(table_data) + 1, cols=5)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    col_widths = [Inches(0.9), Inches(1.3), Inches(1.6), Inches(1.6), Inches(2.1)]

    # Format header row
    hdr_cells = table.rows[0].cells
    for i, title in enumerate(headers):
        hdr_cells[i].text = title
        hdr_cells[i].width = col_widths[i]
        set_cell_background(hdr_cells[i], "1E293B")
        set_cell_margins(hdr_cells[i], top=120, bottom=120, left=90, right=90)
        p = hdr_cells[i].paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        for run in p.runs:
            run.font.name = "Arial"
            run.font.size = Pt(8.5)
            run.font.bold = True
            run.font.color.rgb = RGBColor(255, 255, 255)

    # Format data rows
    for row_idx, row in enumerate(table_data):
        row_cells = table.rows[row_idx + 1].cells
        is_lead = "[Lead]" in row[1] or "Collective Lead" in row[1]
        bg_color = "E0F2FE" if is_lead else ("F8FAFC" if row_idx % 2 == 0 else "FFFFFF")

        for col_idx, text in enumerate(row):
            row_cells[col_idx].text = text
            row_cells[col_idx].width = col_widths[col_idx]
            set_cell_background(row_cells[col_idx], bg_color)
            set_cell_margins(row_cells[col_idx], top=70, bottom=70, left=90, right=90)
            p = row_cells[col_idx].paragraphs[0]
            if col_idx in (0, 1):
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            for run in p.runs:
                run.font.name = "Arial"
                run.font.size = Pt(8)
                if col_idx == 1:
                    run.font.bold = True
                    if is_lead:
                        run.font.color.rgb = RGBColor(2, 132, 199) # Blue 600
                    else:
                        run.font.color.rgb = RGBColor(15, 23, 42)
                else:
                    run.font.color.rgb = RGBColor(15, 23, 42)

    # ---------------------------------------------------------
    # PART 2: ARCHITECTURE GRAPH (Immediately after table)
    # ---------------------------------------------------------
    doc.add_page_break()

    h2 = doc.add_paragraph()
    h2.paragraph_format.space_before = Pt(8)
    h2.paragraph_format.space_after = Pt(4)
    r_h2 = h2.add_run("2. CTEM End-to-End Pipeline Architecture Diagram")
    r_h2.font.name = "Arial"
    r_h2.font.size = Pt(14)
    r_h2.font.bold = True
    r_h2.font.color.rgb = RGBColor(30, 58, 138)

    p_diagram_desc = doc.add_paragraph()
    p_diagram_desc.paragraph_format.space_after = Pt(10)
    r_diag_desc = p_diagram_desc.add_run("The following flowchart illustrates the continuous execution pipeline across all 5 engineering teams, showing direct supervisory ownership by Team Leads Himansh Purswani, Avinash Shankar P T, and Mohd Aaqib:")
    r_diag_desc.font.name = "Arial"
    r_diag_desc.font.size = Pt(9.5)
    r_diag_desc.font.color.rgb = RGBColor(71, 85, 105)

    img_path = generate_diagram()
    p_img = doc.add_paragraph()
    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img.paragraph_format.space_after = Pt(4)
    doc.add_picture(img_path, width=Inches(6.9))

    caption = doc.add_paragraph()
    caption.alignment = WD_ALIGN_PARAGRAPH.CENTER
    caption.paragraph_format.space_after = Pt(16)
    r_cap = caption.add_run("Figure 1: CTEM Five-Stage Ingestion, Scoring, and Operational Response Architecture")
    r_cap.font.name = "Arial"
    r_cap.font.size = Pt(9)
    r_cap.font.italic = True
    r_cap.font.color.rgb = RGBColor(100, 116, 139)

    # ---------------------------------------------------------
    # PART 3: DETAILED DESCRIPTION BY TEAM & INDIVIDUAL
    # ---------------------------------------------------------
    h3 = doc.add_paragraph()
    h3.paragraph_format.space_before = Pt(8)
    h3.paragraph_format.space_after = Pt(6)
    r_h3 = h3.add_run("3. Detailed Engineering Breakdown by Team & Individual")
    r_h3.font.name = "Arial"
    r_h3.font.size = Pt(14)
    r_h3.font.bold = True
    r_h3.font.color.rgb = RGBColor(30, 58, 138)

    team_details = [
        {
            "team": "Team 1: Attack Surface Discovery & Reconnaissance",
            "lead": "Himansh Purswani (@himanshdp) — Team 1 Lead & Technical Supervisor",
            "lead_desc": "Supervised the overall reconnaissance engine, guided tool orchestration (Subfinder, Nmap, httpx), unblocked async subprocess integration, and reviewed pipeline code to ensure high-performance external attack surface mapping without false positives.",
            "desc": "Team 1 is responsible for discovering unmapped assets, mapping external domains, probing network subnets, and extracting service version banners.",
            "members": [
                {
                    "name": "Kavita",
                    "role": "Subdomain Enumeration & Multi-Target Recon Dispatcher",
                    "files": "ctem-backend/app/services/recon_runner.py, ctem-backend/app/services/target_validation.py",
                    "how": "Engineered the non-intrusive subdomain discovery engine by querying Certificate Transparency logs via crt.sh (_run_crtsh). Developed the main recon dispatcher (run_recon), which accepts diverse target types (domain, ip, cidr, cloud_project) and routes them into dedicated reconnaissance workflows. Implemented regex and IP syntax verification in target_validation.py to prevent malformed targets or injection attacks."
                },
                {
                    "name": "Rutuja",
                    "role": "ASM Tool Orchestration & Docker Containerization",
                    "files": "ctem-backend/app/services/recon_runner.py, ctem-backend/Dockerfile",
                    "how": "Built production-grade async subprocess wrappers (_run_subprocess_json) that execute external reconnaissance CLI tools such as subfinder and gau without blocking the async event loop. Configured the multi-stage Dockerfile packaging Nmap, Go security binaries, and Python 3 into an automated, self-contained Attack Surface Management (ASM) container."
                },
                {
                    "name": "Mohit",
                    "role": "FastAPI Scan Router & Web Probing Engine",
                    "files": "ctem-backend/app/routers/scans.py, ctem-backend/app/services/scan_service.py, ctem-backend/app/services/recon_runner.py",
                    "how": "Implemented the core FastAPI REST endpoints for scans (POST /scans, GET /scans/{id}, GET /scans/{id}/assets). Developed the web asset prober (_run_httpx) leveraging httpx to retrieve HTTP status codes, webpage titles, and TLS certificate metadata. Architected the sequential scan lifecycle tracker (queued -> running -> ingesting -> scoring -> complete)."
                },
                {
                    "name": "Tanush",
                    "role": "Asynchronous Task Scheduling & Rate Limiting",
                    "files": "ctem-backend/app/routers/scans.py, ctem-backend/app/services/target_validation.py",
                    "how": "Engineered non-blocking background scan execution utilizing FastAPI BackgroundTasks to ensure large network scans do not time out client HTTP requests. Implemented a sliding-window rate limiter per tenant (check_rate_limit) to protect the scanning backend from resource exhaustion."
                },
                {
                    "name": "Harvinder",
                    "role": "Nmap XML Parsing, Cloud Assets & Scan UI Modal",
                    "files": "ctem-backend/app/services/recon_runner.py, ctem-frontend/components/NewScanModal.tsx",
                    "how": "Wrote the Nmap service execution routine (_run_nmap) using parameters -Pn -sV -T4 --top-ports 100 -oX -. Built the ElementTree XML parser (_parse_nmap_xml) to accurately extract open ports, protocols, service banners, and software versions (e.g. vsftpd 2.3.4, Apache 2.2.8). Integrated GCP Cloud Asset Inventory search and designed the frontend New Scan modal."
                }
            ]
        },
        {
            "team": "Team 2: Asset Inventory, Database Architecture & Drift Detection",
            "lead": "Avinash Shankar P T (@avinashshankarpt) — Team 2 Lead & Technical Supervisor",
            "lead_desc": "Supervised relational database design, data modeling for internal/external assets, change detection schema integration, and ensured high-integrity cross-table synchronization with Supabase.",
            "desc": "Team 2 owns the persistent data model, manages asset confirmation and network zoning, detects attack surface drift, and drives the central alert service.",
            "members": [
                {
                    "name": "VK Anupama",
                    "role": "Core Relational Database Schema & Port Drift Detection",
                    "files": "ctem-backend/migrations/000_base_schema.sql, ctem-backend/app/services/change_detection_service.py",
                    "how": "Authored the foundational PostgreSQL DDL migrations defining assets, open_ports, and asset_dependencies tables. Engineered the automated port drift detection engine (detect_port_change), which compares scan snapshots to detect newly opened ports, closed ports, and service modifications, filtering out dynamic ephemeral ports (>= 49152) to prevent false alerts."
                },
                {
                    "name": "Ronak",
                    "role": "Asset Zoning, Declared Assets & Inventory Management",
                    "files": "ctem-backend/migrations/001_scans_and_zone.sql, ctem-backend/app/services/declared_asset_service.py, ctem-frontend/app/assets/page.tsx",
                    "how": "Architected the enterprise asset zoning model distinguishing internal (RFC1918) from external perimeter assets. Developed the Declared Asset service allowing security analysts to manually pre-declare or confirm shadow IT assets. Built the frontend Asset Inventory views displaying live asset status, open ports count, and highest risk tiers."
                },
                {
                    "name": "Chinmay",
                    "role": "Database Schema Validation & Integrity Testing",
                    "files": "ctem-backend/migrations/001_scans_and_zone.sql, ctem-backend/tests/test_api.py",
                    "how": "Performed structural schema reviews and verified foreign-key cascade constraints across scans, scan_assets, and open_ports. Validated database persistence integrity during scan lifecycle operations."
                },
                {
                    "name": "Dhinesh (Project Lead / Integration)",
                    "role": "Supabase Client Singleton, Alert Generation Engine & System Integration",
                    "files": "ctem-backend/app/db/supabase_client.py, ctem-backend/migrations/000_full_schema_all_migrations.sql, ctem-backend/app/services/alert_service.py, ctem-backend/app/routers/alerts.py, ctem-backend/scripts/peripheral_blocker.py",
                    "how": "Built the centralized Supabase database connection client and consolidated all schema migrations. Designed and implemented the unified Alert Generation System (alert_service.py) that aggregates alerts from port drift, UEBA anomalies, SIEM logs, and unauthorized peripherals into an actionable triage queue. Developed the physical hardware enforcer (peripheral_blocker.py) for Linux kernel authorization control."
                }
            ]
        },
        {
            "team": "Team 3: Vulnerability Ingestion & Multi-Factor Risk Scoring",
            "lead": "Mohd Aaqib (@aaqibansarii) — Team 3 Lead & Technical Supervisor",
            "lead_desc": "Supervised vulnerability data ingestion pipelines, EPSS integration, curated CVE database structuring, and mathematical formula modeling for composite risk prioritization.",
            "desc": "Team 3 translates detected software versions into actionable CVE vulnerabilities, evaluates exploit feasibility, calculates composite risk scores, and maps corporate SLAs.",
            "members": [
                {
                    "name": "Vibhuti",
                    "role": "Async CVE Client & Remediation SLA Engine",
                    "files": "ctem-backend/app/services/cve_lookup.py, ctem-backend/app/services/risk_engine.py, ctem-backend/app/routers/risk.py",
                    "how": "Developed the asynchronous CVE client using httpx to query public vulnerability APIs (NVD, CIRCL). Built the remediation SLA calculator mapping composite risk tiers directly to organizational response deadlines: P1 (Critical) within 24 hours, P2 (High) within 72 hours, P3 (Medium) within 7 days, and P4 (Low) within 30 days."
                },
                {
                    "name": "Tanay Sengupta",
                    "role": "Curated Offline CVE Cache & In-Memory Matching",
                    "files": "ctem-backend/app/services/scoring_runner.py, ctem-backend/app/services/cve_lookup.py",
                    "how": "Designed and populated the CURATED_CVE_MAP database caching high-confidence signatures for commonly targeted software (vsftpd 2.3.4 -> CVE-2011-2523, Samba 3.0.20 -> CVE-2007-2447, Apache 2.2.8 -> CVE-2008-0005). Enabled instant, zero-latency vulnerability matching without external API dependency, crucial for air-gapped enterprise environments."
                },
                {
                    "name": "Akash",
                    "role": "Multi-Factor Composite Risk Mathematical Formula",
                    "files": "ctem-backend/app/services/risk_engine.py, ctem-backend/migrations/000_base_schema.sql",
                    "how": "Engineered the multi-factor risk scoring formula: Composite Risk = CVSS Base Score * Asset Criticality Weight * Network Exposure Factor * Blast Radius Multiplier. Ensured external-facing critical servers are scored substantially higher than identical vulnerabilities residing on isolated internal systems."
                },
                {
                    "name": "Hasina",
                    "role": "CISA KEV Exploit Multiplier & Batch Asset Scorer",
                    "files": "ctem-backend/app/services/risk_engine.py, ctem-backend/app/services/scoring_runner.py",
                    "how": "Implemented threat intelligence multipliers applying a 1.5x penalty when a CVE has confirmed active weaponized exploitation (CISA KEV catalog). Built the batch scoring orchestrator (score_assets, score_all_assets) that iterates through all discovered assets to assign P1-P4 tiers and detect criticality mismatches."
                }
            ]
        },
        {
            "team": "Team 4: Graph Topology, SIEM Logs & UEBA Analytics",
            "lead": "Collective Supervisory Council: Himansh Purswani, Avinash Shankar P T, Mohd Aaqib",
            "lead_desc": "Managed collectively by all Team Leads. Supervised the intersection between network topology (Blast Radius), real-time threat intelligence (Security Onion / Suricata), user behavior anomaly detection, and cross-team alert correlation.",
            "desc": "Team 4 evaluates the downstream impact of an asset compromise, ingests real-time network intrusion logs, and analyzes identity authentication anomalies.",
            "members": [
                {
                    "name": "Tanya",
                    "role": "Blast Radius Topology Visualization UI",
                    "files": "ctem-frontend/components/BlastRadiusGraph.tsx, ctem-frontend/app/blast-radius/page.tsx",
                    "how": "Designed and implemented the interactive Blast Radius visualization component using dynamic SVG/Canvas graphics. Renders asset nodes, network boundaries, and dependency arrows to graphically present lateral movement paths and attack propagation."
                },
                {
                    "name": "Yogesh",
                    "role": "Blast Radius Graph Traversal Engine",
                    "files": "ctem-backend/app/services/blast_radius_service.py, ctem-backend/app/routers/assets.py, ctem-frontend/components/DeclareDependencyModal.tsx",
                    "how": "Built the 700+ line graph traversal algorithm calculating blast radius impact. Traverses asset dependencies via breadth-first search across same_subnet, same_zone, and dependency_edges to compute the logarithmic blast radius multiplier: 1.0 + log2(1 + connected_nodes) * 0.25."
                },
                {
                    "name": "Dhanavelan",
                    "role": "Risk Heatmap Component & Priority Grid Aggregation",
                    "files": "ctem-frontend/components/RiskHeatmap.tsx, ctem-backend/app/routers/risk.py",
                    "how": "Created the responsive Risk Heatmap component visually grouping organizational assets by priority tier (P1 Critical through P4 Low). Integrated real-time client-side search by hostname and IP, connected to the backend GET /risk/heatmap endpoint."
                },
                {
                    "name": "Rahil",
                    "role": "SIEM / Security Onion Ingestion & UEBA Detection Engine",
                    "files": "ctem-backend/app/services/log_ingestion_service.py, ctem-backend/app/services/ueba_service.py, ctem-backend/scripts/ueba_forwarder.py",
                    "how": "Developed the ingestion pipeline for Security Onion and Suricata NIDS logs (POST /logs/events). Implemented 3 rule-based UEBA identity anomaly detectors: (1) Rapid burst of 5 failed logins within 15 minutes, (2) Origin IP drift on successful login, and (3) Off-hours logins between 22:00 and 06:00 UTC. Provided a live endpoint forwarding script."
                }
            ]
        },
        {
            "team": "Team 5: SOC Executive Dashboard, Web UI & Alert Operations",
            "lead": "Executive Technical Leadership Oversight",
            "lead_desc": "Oversight on end-to-end user experience, dashboard performance, responsive layouts, API communication integrity, and interactive security demonstration features.",
            "desc": "Team 5 delivers the user experience, executive oversight screens, operational alert response tools, and zero-trust hardware control interfaces.",
            "members": [
                {
                    "name": "Abhishek",
                    "role": "Typed API Client & Frontend Data Models",
                    "files": "ctem-frontend/lib/api.ts, ctem-frontend/lib/types.ts",
                    "how": "Architected the typed frontend API layer (api.ts) with dynamic base URL resolution, allowing seamless switching between localhost and LAN IPs without CORS failures. Defined strict TypeScript interfaces for Assets, Scans, Alerts, Risk Scores, and Peripherals."
                },
                {
                    "name": "Pooja",
                    "role": "Cybersecurity UI Theme & Priority Badge System",
                    "files": "ctem-frontend/components/Badge.tsx, ctem-frontend/app/globals.css, ctem-frontend/tailwind.config.js",
                    "how": "Established the SOC dark-theme design tokens and typography. Created the reusable Badge component providing consistent visual indicators for scan states (queued, running, complete) and severity tiers (P1 Red, P2 Orange, P3 Yellow, P4 Green, Resolved Emerald)."
                },
                {
                    "name": "Vijayashree",
                    "role": "Executive Dashboard, Alert Incident Queue & Simulator UI",
                    "files": "ctem-frontend/app/page.tsx, ctem-frontend/app/alerts/page.tsx, ctem-frontend/app/monitoring/page.tsx, ctem-frontend/app/peripherals/page.tsx",
                    "how": "Built the primary executive dashboard displaying high-level KPI metric cards and active alerts feed. Developed the SOC Alert Triage page with one-click Acknowledge and Resolve state transitions. Created the interactive Security Monitoring testing console allowing evaluators to simulate Suricata exploit alerts and UEBA brute-force attacks."
                }
            ]
        }
    ]

    for team in team_details:
        t_head = doc.add_paragraph()
        t_head.paragraph_format.space_before = Pt(14)
        t_head.paragraph_format.space_after = Pt(2)
        r_th = t_head.add_run(team["team"])
        r_th.font.name = "Arial"
        r_th.font.size = Pt(13)
        r_th.font.bold = True
        r_th.font.color.rgb = RGBColor(14, 116, 144)

        if "lead" in team:
            t_lead_p = doc.add_paragraph()
            t_lead_p.paragraph_format.space_after = Pt(2)
            r_lpfx = t_lead_p.add_run("★ Technical Lead / Supervisor: ")
            r_lpfx.font.name = "Arial"
            r_lpfx.font.size = Pt(10)
            r_lpfx.font.bold = True
            r_lpfx.font.color.rgb = RGBColor(30, 58, 138)

            r_lnm = t_lead_p.add_run(f"{team['lead']}\n")
            r_lnm.font.name = "Arial"
            r_lnm.font.size = Pt(10)
            r_lnm.font.bold = True
            r_lnm.font.color.rgb = RGBColor(15, 23, 42)

            r_ldesc = t_lead_p.add_run(f"   Supervisory Role: {team['lead_desc']}")
            r_ldesc.font.name = "Arial"
            r_ldesc.font.size = Pt(9)
            r_ldesc.font.italic = True
            r_ldesc.font.color.rgb = RGBColor(71, 85, 105)

        t_desc = doc.add_paragraph()
        t_desc.paragraph_format.space_after = Pt(8)
        r_td = t_desc.add_run(team["desc"])
        r_td.font.name = "Arial"
        r_td.font.size = Pt(9.5)
        r_td.font.italic = True
        r_td.font.color.rgb = RGBColor(71, 85, 105)

        for mem in team["members"]:
            m_p = doc.add_paragraph()
            m_p.paragraph_format.space_before = Pt(4)
            m_p.paragraph_format.space_after = Pt(2)

            r_name = m_p.add_run(f"• {mem['name']} — ")
            r_name.font.name = "Arial"
            r_name.font.size = Pt(10)
            r_name.font.bold = True
            r_name.font.color.rgb = RGBColor(15, 23, 42)

            r_role = m_p.add_run(f"{mem['role']}\n")
            r_role.font.name = "Arial"
            r_role.font.size = Pt(9.5)
            r_role.font.bold = True
            r_role.font.color.rgb = RGBColor(30, 58, 138)

            r_fl = m_p.add_run("   Code Location: ")
            r_fl.font.name = "Arial"
            r_fl.font.size = Pt(8.5)
            r_fl.font.bold = True
            r_fl.font.color.rgb = RGBColor(100, 116, 139)

            r_fp = m_p.add_run(f"{mem['files']}\n")
            r_fp.font.name = "Courier New"
            r_fp.font.size = Pt(8)
            r_fp.font.color.rgb = RGBColor(194, 65, 12)

            r_hl = m_p.add_run("   Technical Operation: ")
            r_hl.font.name = "Arial"
            r_hl.font.size = Pt(8.5)
            r_hl.font.bold = True
            r_hl.font.color.rgb = RGBColor(100, 116, 139)

            r_hw = m_p.add_run(f"{mem['how']}\n")
            r_hw.font.name = "Arial"
            r_hw.font.size = Pt(8.5)
            r_hw.font.color.rgb = RGBColor(51, 65, 85)

    doc.save(doc_path)
    print(f"[SUCCESS] Document generated successfully: {doc_path}")

if __name__ == "__main__":
    out_dir = "/Users/dhinesh/Downloads/new 01"
    doc_file = os.path.join(out_dir, "CTEM_Team_Attribution_and_Architecture.docx")
    create_document(doc_file)
    shutil.copy(doc_file, "/Users/dhinesh/Downloads/CTEM_Team_Attribution_and_Architecture.docx")
    print("[SUCCESS] Copied to /Users/dhinesh/Downloads/CTEM_Team_Attribution_and_Architecture.docx")
