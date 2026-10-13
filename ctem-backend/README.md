# CTEM Platform Backend

FastAPI service implementing Team 1 (recon), Team 2 (ingestion/asset lifecycle), and Team 3 (risk scoring) against a shared Supabase project, plus the dashboard-triggered scan flow from Section 1 of the plan.

## 1. Prerequisites

- Python 3.10+
- A Supabase project (URL + service role or anon key, per what Team 2 gives you)
- The following CLI tools installed and on your `PATH` (used by `recon_runner.py`):
  - `subfinder`
  - `httpx` (ProjectDiscovery's httpx, not the Python library)
  - `nmap`
  - `gau`
  - `gcloud` (only needed if you'll scan `cloud_project` targets)

Install the Go-based recon tools, e.g.:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
```

Make sure `$(go env GOPATH)/bin` is on your `PATH` so these resolve.

## 2. Clone / unzip and install Python dependencies

```bash
cd ctem-backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Configure environment variables

```bash
cp .env.example .env
```

Fill in `.env`:

```
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-key
NVD_API_KEY=            # optional, NVD works without a key at lower rate limits
```

Load them before running the app. Either export manually:

```bash
export $(cat .env | xargs)
```

or use a tool like `python-dotenv` / `direnv` if you prefer — the app reads these via `os.environ` in `app/config.py`, so any method that sets real process environment variables works.

## 4. Run the database migrations

These are plain SQL files, not an auto-migration tool — run them once against your Supabase project, **in order**, via the Supabase SQL editor or `psql`:

```bash
psql "$SUPABASE_DB_URL" -f migrations/000_base_schema.sql
psql "$SUPABASE_DB_URL" -f migrations/001_scans_and_zone.sql
psql "$SUPABASE_DB_URL" -f migrations/002_risk_scores_blast_radius.sql
psql "$SUPABASE_DB_URL" -f migrations/003_declared_assets_and_peripherals.sql
psql "$SUPABASE_DB_URL" -f migrations/004_team4_monitoring.sql
```

`000` creates every base table this backend touches from scratch: `assets`, `open_ports`, `risk_scores`, `asset_dependencies`. If you already have any of these tables from other work, review `000` before running it — it uses `create table if not exists`, so it won't clobber existing tables, but it won't reconcile column differences either. `001`–`003` only add columns/new tables on top of `000`.

## 5. Run the API

```bash
uvicorn app.main:app --reload --port 8000
```

Check it's up:

```bash
curl http://localhost:8000/health
```

Interactive docs (Swagger UI) are auto-generated at `http://localhost:8000/docs`.

## 6. Declared assets and peripheral authorization

Two things that don't come from a scan:

**Register declared assets** (org-provided PCs, laptops, servers, VPS, firewalls — anything the org tells you about directly instead of Team 1 discovering it):

```bash
curl -X POST http://localhost:8000/assets/declared \
  -H "Content-Type: application/json" \
  -d '{
    "declared_by": "org-onboarding",
    "assets": [
      {"hostname": "finance-pc-01", "asset_type": "computer", "zone": "internal", "criticality": "medium"},
      {"ip_address": "10.0.0.5", "asset_type": "vps", "zone": "external", "criticality": "high"}
    ]
  }'
```

Re-running this with the same hostname/IP updates the existing asset instead of duplicating it.

**Register an authorized peripheral** (router, hard drive, pendrive) — this is an allowlist, not a scan:

```bash
curl -X POST http://localhost:8000/peripherals \
  -H "Content-Type: application/json" \
  -d '{"device_type": "pendrive", "serial_number": "SN12345", "authorized": true, "authorized_by": "it-admin"}'
```

**Check whether a device is authorized** (call this whenever a device connection is reported, e.g. from an agent):

```bash
curl -X POST http://localhost:8000/peripherals/check \
  -H "Content-Type: application/json" \
  -d '{"serial_number": "SN99999"}'
```

Returns `authorized`, `unauthorized`, or `unknown` (device never registered). Every check is logged to `peripheral_check_events`.

**Check whether a router/network peripheral is reachable** (simple TCP connect, not a scan):

```bash
curl -X POST http://localhost:8000/peripherals/<peripheral_id>/check-reachability
```

Returns `reachable` or `unreachable` based on whether the stored `ip_address` accepts a connection on port 80.

## 7. Team 4 — logs, endpoint/hardware change detection, UEBA

This is the monitoring branch that runs in parallel to the scan pipeline and feeds alerts to the dashboard.

**Log ingestion** (point Security Onion, Sysmon, or any log source at this):

```bash
curl -X POST http://localhost:8000/logs/events \
  -H "Content-Type: application/json" \
  -d '{"source": "security_onion", "event_type": "suspicious_process", "severity": "high", "summary": "unexpected outbound connection"}'
```

`high`/`critical` severity events automatically raise an alert. Only the event summary is stored — no raw log payloads.

**Endpoint/hardware change detection** — this runs automatically, not something you call directly. Every time a scan re-touches an asset, `ingestion_runner.py` diffs the newly found ports against what was there before and:
- logs the change to `asset_change_log`
- raises an `endpoint_change` alert for newly opened ports
- raises a `hardware_change` alert for a changed service or version on an existing port

Check history for one asset:

```bash
curl http://localhost:8000/assets/<asset_id>/changes
```

**UEBA** — rule-based, since there's no auth/session system to hook into. Feed it login/activity events from wherever you're capturing them (a login page, an agent, a VPN gateway):

```bash
curl -X POST http://localhost:8000/ueba/events \
  -H "Content-Type: application/json" \
  -d '{"username": "jdoe", "event_type": "login", "source_ip": "203.0.113.5"}'
```

Three rules run automatically: 5+ failed logins in 15 minutes, login from a source IP never seen before for that user, and logins outside 06:00–22:00 UTC. Each raises an alert when triggered.

**Alerts** — the single feed everything above writes to:

```bash
curl http://localhost:8000/alerts?status=open
curl -X POST http://localhost:8000/alerts/<alert_id>/acknowledge
curl -X POST http://localhost:8000/alerts/<alert_id>/resolve
```

## 8. Quick smoke test

Trigger a scan:

```bash
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: test-tenant" \
  -d '{"target": "example.com", "target_type": "domain"}'
```

Poll status:

```bash
curl http://localhost:8000/scans/<scan_id>
```

Once `status` is `complete`, check findings:

```bash
curl http://localhost:8000/risk/heatmap
```

## 9. Project layout

```
app/
  config.py              formula constants, thresholds, SLA table
  main.py                FastAPI app + router wiring
  db/
    supabase_client.py   supabase-py client singleton
  routers/
    scans.py             POST /scans, GET /scans/{id}, /scans/{id}/assets, GET /scans
    assets.py            asset CRUD/lifecycle, POST /assets/declared, GET /assets/{id}/changes
    risk.py              risk scores, explanation, heatmap
    peripherals.py       peripheral registration, authorization check, reachability check
    alerts.py            alert listing, acknowledge, resolve
    logs.py              security event ingestion (Security Onion / Sysmon feed point)
    ueba.py              login/behavior event submission and history
  services/
    recon_runner.py      Team 1 tool wrappers (subfinder/httpx/nmap/gau/gcloud)
    ingestion_runner.py  Team 2 asset resolution + lifecycle, triggers change detection
    declared_asset_service.py  bulk registration of org-declared assets
    scoring_runner.py    Team 3 CVE matching + scoring orchestration
    risk_engine.py       pure scoring/tiering functions
    blast_radius_service.py  interim blast radius (subnet/zone/dependency modes)
    peripheral_service.py    peripheral allowlist checks + TCP reachability check
    change_detection_service.py  diffs rescans against prior state, raises endpoint/hardware alerts
    alert_service.py     central alert create/list/acknowledge/resolve
    log_ingestion_service.py  stores security events, raises alerts on high/critical severity
    ueba_service.py      rule-based login anomaly detection
    cve_lookup.py        CIRCL/NVD/EPSS/KEV lookups
    target_validation.py scan target validation + rate limiting
    scan_service.py      scan record CRUD + pipeline orchestration
  schemas/
    scans.py             pydantic request/response models
migrations/
  000_base_schema.sql               creates assets, open_ports, risk_scores, asset_dependencies
  001_scans_and_zone.sql            creates scans, scan_assets, adds zone to assets
  002_risk_scores_blast_radius.sql  adds blast_radius/tiering columns to risk_scores
  003_declared_assets_and_peripherals.sql  declared-asset fields, peripheral_devices, peripheral_check_events
  004_team4_monitoring.sql          security_events, alerts, user_behavior_events, asset_change_log
```

## 10. Known gaps to close before this goes further

- `target_validation.check_rate_limit` is in-process memory — fine for one worker, resets if the process restarts, and doesn't share state across multiple uvicorn workers. Swap for a Supabase table or Redis if you deploy with more than one worker.
- No auth layer yet, per the plan's "simplified for now" trajectory — every endpoint is open. Add a real auth dependency before this touches anything but your own lab.
- `BLAST_RADIUS_REACHABILITY_MODE` defaults to `same_subnet` in `config.py`. The plan leaves this as an explicit open decision — confirm it before relying on the numbers.
- `_match_cve` in `scoring_runner.py` does a simple keyword search against CIRCL; it's a starting point, not a hardened matching pipeline.
- Peripheral checking is allowlist-based, not detection-based — something has to call `/peripherals/check` when a device connects (an agent, a script, manual entry). This backend doesn't watch USB ports itself.
- Router reachability check is a bare TCP connect on port 80 — it tells you the device answers on that port, not that it's healthy or unmodified.
- `assets.hostname` and `assets.ip_address` each have a unique index in `000_base_schema.sql`. That's what makes the "resolve or create" logic in `ingestion_runner.py` work without duplicates — if you ever load in bulk data from elsewhere, make sure it respects that uniqueness or the insert will fail.
- No auth layer at all, anywhere — not on the core endpoints, not on `/logs/events`, `/ueba/events`, or `/peripherals/check`. Anyone who can reach this API can post fake log events, fake login events, or fake peripheral checks and generate alerts (or suppress real ones by never reporting). This was left out on request; it needs to exist before this is exposed beyond a local lab.
- UEBA is three simple rules (failed-login burst, new source IP, off-hours), not real behavioral modeling — it has no baseline period, so a legitimately new employee's first login triggers the same alert as a compromised account.
- Change detection only fires on rescan, so it only catches drift between scans, not real-time changes.
