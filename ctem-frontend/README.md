# CTEM Platform Frontend

Next.js/TypeScript/Tailwind dashboard for the CTEM backend. No auth — every page hits the backend directly.

## 1. Prerequisites

- Node.js 18+
- The backend running and reachable (see `ctem-backend/README.md`)

## 2. Install

```bash
cd ctem-frontend
npm install
```

## 3. Configure the backend URL

```bash
cp .env.example .env.local
```

Edit `.env.local` if your backend isn't at the default:

```
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

## 4. Run

```bash
npm run dev
```

Open `http://localhost:3000`.

For a production build:

```bash
npm run build
npm run start
```

## 5. Pages

- `/` — dashboard: heat map, P1–P4 counts, latest open alerts
- `/scans` — scan history + "New Scan" wizard (target, target type, business unit/criticality labels); shows the "already scanned" warning instead of silently duplicating
- `/scans/[id]` — live status polling and the assets tied to that scan
- `/assets` — asset list, filterable by lifecycle status, with a one-click Confirm action for discovered assets
- `/assets/[id]` — full asset detail: confirm/delete, edit criticality, the "why is this vulnerable" explanation per finding, and change history (port/service/version drift detected on rescans)
- `/alerts` — all alerts (Team 4's UEBA/log/change-detection/peripheral output converges here), filterable by status, with acknowledge/resolve
- `/peripherals` — register a device as authorized/unauthorized, run an authorization check by serial number, check a router's reachability

## 6. What's deliberately left out

- No auth, no login page, no sessions — per your instruction. Every page assumes an open backend.
- No real-time transport (WebSocket/Supabase Realtime) — status pages poll on a timer instead (dashboard every 15s, scan detail every 5s, alerts every 10s). Swap in a subscription later if you want push updates.
- No TanStack Query/Zustand — state is plain `useState`/`useEffect` per page. Fine at this size; worth introducing if the app grows past these six pages.
- Next.js 14.x is now end-of-life (EOL October 2025); this uses the final patched release (14.2.35). There will be no further security patches for new CVEs on this line going forward — worth planning a move to 15.x or later at some point.
