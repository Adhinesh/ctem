create table if not exists log_events (
    id uuid primary key default gen_random_uuid(),
    source text not null default 'security_onion',
    asset_id uuid references assets(id) on delete set null,
    event_type text,
    severity text check (severity in ('low', 'medium', 'high', 'critical')),
    raw_payload jsonb,
    occurred_at timestamptz not null default now(),
    ingested_at timestamptz not null default now()
);

create index if not exists idx_log_events_asset_id on log_events(asset_id);
create index if not exists idx_log_events_occurred_at on log_events(occurred_at);

create table if not exists alerts (
    id uuid primary key default gen_random_uuid(),
    asset_id uuid references assets(id) on delete set null,
    alert_type text not null check (alert_type in ('ueba_anomaly', 'asset_change', 'peripheral_unauthorized', 'log_severity', 'new_exposure')),
    severity text not null check (severity in ('low', 'medium', 'high', 'critical')),
    title text not null,
    description text,
    source_reference_id uuid,
    status text not null default 'open' check (status in ('open', 'acknowledged', 'resolved', 'false_positive')),
    acknowledged_by text,
    acknowledged_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists idx_alerts_asset_id on alerts(asset_id);
create index if not exists idx_alerts_status on alerts(status);
create index if not exists idx_alerts_severity on alerts(severity);

create table if not exists exposures (
    id uuid primary key default gen_random_uuid(),
    asset_id uuid not null references assets(id) on delete cascade,
    exposure_type text not null,
    description text,
    detected_at timestamptz not null default now(),
    resolved_at timestamptz
);

create index if not exists idx_exposures_asset_id on exposures(asset_id);

create table if not exists asset_changes (
    id uuid primary key default gen_random_uuid(),
    asset_id uuid not null references assets(id) on delete cascade,
    scan_id uuid references scans(scan_id) on delete set null,
    change_type text not null check (change_type in ('new_port', 'new_subdomain', 'port_closed', 'service_changed', 'new_asset')),
    detail jsonb,
    detected_at timestamptz not null default now()
);

create index if not exists idx_asset_changes_asset_id on asset_changes(asset_id);

create table if not exists ueba_baselines (
    id uuid primary key default gen_random_uuid(),
    asset_id uuid not null references assets(id) on delete cascade,
    metric_name text not null,
    baseline_value numeric,
    updated_at timestamptz not null default now()
);

create unique index if not exists idx_ueba_baseline_unique on ueba_baselines(asset_id, metric_name);
