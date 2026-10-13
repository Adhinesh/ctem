alter table assets
    add column if not exists zone text check (zone in ('internal', 'external'));

update assets
set zone = case
    when network_zone is not null and lower(network_zone) like '%internal%' then 'internal'
    when network_zone is not null and lower(network_zone) like '%external%' then 'external'
    else zone
end
where zone is null;

create table if not exists scans (
    scan_id uuid primary key default gen_random_uuid(),
    target text not null,
    target_type text not null check (target_type in ('domain', 'ip', 'cidr', 'cloud_project')),
    tenant_id uuid,
    status text not null default 'queued' check (status in ('queued', 'running', 'ingesting', 'scoring', 'complete', 'failed')),
    labels jsonb default '{}'::jsonb,
    error_message text,
    started_at timestamptz,
    finished_at timestamptz,
    created_at timestamptz not null default now()
);

create table if not exists scan_assets (
    scan_id uuid not null references scans(scan_id) on delete cascade,
    asset_id uuid not null references assets(id) on delete cascade,
    primary key (scan_id, asset_id)
);

create index if not exists idx_scan_assets_scan_id on scan_assets(scan_id);
create index if not exists idx_scans_target on scans(target);
create index if not exists idx_assets_zone on assets(zone);
