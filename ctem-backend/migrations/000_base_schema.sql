create extension if not exists pgcrypto;

create table if not exists assets (
    id uuid primary key default gen_random_uuid(),
    hostname text,
    ip_address text,
    cidr text,
    asset_type text,
    network_zone text,
    zone text check (zone in ('internal', 'external')),
    criticality text not null default 'low' check (criticality in ('low', 'medium', 'high', 'critical')),
    asset_status text not null default 'discovered' check (asset_status in ('discovered', 'declared', 'confirmed')),
    asset_confirmed boolean not null default false,
    declared_by text,
    declared_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index if not exists idx_assets_hostname on assets(hostname) where hostname is not null;
create unique index if not exists idx_assets_ip_address on assets(ip_address) where ip_address is not null;

create table if not exists open_ports (
    id uuid primary key default gen_random_uuid(),
    asset_id uuid not null references assets(id) on delete cascade,
    port text not null,
    protocol text,
    service text,
    product text,
    version text,
    created_at timestamptz not null default now()
);

create unique index if not exists idx_open_ports_unique on open_ports(asset_id, port, protocol);

create table if not exists risk_scores (
    id uuid primary key,
    asset_id uuid not null references assets(id) on delete cascade,
    cve_id text not null,
    matched_product text,
    matched_version text,
    cvss_source text check (cvss_source in ('circl', 'nvd', 'unknown')),
    base_score numeric,
    exploit_score numeric,
    asset_weight numeric,
    blast_radius numeric not null default 1.0,
    raw_composite numeric,
    composite_score numeric,
    priority_tier text check (priority_tier in ('P1', 'P2', 'P3', 'P4')),
    sla_hours integer,
    criticality_mismatch boolean not null default false,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists idx_risk_scores_asset_id on risk_scores(asset_id);
create index if not exists idx_risk_scores_priority_tier on risk_scores(priority_tier);

create table if not exists asset_dependencies (
    id uuid primary key default gen_random_uuid(),
    asset_id uuid not null references assets(id) on delete cascade,
    depends_on_asset_id uuid not null references assets(id) on delete cascade,
    created_at timestamptz not null default now()
);

create index if not exists idx_asset_dependencies_asset_id on asset_dependencies(asset_id);
