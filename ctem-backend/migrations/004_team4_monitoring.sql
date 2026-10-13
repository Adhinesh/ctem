create table if not exists security_events (
    id uuid primary key default gen_random_uuid(),
    asset_id uuid references assets(id) on delete set null,
    event_type text not null,
    source text not null default 'security_onion',
    summary text,
    severity text not null default 'low' check (severity in ('low', 'medium', 'high', 'critical')),
    occurred_at timestamptz not null default now(),
    created_at timestamptz not null default now()
);

create index if not exists idx_security_events_asset_id on security_events(asset_id);
create index if not exists idx_security_events_occurred_at on security_events(occurred_at);

create table if not exists alerts (
    id uuid primary key default gen_random_uuid(),
    alert_type text not null check (alert_type in ('ueba', 'endpoint_change', 'log_rule', 'peripheral_unauthorized', 'hardware_change')),
    title text not null,
    description text,
    severity text not null default 'low' check (severity in ('low', 'medium', 'high', 'critical')),
    asset_id uuid references assets(id) on delete set null,
    source_event_id uuid references security_events(id) on delete set null,
    status text not null default 'open' check (status in ('open', 'acknowledged', 'resolved')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists idx_alerts_status on alerts(status);
create index if not exists idx_alerts_asset_id on alerts(asset_id);

create table if not exists user_behavior_events (
    id uuid primary key default gen_random_uuid(),
    username text not null,
    event_type text not null check (event_type in ('login', 'failed_login', 'file_access', 'privilege_change', 'other')),
    source_ip text,
    occurred_at timestamptz not null default now(),
    created_at timestamptz not null default now()
);

create index if not exists idx_user_behavior_username on user_behavior_events(username);
create index if not exists idx_user_behavior_occurred_at on user_behavior_events(occurred_at);

create table if not exists asset_change_log (
    id uuid primary key default gen_random_uuid(),
    asset_id uuid not null references assets(id) on delete cascade,
    change_type text not null check (change_type in ('port_opened', 'port_closed', 'service_changed', 'version_changed')),
    previous_value text,
    new_value text,
    detected_at timestamptz not null default now()
);

create index if not exists idx_asset_change_log_asset_id on asset_change_log(asset_id);
