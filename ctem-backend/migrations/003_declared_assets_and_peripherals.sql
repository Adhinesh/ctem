alter table assets
    add column if not exists declared_by text;

alter table assets
    add column if not exists declared_at timestamptz;

create table if not exists peripheral_devices (
    id uuid primary key default gen_random_uuid(),
    device_type text not null check (device_type in ('router', 'hard_drive', 'pendrive', 'usb_storage', 'other')),
    serial_number text,
    device_identifier text,
    label text,
    associated_asset_id uuid references assets(id) on delete set null,
    ip_address text,
    authorized boolean not null default false,
    authorized_by text,
    authorized_at timestamptz,
    created_at timestamptz not null default now()
);

create unique index if not exists idx_peripheral_serial on peripheral_devices(serial_number) where serial_number is not null;
create index if not exists idx_peripheral_device_identifier on peripheral_devices(device_identifier);

create table if not exists peripheral_check_events (
    id uuid primary key default gen_random_uuid(),
    peripheral_id uuid references peripheral_devices(id) on delete set null,
    serial_number text,
    device_identifier text,
    device_type text,
    result text not null check (result in ('authorized', 'unauthorized', 'unknown', 'unreachable', 'reachable')),
    checked_at timestamptz not null default now()
);

create index if not exists idx_peripheral_events_peripheral_id on peripheral_check_events(peripheral_id);
