-- ==============================================================================
-- CTEM PLATFORM - COMPLETE CONSOLIDATED DATABASE SCHEMA
-- Run this entire script ONCE in your Supabase Project:
--   Supabase Dashboard -> SQL Editor -> New Query -> Paste & Click Run
-- ==============================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 2. CORE ASSETS
CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname TEXT,
    ip_address TEXT,
    cidr TEXT,
    asset_type TEXT,
    network_zone TEXT,
    zone TEXT CHECK (zone IN ('internal', 'external')),
    criticality TEXT NOT NULL DEFAULT 'low' CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    asset_status TEXT NOT NULL DEFAULT 'discovered' CHECK (asset_status IN ('discovered', 'declared', 'confirmed')),
    asset_confirmed BOOLEAN NOT NULL DEFAULT false,
    declared_by TEXT,
    declared_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname) WHERE hostname IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_ip_address ON assets(ip_address) WHERE ip_address IS NOT NULL;

-- 3. OPEN PORTS & SERVICES
CREATE TABLE IF NOT EXISTS open_ports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    port TEXT NOT NULL,
    protocol TEXT,
    service TEXT,
    product TEXT,
    version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_open_ports_unique ON open_ports(asset_id, port, protocol);

-- 4. RISK SCORES & BLAST RADIUS
CREATE TABLE IF NOT EXISTS risk_scores (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    matched_product TEXT,
    matched_version TEXT,
    cvss_source TEXT CHECK (cvss_source IN ('circl', 'nvd', 'unknown')),
    base_score NUMERIC,
    exploit_score NUMERIC,
    asset_weight NUMERIC,
    blast_radius NUMERIC NOT NULL DEFAULT 1.0,
    raw_composite NUMERIC,
    composite_score NUMERIC,
    priority_tier TEXT CHECK (priority_tier IN ('P1', 'P2', 'P3', 'P4')),
    sla_hours INTEGER,
    criticality_mismatch BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_risk_scores_asset_id ON risk_scores(asset_id);
CREATE INDEX IF NOT EXISTS idx_risk_scores_priority_tier ON risk_scores(priority_tier);

-- 5. ASSET ARCHITECTURE & SERVICE DEPENDENCIES
CREATE TABLE IF NOT EXISTS asset_dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    depends_on_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asset_dependencies_asset_id ON asset_dependencies(asset_id);

-- 6. SCANS PIPELINE
CREATE TABLE IF NOT EXISTS scans (
    scan_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'ingesting', 'scoring', 'complete', 'failed')),
    labels JSONB,
    error_message TEXT,
    tenant_id TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_assets (
    scan_id UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (scan_id, asset_id)
);

-- 7. PERIPHERALS & HARDWARE ALLOWLIST
CREATE TABLE IF NOT EXISTS peripheral_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_type TEXT NOT NULL,
    serial_number TEXT,
    device_identifier TEXT,
    label TEXT,
    ip_address TEXT,
    authorized BOOLEAN NOT NULL DEFAULT false,
    authorized_by TEXT,
    authorized_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_peripherals_serial ON peripheral_devices(serial_number) WHERE serial_number IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_peripherals_identifier ON peripheral_devices(device_identifier) WHERE device_identifier IS NOT NULL;

CREATE TABLE IF NOT EXISTS peripheral_check_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_type TEXT,
    serial_number TEXT,
    device_identifier TEXT,
    result TEXT NOT NULL CHECK (result IN ('authorized', 'unauthorized', 'unknown')),
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    peripheral_id UUID REFERENCES peripheral_devices(id) ON DELETE SET NULL
);

-- 8. SECURITY MONITORING, LOGS & ALERTS
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'security_onion',
    summary TEXT,
    severity TEXT NOT NULL DEFAULT 'low' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_security_events_asset_id ON security_events(asset_id);
CREATE INDEX IF NOT EXISTS idx_security_events_occurred_at ON security_events(occurred_at);

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_type TEXT NOT NULL CHECK (alert_type IN ('ueba', 'ueba_anomaly', 'endpoint_change', 'log_rule', 'log_severity', 'peripheral_unauthorized', 'hardware_change', 'new_exposure', 'asset_change')),
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'low' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    source_event_id UUID REFERENCES security_events(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_asset_id ON alerts(asset_id);

CREATE TABLE IF NOT EXISTS user_behavior_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('login', 'failed_login', 'file_access', 'privilege_change', 'other')),
    source_ip TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_behavior_username ON user_behavior_events(username);
CREATE INDEX IF NOT EXISTS idx_user_behavior_occurred_at ON user_behavior_events(occurred_at);

CREATE TABLE IF NOT EXISTS asset_change_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    change_type TEXT NOT NULL CHECK (change_type IN ('port_opened', 'port_closed', 'service_changed', 'version_changed')),
    previous_value TEXT,
    new_value TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asset_change_log_asset_id ON asset_change_log(asset_id);

-- 9. PERMISSIONS GRANT (ALLOW SERVICE ROLE AND APP ACCESS)
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO service_role;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon, authenticated;
GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT INSERT, UPDATE, DELETE ON TABLES TO authenticated;
