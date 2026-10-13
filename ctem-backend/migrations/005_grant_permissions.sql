-- ============================================================
-- Migration 005: Grant permissions to Supabase roles
-- Run this in Supabase Dashboard → SQL Editor
-- ============================================================

-- Grant schema-level usage (required before table-level grants work)
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

-- Grant access on all existing tables to service_role (trusted backend role)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO service_role;

-- Grant read access to anon/authenticated (for future RLS policies)
GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon, authenticated;
GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated;

-- Ensure future tables automatically inherit these grants
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON TABLES TO service_role;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON SEQUENCES TO service_role;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO anon, authenticated;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT INSERT, UPDATE, DELETE ON TABLES TO authenticated;
