-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- 1. TARGETS TABLE
-- NOTE: Removed UNIQUE constraint on `domain` — allows re-scanning the same domain.
create table if not exists public.targets (
    id uuid default uuid_generate_v4() primary key,
    domain text not null,
    status text default 'pending', -- 'pending', 'scanning', 'completed', 'failed'
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- 2. SUBDOMAINS TABLE (Discovered assets from active DNS recon)
create table if not exists public.subdomains (
    id uuid default uuid_generate_v4() primary key,
    target_id uuid references public.targets(id) on delete cascade,
    subdomain text not null,
    cname text,
    http_status integer,
    live_status text default 'unknown', -- 'live', 'dead', 'unknown'
    discovered_at timestamp with time zone default timezone('utc'::text, now()) not null,
    unique(target_id, subdomain)
);

-- 3. AGENT REASONING LOGS (Streams agent thoughts to the UI via Supabase Realtime)
create table if not exists public.agent_logs (
    id uuid default uuid_generate_v4() primary key,
    target_id uuid references public.targets(id) on delete cascade,
    step_name text not null,     -- e.g. 'Enumeration', 'DNS Probe', 'Analysis Loop', 'Completed', 'Failed'
    log_level text default 'info', -- 'info', 'warning', 'critical'
    message text not null,
    timestamp timestamp with time zone default timezone('utc'::text, now()) not null
);

-- 4. VULNERABILITIES TABLE (High-confidence findings with full remediation reports)
create table if not exists public.vulnerabilities (
    id uuid default uuid_generate_v4() primary key,
    target_id uuid references public.targets(id) on delete cascade,
    subdomain_id uuid references public.subdomains(id) on delete set null,
    vuln_type text not null,     -- e.g. 'Subdomain Takeover'
    severity text not null,      -- 'Low', 'Medium', 'High', 'Critical'
    evidence text not null,      -- Full AI-generated Markdown remediation advisory report
    resolved boolean default false,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- =============================================================================
-- ROW LEVEL SECURITY
-- =============================================================================
ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE subdomains ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- READ policies — allow the anon key (frontend) to read all rows
-- ---------------------------------------------------------------------------
CREATE POLICY IF NOT EXISTS "Allow public read on targets"
ON targets FOR SELECT TO anon USING (true);

CREATE POLICY IF NOT EXISTS "Allow public read on subdomains"
ON subdomains FOR SELECT TO anon USING (true);

CREATE POLICY IF NOT EXISTS "Allow public read on agent_logs"
ON agent_logs FOR SELECT TO anon USING (true);

CREATE POLICY IF NOT EXISTS "Allow public read on vulnerabilities"
ON vulnerabilities FOR SELECT TO anon USING (true);

-- ---------------------------------------------------------------------------
-- WRITE policies — allow the service_role (backend) to insert and update rows
-- The service_role bypasses RLS by default, but these are explicit for clarity.
-- ---------------------------------------------------------------------------
CREATE POLICY IF NOT EXISTS "Allow service_role write on targets"
ON targets FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY IF NOT EXISTS "Allow service_role write on subdomains"
ON subdomains FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY IF NOT EXISTS "Allow service_role write on agent_logs"
ON agent_logs FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY IF NOT EXISTS "Allow service_role write on vulnerabilities"
ON vulnerabilities FOR ALL TO service_role USING (true) WITH CHECK (true);

-- =============================================================================
-- REALTIME PUBLICATION
-- Make sure these tables are included in the Supabase Realtime publication.
-- Run these in the Supabase SQL editor if realtime events are not arriving.
-- =============================================================================
-- ALTER PUBLICATION supabase_realtime ADD TABLE public.targets;
-- ALTER PUBLICATION supabase_realtime ADD TABLE public.subdomains;
-- ALTER PUBLICATION supabase_realtime ADD TABLE public.agent_logs;
-- ALTER PUBLICATION supabase_realtime ADD TABLE public.vulnerabilities;
