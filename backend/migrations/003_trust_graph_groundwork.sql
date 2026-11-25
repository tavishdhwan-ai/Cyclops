-- ==============================================================================
-- Migration: 003_trust_graph_groundwork.sql
-- Description: Groundwork tables for Connected Accounts, Personal Trust Graph,
--              Behavioural Baselines, and Privacy-Preserving Threat Signatures.
-- Note: Does NOT implement OAuth or mailbox ingestion; prepares schema only.
-- ==============================================================================

-- 1. connected_accounts table
-- Tracks authenticated external connections (e.g. Gmail read-only) per user
CREATE TABLE IF NOT EXISTS public.connected_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    provider VARCHAR(32) NOT NULL DEFAULT 'google', -- 'google', 'microsoft', etc.
    account_email VARCHAR(255) NOT NULL,
    scopes TEXT[] DEFAULT '{https://www.googleapis.com/auth/gmail.readonly}',
    token_encrypted TEXT, -- AES-256-GCM encrypted refresh token (NEVER plaintext)
    token_expires_at TIMESTAMPTZ,
    status VARCHAR(32) NOT NULL DEFAULT 'pending', -- 'pending', 'connected', 'expired', 'revoked'
    sync_state JSONB DEFAULT '{}'::jsonb,
    last_synced_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_connected_accounts_user_provider_email UNIQUE (user_id, provider, account_email)
);

CREATE INDEX IF NOT EXISTS idx_conn_acc_user ON public.connected_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_conn_acc_status ON public.connected_accounts(status);

-- 2. trust_nodes table
-- Represents entities in the Personal Trust Graph (sender emails, sender domains)
CREATE TABLE IF NOT EXISTS public.trust_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    entity_type VARCHAR(32) NOT NULL DEFAULT 'email', -- 'email', 'domain'
    entity_value VARCHAR(255) NOT NULL, -- e.g. 'alice@company.com' or 'company.com'
    display_name VARCHAR(255) DEFAULT '',
    trust_score DOUBLE PRECISION NOT NULL DEFAULT 50.0, -- 0.0 (untrusted) to 100.0 (fully verified)
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.0, -- 0.0 to 1.0 based on data volume
    interaction_count INTEGER NOT NULL DEFAULT 0,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_user_verified BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_trust_nodes_user_entity UNIQUE (user_id, entity_type, entity_value)
);

CREATE INDEX IF NOT EXISTS idx_trust_nodes_user ON public.trust_nodes(user_id);
CREATE INDEX IF NOT EXISTS idx_trust_nodes_value ON public.trust_nodes(entity_value);
CREATE INDEX IF NOT EXISTS idx_trust_nodes_score ON public.trust_nodes(trust_score);

-- 3. trust_edges table
-- Represents relationship interactions between user and entities or between entities
CREATE TABLE IF NOT EXISTS public.trust_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    source_node_id UUID REFERENCES public.trust_nodes(id) ON DELETE CASCADE,
    target_node_id UUID REFERENCES public.trust_nodes(id) ON DELETE CASCADE,
    interaction_type VARCHAR(32) NOT NULL DEFAULT 'email_exchange',
    weight DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    message_count INTEGER NOT NULL DEFAULT 1,
    thread_count INTEGER NOT NULL DEFAULT 1,
    inbound_count INTEGER NOT NULL DEFAULT 0,
    outbound_count INTEGER NOT NULL DEFAULT 0,
    last_interaction_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_trust_edges_user_nodes UNIQUE (user_id, source_node_id, target_node_id, interaction_type)
);

CREATE INDEX IF NOT EXISTS idx_trust_edges_user ON public.trust_edges(user_id);
CREATE INDEX IF NOT EXISTS idx_trust_edges_source ON public.trust_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_trust_edges_target ON public.trust_edges(target_node_id);

-- 4. behavioral_baselines table
-- Statistical communication baselines per sender entity for anomaly detection
CREATE TABLE IF NOT EXISTS public.behavioral_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    node_id UUID REFERENCES public.trust_nodes(id) ON DELETE CASCADE,
    baseline_type VARCHAR(64) NOT NULL, -- 'timing_distribution', 'urgency_baseline', 'typical_links'
    baseline_metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    anomaly_threshold DOUBLE PRECISION NOT NULL DEFAULT 2.0,
    sample_size INTEGER NOT NULL DEFAULT 0,
    last_computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_behavioral_baselines_user_node_type UNIQUE (user_id, node_id, baseline_type)
);

CREATE INDEX IF NOT EXISTS idx_behav_base_user ON public.behavioral_baselines(user_id);
CREATE INDEX IF NOT EXISTS idx_behav_base_node ON public.behavioral_baselines(node_id);

-- 5. threat_signatures table
-- Privacy-preserving collective threat intelligence. Stores ONLY one-way cryptographic hashes
-- of confirmed threats (never personal emails, names, or messages).
CREATE TABLE IF NOT EXISTS public.threat_signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_hash VARCHAR(128) UNIQUE NOT NULL, -- SHA-256 of normalized domain, URL or file
    indicator_type VARCHAR(32) NOT NULL, -- 'domain_hash', 'url_hash', 'attachment_hash'
    risk_level VARCHAR(32) NOT NULL DEFAULT 'suspicious', -- 'safe', 'suspicious', 'malicious'
    severity VARCHAR(32) NOT NULL DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    report_count INTEGER NOT NULL DEFAULT 1,
    tags TEXT[] DEFAULT '{}',
    first_reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_sig_hash ON public.threat_signatures(indicator_hash);
CREATE INDEX IF NOT EXISTS idx_threat_sig_type ON public.threat_signatures(indicator_type);

-- ==============================================================================
-- Row-Level Security Policies for Groundwork Tables
-- ==============================================================================

ALTER TABLE public.connected_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.trust_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.trust_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.behavioral_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_signatures ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    -- connected_accounts policies
    DROP POLICY IF EXISTS "Users can manage own connected accounts" ON public.connected_accounts;
    DROP POLICY IF EXISTS "Service role full access on connected accounts" ON public.connected_accounts;

    CREATE POLICY "Users can manage own connected accounts"
        ON public.connected_accounts FOR ALL
        USING (auth.uid() = user_id)
        WITH CHECK (auth.uid() = user_id);

    CREATE POLICY "Service role full access on connected accounts"
        ON public.connected_accounts FOR ALL
        TO service_role
        USING (true)
        WITH CHECK (true);

    -- trust_nodes policies
    DROP POLICY IF EXISTS "Users can manage own trust nodes" ON public.trust_nodes;
    DROP POLICY IF EXISTS "Service role full access on trust nodes" ON public.trust_nodes;

    CREATE POLICY "Users can manage own trust nodes"
        ON public.trust_nodes FOR ALL
        USING (auth.uid() = user_id)
        WITH CHECK (auth.uid() = user_id);

    CREATE POLICY "Service role full access on trust nodes"
        ON public.trust_nodes FOR ALL
        TO service_role
        USING (true)
        WITH CHECK (true);

    -- trust_edges policies
    DROP POLICY IF EXISTS "Users can manage own trust edges" ON public.trust_edges;
    DROP POLICY IF EXISTS "Service role full access on trust edges" ON public.trust_edges;

    CREATE POLICY "Users can manage own trust edges"
        ON public.trust_edges FOR ALL
        USING (auth.uid() = user_id)
        WITH CHECK (auth.uid() = user_id);

    CREATE POLICY "Service role full access on trust edges"
        ON public.trust_edges FOR ALL
        TO service_role
        USING (true)
        WITH CHECK (true);

    -- behavioral_baselines policies
    DROP POLICY IF EXISTS "Users can manage own behavioral baselines" ON public.behavioral_baselines;
    DROP POLICY IF EXISTS "Service role full access on behavioral baselines" ON public.behavioral_baselines;

    CREATE POLICY "Users can manage own behavioral baselines"
        ON public.behavioral_baselines FOR ALL
        USING (auth.uid() = user_id)
        WITH CHECK (auth.uid() = user_id);

    CREATE POLICY "Service role full access on behavioral baselines"
        ON public.behavioral_baselines FOR ALL
        TO service_role
        USING (true)
        WITH CHECK (true);

    -- threat_signatures policies (collective intelligence: read by authenticated users, write by service role)
    DROP POLICY IF EXISTS "Authenticated users can read threat signatures" ON public.threat_signatures;
    DROP POLICY IF EXISTS "Service role full access on threat signatures" ON public.threat_signatures;

    CREATE POLICY "Authenticated users can read threat signatures"
        ON public.threat_signatures FOR SELECT
        TO authenticated
        USING (true);

    CREATE POLICY "Service role full access on threat signatures"
        ON public.threat_signatures FOR ALL
        TO service_role
        USING (true)
        WITH CHECK (true);
END $$;
