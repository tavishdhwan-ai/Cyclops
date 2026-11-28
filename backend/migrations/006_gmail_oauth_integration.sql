-- ==============================================================================
-- Migration: 006_gmail_oauth_integration.sql
-- Description: Isolated persistence layer for Gmail OAuth 2.0 integration.
--              Stores encrypted refresh tokens, OAuth PKCE/state transactions,
--              and enforces strict tenant isolation and RLS privilege boundaries.
-- Note: Short-lived Google access tokens remain in backend memory and are NOT
--       persisted to PostgreSQL.
-- ==============================================================================

-- 1. gmail_connections table
-- Initially supports one active Gmail connection per Cyclops user (UNIQUE user_id).
CREATE TABLE IF NOT EXISTS public.gmail_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.user_profiles(user_id) ON DELETE CASCADE,
    gmail_address VARCHAR(255) NOT NULL,
    encrypted_refresh_token TEXT NOT NULL,
    granted_scopes TEXT[] NOT NULL DEFAULT '{https://www.googleapis.com/auth/gmail.readonly}',
    status VARCHAR(32) NOT NULL DEFAULT 'connected',
    connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified_at TIMESTAMPTZ,
    reauth_required BOOLEAN NOT NULL DEFAULT FALSE,
    reauth_reason VARCHAR(128),
    access_token_expires_at TIMESTAMPTZ,
    refresh_token_issued_at TIMESTAMPTZ,
    refresh_token_expires_estimate_at TIMESTAMPTZ,
    last_error_code VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_gmail_connections_user_id UNIQUE (user_id),
    CONSTRAINT chk_gmail_connections_status CHECK (status IN ('connected', 'reauth_required', 'revoked', 'error'))
);

CREATE INDEX IF NOT EXISTS idx_gmail_connections_user_id ON public.gmail_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_gmail_connections_status ON public.gmail_connections(status);

-- 2. gmail_oauth_transactions table
-- Short-lived, single-use OAuth 2.0 state & encrypted PKCE code_verifier persistence.
CREATE TABLE IF NOT EXISTS public.gmail_oauth_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    state_hash VARCHAR(128) NOT NULL,
    user_id UUID NOT NULL REFERENCES public.user_profiles(user_id) ON DELETE CASCADE,
    session_id VARCHAR(128) NOT NULL,
    code_verifier_encrypted TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    requested_scope VARCHAR(255) NOT NULL DEFAULT 'https://www.googleapis.com/auth/gmail.readonly',
    action_type VARCHAR(32) NOT NULL DEFAULT 'connect',
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_gmail_oauth_tx_state_hash UNIQUE (state_hash),
    CONSTRAINT chk_gmail_oauth_tx_action CHECK (action_type IN ('connect', 'reconnect'))
);

CREATE INDEX IF NOT EXISTS idx_gmail_oauth_tx_state_hash ON public.gmail_oauth_transactions(state_hash);
CREATE INDEX IF NOT EXISTS idx_gmail_oauth_tx_user_id ON public.gmail_oauth_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_gmail_oauth_tx_expires_at ON public.gmail_oauth_transactions(expires_at);

-- ==============================================================================
-- Row-Level Security (RLS) & Strict Privilege Boundaries
-- Gmail credential records must NEVER be directly accessible through
-- Supabase's public client API (anon or authenticated roles).
-- ==============================================================================

ALTER TABLE public.gmail_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gmail_oauth_transactions ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.gmail_connections FROM PUBLIC;
REVOKE ALL ON TABLE public.gmail_oauth_transactions FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        REVOKE ALL ON TABLE public.gmail_connections FROM anon;
        REVOKE ALL ON TABLE public.gmail_oauth_transactions FROM anon;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        REVOKE ALL ON TABLE public.gmail_connections FROM authenticated;
        REVOKE ALL ON TABLE public.gmail_oauth_transactions FROM authenticated;
    END IF;

    DROP POLICY IF EXISTS "Service role full access on gmail_connections" ON public.gmail_connections;
    DROP POLICY IF EXISTS "Service role full access on gmail_oauth_transactions" ON public.gmail_oauth_transactions;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        CREATE POLICY "Service role full access on gmail_connections"
            ON public.gmail_connections FOR ALL
            TO service_role
            USING (true)
            WITH CHECK (true);

        CREATE POLICY "Service role full access on gmail_oauth_transactions"
            ON public.gmail_oauth_transactions FOR ALL
            TO service_role
            USING (true)
            WITH CHECK (true);
    END IF;
END $$;
