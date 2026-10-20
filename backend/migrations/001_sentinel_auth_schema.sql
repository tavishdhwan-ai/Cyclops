-- ==============================================================================
-- Migration: 001_sentinel_auth_schema.sql
-- Description: Sentinel AI Dual-Channel Authentication & Session Security Schema
-- Authoritative State Engine: Email Gate 1, WhatsApp Gate 2, Mobile WebAuthn
-- ==============================================================================

-- 1. Enable UUID Extension if not present
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. user_profiles table
-- Preserves existing user profiles while expanding with E.164 phone, verification, and security tier
CREATE TABLE IF NOT EXISTS public.user_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE, -- References auth.users(id) in Supabase deployments
    email VARCHAR(255) NOT NULL,
    phone_number VARCHAR(32), -- Normalized international E.164 format
    phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
    display_name VARCHAR(100) DEFAULT '',
    goal VARCHAR(50) DEFAULT '',
    concerns TEXT[] DEFAULT '{}',
    experience VARCHAR(50) DEFAULT '',
    onboarding_completed BOOLEAN NOT NULL DEFAULT FALSE,
    security_tier INTEGER NOT NULL DEFAULT 1, -- Server-controlled authorization tier (1: Standard, 2: Enhanced 2FA, 3: Hardened)
    account_status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'active', 'suspended', 'security_review', 'deleted'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes on user_profiles
CREATE INDEX IF NOT EXISTS idx_user_profiles_user_id ON public.user_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_profiles_email ON public.user_profiles(email);
CREATE INDEX IF NOT EXISTS idx_user_profiles_phone ON public.user_profiles(phone_number);

-- 3. auth_sessions table
-- Tracks active application sessions and authentication transactions across devices
CREATE TABLE IF NOT EXISTS public.auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id VARCHAR(128) UNIQUE NOT NULL,
    user_id UUID REFERENCES public.user_profiles(user_id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    phone_number VARCHAR(32),
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    mobile_verified BOOLEAN NOT NULL DEFAULT FALSE,
    biometric_verified BOOLEAN NOT NULL DEFAULT FALSE,
    biometric_status VARCHAR(64) DEFAULT 'pending',
    state VARCHAR(64) NOT NULL DEFAULT 'EMAIL_REQUIRED',
    user_agent TEXT,
    ip_address VARCHAR(64),
    expires_at TIMESTAMPTZ NOT NULL,
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes on auth_sessions
CREATE INDEX IF NOT EXISTS idx_auth_sessions_tx_id ON public.auth_sessions(transaction_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON public.auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_state ON public.auth_sessions(state);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON public.auth_sessions(expires_at);

-- 4. auth_challenges table
-- Stores cryptographically hashed single-use challenges for WhatsApp and WebAuthn
CREATE TABLE IF NOT EXISTS public.auth_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id VARCHAR(128) NOT NULL,
    user_id UUID,
    challenge_type VARCHAR(32) NOT NULL, -- 'whatsapp_mobile_link', 'webauthn_assertion', 'email_otp'
    token_hash VARCHAR(128) NOT NULL, -- SHA-256 hash of single-use challenge token
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes on auth_challenges
CREATE INDEX IF NOT EXISTS idx_auth_challenges_hash ON public.auth_challenges(token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_tx ON public.auth_challenges(transaction_id);

-- 5. webauthn_credentials table
-- Stores public key credential material and signature counters for registered mobile authenticators
CREATE TABLE IF NOT EXISTS public.webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    credential_id VARCHAR(255) UNIQUE NOT NULL, -- Base64URL credential ID
    public_key TEXT NOT NULL, -- Public key bytes or JWK (never stores private keys!)
    counter BIGINT NOT NULL DEFAULT 0,
    device_name VARCHAR(100) DEFAULT 'Mobile Authenticator',
    transports TEXT[] DEFAULT '{internal}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes on webauthn_credentials
CREATE INDEX IF NOT EXISTS idx_webauthn_cred_user ON public.webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_cred_id ON public.webauthn_credentials(credential_id);

-- 6. auth_audit_events table
-- Tamper-evident audit logging of authentication transitions and security events
CREATE TABLE IF NOT EXISTS public.auth_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id VARCHAR(128),
    user_id UUID,
    event_type VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL, -- 'SUCCESS', 'FAILURE', 'DENIED', 'EXPIRED'
    details JSONB DEFAULT '{}'::jsonb,
    ip_address VARCHAR(64),
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_tx ON public.auth_audit_events(transaction_id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_user ON public.auth_audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_time ON public.auth_audit_events(created_at);

-- ==============================================================================
-- Row-Level Security (RLS) Policies
-- ==============================================================================

ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.auth_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.auth_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.auth_audit_events ENABLE ROW LEVEL SECURITY;

-- 1. user_profiles policies
-- Users can only read and update their own profile; server-side service role has full access
DO $$
BEGIN
    DROP POLICY IF EXISTS "Users can read own profile" ON public.user_profiles;
    DROP POLICY IF EXISTS "Users can update own profile" ON public.user_profiles;
    DROP POLICY IF EXISTS "Service role full access on profiles" ON public.user_profiles;

    CREATE POLICY "Users can read own profile"
        ON public.user_profiles FOR SELECT
        USING (auth.uid() = user_id);

    CREATE POLICY "Users can update own profile"
        ON public.user_profiles FOR UPDATE
        USING (auth.uid() = user_id)
        WITH CHECK (auth.uid() = user_id);

    CREATE POLICY "Service role full access on profiles"
        ON public.user_profiles FOR ALL
        TO service_role
        USING (true)
        WITH CHECK (true);
END $$;

-- 2. auth_sessions & challenges policies
-- Only the authenticated user can read their session status; all mutations restricted to server
DO $$
BEGIN
    DROP POLICY IF EXISTS "Users can read own session status" ON public.auth_sessions;
    DROP POLICY IF EXISTS "Service role full access on sessions" ON public.auth_sessions;
    DROP POLICY IF EXISTS "Service role full access on challenges" ON public.auth_challenges;

    CREATE POLICY "Users can read own session status"
        ON public.auth_sessions FOR SELECT
        USING (auth.uid() = user_id);

    CREATE POLICY "Service role full access on sessions"
        ON public.auth_sessions FOR ALL
        TO service_role
        USING (true)
        WITH CHECK (true);

    CREATE POLICY "Service role full access on challenges"
        ON public.auth_challenges FOR ALL
        TO service_role
        USING (true)
        WITH CHECK (true);
END $$;
