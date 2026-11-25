-- ==============================================================================
-- Migration: 002_sentinel_auth_update.sql
-- Description: Brings PostgreSQL schema into 100% parity with SQLite persistence layer
-- Adds: push_login_transactions table, extended user profile columns,
--       notification preferences, missing challenge/session columns, and RLS policies.
-- ==============================================================================

-- 1. Extend user_profiles with additional profile fields and notification preferences
DO $$
BEGIN
    -- Extended profile identity columns
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_profiles' AND column_name = 'full_name') THEN
        ALTER TABLE public.user_profiles ADD COLUMN full_name VARCHAR(100) DEFAULT '';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_profiles' AND column_name = 'username') THEN
        ALTER TABLE public.user_profiles ADD COLUMN username VARCHAR(30) DEFAULT '';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_profiles' AND column_name = 'country') THEN
        ALTER TABLE public.user_profiles ADD COLUMN country VARCHAR(100) DEFAULT '';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_profiles' AND column_name = 'profile_picture_url') THEN
        ALTER TABLE public.user_profiles ADD COLUMN profile_picture_url TEXT DEFAULT '';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_profiles' AND column_name = 'date_of_birth') THEN
        ALTER TABLE public.user_profiles ADD COLUMN date_of_birth VARCHAR(30) DEFAULT '';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_profiles' AND column_name = 'preferred_language') THEN
        ALTER TABLE public.user_profiles ADD COLUMN preferred_language VARCHAR(20) DEFAULT 'en';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_profiles' AND column_name = 'time_zone') THEN
        ALTER TABLE public.user_profiles ADD COLUMN time_zone VARCHAR(50) DEFAULT 'UTC';
    END IF;

    -- Security notification preference toggles
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_profiles' AND column_name = 'notify_new_device') THEN
        ALTER TABLE public.user_profiles ADD COLUMN notify_new_device BOOLEAN NOT NULL DEFAULT TRUE;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_profiles' AND column_name = 'notify_new_passkey') THEN
        ALTER TABLE public.user_profiles ADD COLUMN notify_new_passkey BOOLEAN NOT NULL DEFAULT TRUE;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_profiles' AND column_name = 'notify_failed_login') THEN
        ALTER TABLE public.user_profiles ADD COLUMN notify_failed_login BOOLEAN NOT NULL DEFAULT TRUE;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'user_profiles' AND column_name = 'notify_security_changes') THEN
        ALTER TABLE public.user_profiles ADD COLUMN notify_security_changes BOOLEAN NOT NULL DEFAULT TRUE;
    END IF;
END $$;

-- Unique partial index for clean usernames (ignoring empty string or null)
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_profiles_username_clean
    ON public.user_profiles(LOWER(username))
    WHERE username IS NOT NULL AND username != '';

-- 2. Extend auth_sessions with mobile_verification_url
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'auth_sessions' AND column_name = 'mobile_verification_url') THEN
        ALTER TABLE public.auth_sessions ADD COLUMN mobile_verification_url TEXT;
    END IF;
END $$;

-- 3. Extend auth_challenges with webauthn_challenge
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'auth_challenges' AND column_name = 'webauthn_challenge') THEN
        ALTER TABLE public.auth_challenges ADD COLUMN webauthn_challenge TEXT;
    END IF;
END $$;

-- 4. Extend registered_devices with revoked_at
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'registered_devices' AND column_name = 'revoked_at') THEN
        ALTER TABLE public.registered_devices ADD COLUMN revoked_at TIMESTAMPTZ;
    END IF;
END $$;

-- 5. Create push_login_transactions table (Push-to-Approve mobile biometric login)
CREATE TABLE IF NOT EXISTS public.push_login_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id VARCHAR(128) UNIQUE NOT NULL,
    user_id UUID NOT NULL,
    phone_number VARCHAR(32) NOT NULL,
    mobile_token_hash VARCHAR(128) UNIQUE NOT NULL,
    state VARCHAR(64) NOT NULL DEFAULT 'PENDING_APPROVAL',
    webauthn_challenge TEXT,
    credential_id VARCHAR(255),
    ip_address VARCHAR(64),
    user_agent TEXT,
    browser_name VARCHAR(64) DEFAULT 'Browser',
    os_name VARCHAR(64) DEFAULT 'Device',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    rejected_at TIMESTAMPTZ,
    authenticated_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

-- Indexes for push_login_transactions
CREATE INDEX IF NOT EXISTS idx_push_login_tx ON public.push_login_transactions(transaction_id);
CREATE INDEX IF NOT EXISTS idx_push_login_hash ON public.push_login_transactions(mobile_token_hash);
CREATE INDEX IF NOT EXISTS idx_push_login_state ON public.push_login_transactions(state);
CREATE INDEX IF NOT EXISTS idx_push_login_user ON public.push_login_transactions(user_id);

-- 6. Row-Level Security for push_login_transactions
ALTER TABLE public.push_login_transactions ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    DROP POLICY IF EXISTS "Users can read own push transactions" ON public.push_login_transactions;
    DROP POLICY IF EXISTS "Service role full access on push transactions" ON public.push_login_transactions;

    CREATE POLICY "Users can read own push transactions"
        ON public.push_login_transactions FOR SELECT
        USING (auth.uid() = user_id);

    CREATE POLICY "Service role full access on push transactions"
        ON public.push_login_transactions FOR ALL
        TO service_role
        USING (true)
        WITH CHECK (true);
END $$;
