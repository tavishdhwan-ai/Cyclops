-- ==============================================================================
-- Rollback Migration: 002_rollback.sql
-- Description: Safely rolls back changes introduced in 002_sentinel_auth_update.sql
-- ==============================================================================

-- 1. Drop push_login_transactions policies and table
DROP POLICY IF EXISTS "Service role full access on push transactions" ON public.push_login_transactions;
DROP POLICY IF EXISTS "Users can read own push transactions" ON public.push_login_transactions;
DROP TABLE IF EXISTS public.push_login_transactions CASCADE;

-- 2. Drop unique username index
DROP INDEX IF EXISTS public.idx_user_profiles_username_clean;

-- 3. Drop additive columns added to existing tables
ALTER TABLE public.registered_devices DROP COLUMN IF EXISTS revoked_at;
ALTER TABLE public.auth_challenges DROP COLUMN IF EXISTS webauthn_challenge;
ALTER TABLE public.auth_sessions DROP COLUMN IF EXISTS mobile_verification_url;

ALTER TABLE public.user_profiles
    DROP COLUMN IF EXISTS notify_security_changes,
    DROP COLUMN IF EXISTS notify_failed_login,
    DROP COLUMN IF EXISTS notify_new_passkey,
    DROP COLUMN IF EXISTS notify_new_device,
    DROP COLUMN IF EXISTS time_zone,
    DROP COLUMN IF EXISTS preferred_language,
    DROP COLUMN IF EXISTS date_of_birth,
    DROP COLUMN IF EXISTS profile_picture_url,
    DROP COLUMN IF EXISTS country,
    DROP COLUMN IF EXISTS username,
    DROP COLUMN IF EXISTS full_name;
