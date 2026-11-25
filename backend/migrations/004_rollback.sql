-- ==============================================================================
-- Rollback: 004_rollback.sql
-- Description: Revokes SELECT permission granted to authenticated on user_profiles
-- ==============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        REVOKE SELECT ON TABLE public.user_profiles FROM authenticated;
    END IF;
END $$;
