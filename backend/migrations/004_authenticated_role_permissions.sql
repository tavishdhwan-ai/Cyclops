-- ==============================================================================
-- Migration: 004_authenticated_role_permissions.sql
-- Description: Minimal, least-privilege table grants for authenticated Supabase role.
--              Preserves Row-Level Security (RLS) and cross-user isolation.
-- ==============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        -- 1. user_profiles: Authenticated users can read their own profile (RLS enforced)
        GRANT SELECT ON TABLE public.user_profiles TO authenticated;

        -- STRICT SECURITY BOUNDARY:
        -- Zero access granted to 'anon' (unauthenticated public).
        -- Zero direct client access granted to 'authenticated' for sensitive server tables:
        -- public.auth_sessions, public.auth_challenges, public.webauthn_credentials,
        -- public.registered_devices, public.push_subscriptions,
        -- public.push_login_transactions, public.auth_audit_events.
        -- All authentication mutations, challenge validations, and passkey registrations
        -- are mediated exclusively by the FastAPI backend persistence layer.
    END IF;
END $$;
