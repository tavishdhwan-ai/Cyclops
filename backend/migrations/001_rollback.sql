-- ==============================================================================
-- Rollback Migration: 001_rollback.sql
-- Description: Safely tears down Sentinel AI authentication schema in reverse order
-- ==============================================================================

-- 1. Drop RLS Policies
DROP POLICY IF EXISTS "Service role full access on challenges" ON public.auth_challenges;
DROP POLICY IF EXISTS "Service role full access on sessions" ON public.auth_sessions;
DROP POLICY IF EXISTS "Users can read own session status" ON public.auth_sessions;
DROP POLICY IF EXISTS "Service role full access on profiles" ON public.user_profiles;
DROP POLICY IF EXISTS "Users can update own profile" ON public.user_profiles;
DROP POLICY IF EXISTS "Users can read own profile" ON public.user_profiles;

-- 2. Drop Audit & Supporting Tables
DROP TABLE IF EXISTS public.auth_audit_events CASCADE;
DROP TABLE IF EXISTS public.webauthn_credentials CASCADE;
DROP TABLE IF EXISTS public.auth_challenges CASCADE;
DROP TABLE IF EXISTS public.auth_sessions CASCADE;

-- 3. Only drop user_profiles if explicitly rolled back (or retain to preserve existing data)
-- DROP TABLE IF EXISTS public.user_profiles CASCADE;
