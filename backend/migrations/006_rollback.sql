-- ==============================================================================
-- Rollback Migration: 006_rollback.sql
-- Description: Safely removes Gmail OAuth integration tables, indexes, and policies.
--              Does NOT affect core Cyclops authentication or user_profiles tables.
-- ==============================================================================

DROP POLICY IF EXISTS "Service role full access on gmail_oauth_transactions" ON public.gmail_oauth_transactions;
DROP TABLE IF EXISTS public.gmail_oauth_transactions CASCADE;

DROP POLICY IF EXISTS "Service role full access on gmail_connections" ON public.gmail_connections;
DROP TABLE IF EXISTS public.gmail_connections CASCADE;
