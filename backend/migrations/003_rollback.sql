-- ==============================================================================
-- Rollback Migration: 003_rollback.sql
-- Description: Safely rolls back tables created in 003_trust_graph_groundwork.sql
-- ==============================================================================

DROP POLICY IF EXISTS "Service role full access on threat signatures" ON public.threat_signatures;
DROP POLICY IF EXISTS "Authenticated users can read threat signatures" ON public.threat_signatures;
DROP TABLE IF EXISTS public.threat_signatures CASCADE;

DROP POLICY IF EXISTS "Service role full access on behavioral baselines" ON public.behavioral_baselines;
DROP POLICY IF EXISTS "Users can manage own behavioral baselines" ON public.behavioral_baselines;
DROP TABLE IF EXISTS public.behavioral_baselines CASCADE;

DROP POLICY IF EXISTS "Service role full access on trust edges" ON public.trust_edges;
DROP POLICY IF EXISTS "Users can manage own trust edges" ON public.trust_edges;
DROP TABLE IF EXISTS public.trust_edges CASCADE;

DROP POLICY IF EXISTS "Service role full access on trust nodes" ON public.trust_nodes;
DROP POLICY IF EXISTS "Users can manage own trust nodes" ON public.trust_nodes;
DROP TABLE IF EXISTS public.trust_nodes CASCADE;

DROP POLICY IF EXISTS "Service role full access on connected accounts" ON public.connected_accounts;
DROP POLICY IF EXISTS "Users can manage own connected accounts" ON public.connected_accounts;
DROP TABLE IF EXISTS public.connected_accounts CASCADE;
