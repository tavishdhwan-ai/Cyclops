-- ==============================================================================
-- Rollback: 005_rollback.sql
-- Description: Removes uq_auth_challenges_token_hash constraint from auth_challenges.
-- ==============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_auth_challenges_token_hash'
    ) THEN
        ALTER TABLE public.auth_challenges
        DROP CONSTRAINT uq_auth_challenges_token_hash;
    END IF;
END $$;
