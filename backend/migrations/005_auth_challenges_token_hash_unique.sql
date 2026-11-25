-- ==============================================================================
-- Migration: 005_auth_challenges_token_hash_unique.sql
-- Description: Adds UNIQUE constraint to auth_challenges.token_hash for ON CONFLICT upsert.
--              Cleans duplicates if any exist before adding the constraint.
-- ==============================================================================

DO $$
BEGIN
    -- 1. Deduplicate if any duplicate token_hashes exist (keeps newest record)
    DELETE FROM public.auth_challenges a
    USING public.auth_challenges b
    WHERE a.token_hash = b.token_hash
      AND a.created_at < b.created_at;

    -- 2. Add unique constraint if not present
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_auth_challenges_token_hash'
    ) THEN
        ALTER TABLE public.auth_challenges
        ADD CONSTRAINT uq_auth_challenges_token_hash UNIQUE (token_hash);
    END IF;
END $$;
