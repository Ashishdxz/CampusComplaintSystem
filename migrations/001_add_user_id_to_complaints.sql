-- Migration: 001_add_user_id_to_complaints.sql
-- Description: Add nullable user_id referencing auth.users(id) with ON DELETE SET NULL.
--              Verifies exact FK definition (source, target, and ON DELETE SET NULL).
--              Additive-only, transaction-wrapped, and 100% rerun-safe.

BEGIN;

-- 1. Safely add user_id column as nullable UUID if it does not already exist
ALTER TABLE public.complaints 
ADD COLUMN IF NOT EXISTS user_id UUID;

-- 2. Safely verify and attach Foreign Key with exact definition validation
DO $$
BEGIN
    -- Check whether the exact intended foreign key definition already exists:
    -- - Source: public.complaints.user_id
    -- - Target: auth.users.id
    -- - Delete Rule: ON DELETE SET NULL (confdeltype = 'n')
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace tn ON tn.oid = t.relnamespace
        JOIN pg_class ft ON ft.oid = c.confrelid
        JOIN pg_namespace ftn ON ftn.oid = ft.relnamespace
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
        JOIN pg_attribute fa ON fa.attrelid = ft.oid AND fa.attnum = ANY(c.confkey)
        WHERE c.contype = 'f'
          AND tn.nspname = 'public'
          AND t.relname = 'complaints'
          AND a.attname = 'user_id'
          AND ftn.nspname = 'auth'
          AND ft.relname = 'users'
          AND fa.attname = 'id'
          AND c.confdeltype = 'n'
    ) THEN
        -- Ensure constraint name is not taken by an unrelated definition
        IF NOT EXISTS (
            SELECT 1 
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace tn ON tn.oid = t.relnamespace
            WHERE tn.nspname = 'public' 
              AND t.relname = 'complaints' 
              AND c.conname = 'complaints_user_id_fkey'
        ) THEN
            ALTER TABLE public.complaints 
            ADD CONSTRAINT complaints_user_id_fkey 
            FOREIGN KEY (user_id) 
            REFERENCES auth.users(id) 
            ON DELETE SET NULL;
        ELSE
            RAISE EXCEPTION 'Constraint "complaints_user_id_fkey" already exists with an incompatible definition. Please inspect existing constraints.';
        END IF;
    END IF;
END $$;

-- 3. Create performance index for student personal complaints dashboard (/my-complaints)
CREATE INDEX IF NOT EXISTS idx_complaints_user_id 
ON public.complaints(user_id);

COMMIT;
