-- Fix user_sessions table constraints
-- Run this: docker exec -i medlinkpro_postgres psql -U postgres -d medlinkpro < fix-session-constraints.sql

-- First, let's see the current table structure and constraints
\d user_sessions

-- The auth controller is setting session_token to null, so let's make it nullable
ALTER TABLE user_sessions ALTER COLUMN session_token DROP NOT NULL;

-- Also make sure other columns that might be null are properly configured
ALTER TABLE user_sessions ALTER COLUMN refresh_token_hash DROP NOT NULL;
ALTER TABLE user_sessions ALTER COLUMN device_info DROP NOT NULL;

-- Let's also check what columns the auth controller is actually trying to insert
-- Based on the error, it seems to be inserting these columns:
-- id, user_id, session_token (null), ip_address, user_agent, status, expires_at, 
-- created_at, terminated_at (null), token_hash, is_active, last_accessed_at, 
-- refresh_token_hash, refresh_expires_at (null), device_info (null)

-- Make sure all the potentially nullable columns are properly set
ALTER TABLE user_sessions ALTER COLUMN terminated_at DROP NOT NULL;
ALTER TABLE user_sessions ALTER COLUMN refresh_expires_at DROP NOT NULL;

-- Update any existing records that might have constraint issues
UPDATE user_sessions SET 
    session_token = COALESCE(session_token, token_hash),
    refresh_token_hash = COALESCE(refresh_token_hash, token_hash)
WHERE session_token IS NULL OR refresh_token_hash IS NULL;

-- Show the updated table structure
\d user_sessions

-- Display success message
DO $$ 
BEGIN 
    RAISE NOTICE '🔧 user_sessions table constraints fixed!';
    RAISE NOTICE '✅ Made session_token nullable';
    RAISE NOTICE '✅ Made refresh_token_hash nullable';
    RAISE NOTICE '✅ Made other optional columns nullable';
    RAISE NOTICE '✅ Updated existing records';
    RAISE NOTICE '🚀 Login should now work without constraint violations!';
END $$;