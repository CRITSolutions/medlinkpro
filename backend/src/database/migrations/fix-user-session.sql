-- Fix user_sessions table structure
-- Run this: docker exec -i medlinkpro_postgres psql -U postgres -d medlinkpro < fix-user-sessions.sql

-- First, let's see what columns currently exist
\d user_sessions

-- Add the missing refresh_token_hash column
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS refresh_token_hash VARCHAR(255);

-- Add any other columns that might be missing based on your auth controller
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_info JSONB;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS refresh_expires_at TIMESTAMP WITH TIME ZONE;

-- Update existing sessions to have proper structure
UPDATE user_sessions SET 
    refresh_token_hash = token_hash,
    refresh_expires_at = expires_at + INTERVAL '7 days'
WHERE refresh_token_hash IS NULL;

-- Create indexes for the new columns
CREATE INDEX IF NOT EXISTS idx_user_sessions_refresh_token_hash ON user_sessions(refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_user_sessions_refresh_expires_at ON user_sessions(refresh_expires_at);

-- Show the updated table structure
\d user_sessions

-- Display success message
DO $$ 
BEGIN 
    RAISE NOTICE '🔧 user_sessions table fixed successfully!';
    RAISE NOTICE '✅ Added refresh_token_hash column';
    RAISE NOTICE '✅ Added device_info and refresh_expires_at columns';
    RAISE NOTICE '✅ Updated existing sessions';
    RAISE NOTICE '✅ Added proper indexes';
    RAISE NOTICE '🚀 Login should now work!';
END $$;