-- Complete Schema Fix for MedLinkPro Authentication
-- Run this: docker exec -i medlinkpro_postgres psql -U postgres -d medlinkpro < complete-schema-fix.sql

-- Add missing columns to users table that the auth files expect
ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id UUID;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_token VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_email_verified BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS hipaa_training_completed BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS hipaa_training_date TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_last_changed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_failed_login_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS account_locked_until TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_token VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires TIMESTAMP WITH TIME ZONE;

-- Rename existing columns to match what the auth files expect
-- The User.ts expects: failed_login_attempts but we have failed_login_attempts ✓
-- The User.ts expects: is_active -> status (convert boolean to string)

-- Add status column (the auth files expect status as string, not is_active as boolean)
ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';

-- Update status for existing users based on is_active
UPDATE users SET status = 
  CASE 
    WHEN is_active = true THEN 'active'
    WHEN is_active = false THEN 'inactive'
    ELSE 'active'
  END
WHERE status IS NULL;

-- Fix user_sessions table structure
-- The middleware expects different column names
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS token_hash VARCHAR(255);
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS last_accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;

-- Update existing sessions
UPDATE user_sessions SET 
  is_active = CASE WHEN status = 'active' THEN true ELSE false END,
  token_hash = session_token
WHERE token_hash IS NULL;

-- Create the auth_audit_logs table that the middleware expects
CREATE TABLE IF NOT EXISTS auth_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    additional_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for the new columns
CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_email_verification_token ON users(email_verification_token);
CREATE INDEX IF NOT EXISTS idx_users_password_reset_token ON users(password_reset_token);
CREATE INDEX IF NOT EXISTS idx_users_account_locked_until ON users(account_locked_until);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

CREATE INDEX IF NOT EXISTS idx_user_sessions_token_hash ON user_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_user_sessions_is_active ON user_sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_user_sessions_last_accessed ON user_sessions(last_accessed_at);

CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_user_id ON auth_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_action ON auth_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_created_at ON auth_audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_success ON auth_audit_logs(success);

-- Create api_keys table for API key authentication
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    permissions JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at);

-- Update the demo users to have the correct structure
UPDATE users SET 
  status = 'active',
  is_email_verified = true,
  password_last_changed = CURRENT_TIMESTAMP,
  hipaa_training_completed = true,
  hipaa_training_date = CURRENT_TIMESTAMP
WHERE email LIKE '%@medlinkpro.demo';

-- Create enum type for user_status if needed
DO $$ BEGIN
    CREATE TYPE user_status AS ENUM (
        'pending_verification',
        'active',
        'inactive',
        'suspended',
        'deleted'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Function to clean up expired tokens and sessions
CREATE OR REPLACE FUNCTION cleanup_auth_data()
RETURNS void AS $$
BEGIN
    -- Clean up expired sessions
    UPDATE user_sessions 
    SET is_active = false, status = 'expired'
    WHERE is_active = true AND expires_at < CURRENT_TIMESTAMP;
    
    -- Clean up expired password reset tokens
    UPDATE users 
    SET password_reset_token = NULL, password_reset_expires = NULL
    WHERE password_reset_expires < CURRENT_TIMESTAMP;
    
    -- Clean up old audit logs (keep for HIPAA retention - 7 years)
    DELETE FROM auth_audit_logs 
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '7 years';
    
    -- Clean up old expired sessions (keep for 30 days for audit purposes)
    DELETE FROM user_sessions 
    WHERE is_active = false AND terminated_at < CURRENT_TIMESTAMP - INTERVAL '30 days';
    
    RAISE NOTICE 'Authentication data cleanup completed';
END;
$$ LANGUAGE plpgsql;

-- Create a trigger to automatically update the updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply the trigger to users table if not exists
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;

-- Display success message
DO $$ 
BEGIN 
    RAISE NOTICE '🔧 Complete Schema Fix Applied Successfully!';
    RAISE NOTICE '✅ Added all missing columns to users table';
    RAISE NOTICE '✅ Fixed user_sessions table structure';
    RAISE NOTICE '✅ Created auth_audit_logs table';
    RAISE NOTICE '✅ Created api_keys table for API authentication';
    RAISE NOTICE '✅ Updated demo users with correct data structure';
    RAISE NOTICE '✅ Added proper indexes for performance';
    RAISE NOTICE '✅ Created cleanup functions for maintenance';
    RAISE NOTICE '🚀 Authentication system should now work perfectly!';
    RAISE NOTICE '';
    RAISE NOTICE 'Demo Users Available:';
    RAISE NOTICE '👤 admin@medlinkpro.demo (super_admin)';
    RAISE NOTICE '👤 billing.manager@medlinkpro.demo (billing_manager)';
    RAISE NOTICE '👤 specialist@medlinkpro.demo (billing_specialist)';
    RAISE NOTICE '👤 provider@medlinkpro.demo (provider)';
    RAISE NOTICE 'Password for all: Admin123!';
END $$;