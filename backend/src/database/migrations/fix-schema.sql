ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';

-- Create index on status column
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

-- Option 2: Create auth_audit_logs table as alias/view to audit_logs
-- (if the middleware expects this specific table name)
CREATE OR REPLACE VIEW auth_audit_logs AS 
SELECT * FROM audit_logs;

-- Alternative: Create the actual table if needed
CREATE TABLE IF NOT EXISTS auth_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id UUID REFERENCES user_sessions(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index for the auth_audit_logs table
CREATE INDEX IF NOT EXISTS idx_auth_audit_user_id ON auth_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_audit_action ON auth_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_auth_audit_created_at ON auth_audit_logs(created_at);

-- Update existing users to have proper status
UPDATE users SET status = 'active' WHERE status IS NULL;

-- Display what was fixed
DO $$ 
BEGIN 
    RAISE NOTICE '🔧 Schema fixes applied:';
    RAISE NOTICE '✅ Added status column to users table';
    RAISE NOTICE '✅ Created auth_audit_logs table/view';
    RAISE NOTICE '✅ Updated existing users with active status';
    RAISE NOTICE '🚀 Authentication system should now work properly!';
END $$;