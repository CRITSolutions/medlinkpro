-- Final fix for auth_audit_logs table structure
-- Run this: docker exec -i medlinkpro_postgres psql -U postgres -d medlinkpro < final-audit-fix.sql

-- Check what columns exist in auth_audit_logs
\d auth_audit_logs

-- Drop the existing auth_audit_logs table/view and recreate with correct structure
DROP TABLE IF EXISTS auth_audit_logs CASCADE;
DROP VIEW IF EXISTS auth_audit_logs CASCADE;

-- Create the auth_audit_logs table with EXACT columns the middleware expects
CREATE TABLE auth_audit_logs (
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

-- Create indexes
CREATE INDEX idx_auth_audit_logs_user_id ON auth_audit_logs(user_id);
CREATE INDEX idx_auth_audit_logs_action ON auth_audit_logs(action);
CREATE INDEX idx_auth_audit_logs_created_at ON auth_audit_logs(created_at);
CREATE INDEX idx_auth_audit_logs_success ON auth_audit_logs(success);

-- Grant permissions
GRANT ALL PRIVILEGES ON auth_audit_logs TO postgres;

-- Test the table structure
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'auth_audit_logs' 
ORDER BY ordinal_position;

-- Display success
DO $$ 
BEGIN 
    RAISE NOTICE '🔧 Final audit table fix completed!';
    RAISE NOTICE '✅ auth_audit_logs table recreated with correct columns';
    RAISE NOTICE '✅ Ready for authentication testing';
END $$;