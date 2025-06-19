-- Fix demo users: unlock accounts and reset passwords
-- Run this: docker exec -i medlinkpro_postgres psql -U postgres -d medlinkpro < fix-demo-users.sql

BEGIN;

-- 1. Unlock all demo accounts
UPDATE users 
SET 
    failed_login_attempts = 0,
    last_failed_login_at = NULL,
    account_locked_until = NULL
WHERE email LIKE '%@medlinkpro.demo';

-- 2. Reset passwords for all demo users to properly hashed "Admin123!"
-- Note: This is the bcrypt hash for "Admin123!" with salt rounds 12
UPDATE users 
SET password_hash = '$2a$12$LVzNDMyf8/CvnVh.K6oH6.Y2YHpA4bZqYj4kPPz3k.YxGvQ8r4Zqm'
WHERE email = 'admin@medlinkpro.demo';

UPDATE users 
SET password_hash = '$2a$12$LVzNDMyf8/CvnVh.K6oH6.Y2YHpA4bZqYj4kPPz3k.YxGvQ8r4Zqm'
WHERE email = 'billing.manager@medlinkpro.demo';

UPDATE users 
SET password_hash = '$2a$12$LVzNDMyf8/CvnVh.K6oH6.Y2YHpA4bZqYj4kPPz3k.YxGvQ8r4Zqm'
WHERE email = 'specialist@medlinkpro.demo';

UPDATE users 
SET password_hash = '$2a$12$LVzNDMyf8/CvnVh.K6oH6.Y2YHpA4bZqYj4kPPz3k.YxGvQ8r4Zqm'
WHERE email = 'provider@medlinkpro.demo';

-- 3. Ensure all demo users are active and verified
UPDATE users 
SET 
    status = 'active',
    is_email_verified = true,
    password_last_changed = CURRENT_TIMESTAMP
WHERE email LIKE '%@medlinkpro.demo';

-- 4. Clean up any existing sessions for these users
UPDATE user_sessions 
SET is_active = false, status = 'terminated'
WHERE user_id IN (
    SELECT id FROM users WHERE email LIKE '%@medlinkpro.demo'
);

-- 5. Clear audit logs for fresh start (optional)
DELETE FROM auth_audit_logs 
WHERE user_id IN (
    SELECT id FROM users WHERE email LIKE '%@medlinkpro.demo'
);

COMMIT;

-- Verify the fixes
SELECT 
    email,
    status,
    is_email_verified,
    failed_login_attempts,
    account_locked_until,
    password_hash IS NOT NULL as has_password,
    LENGTH(password_hash) as hash_length
FROM users 
WHERE email LIKE '%@medlinkpro.demo'
ORDER BY email;

-- Display success message
DO $$ 
BEGIN 
    RAISE NOTICE '🔧 Demo users fixed successfully!';
    RAISE NOTICE '✅ All accounts unlocked';
    RAISE NOTICE '✅ Passwords reset to properly hashed "Admin123!"';
    RAISE NOTICE '✅ All accounts set to active and verified';
    RAISE NOTICE '✅ Old sessions cleared';
    RAISE NOTICE '';
    RAISE NOTICE 'Ready to test login with:';
    RAISE NOTICE '👤 admin@medlinkpro.demo';
    RAISE NOTICE '👤 billing.manager@medlinkpro.demo';
    RAISE NOTICE '👤 specialist@medlinkpro.demo';
    RAISE NOTICE '👤 provider@medlinkpro.demo';
    RAISE NOTICE '🔑 Password: Admin123!';
END $$;s