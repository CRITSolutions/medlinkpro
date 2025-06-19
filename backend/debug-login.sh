#!/bin/bash

echo "🔍 Debugging MedLinkPro Authentication System"
echo "=============================================="

echo ""
echo "1. Testing server health..."
curl -s http://localhost:3001/health | jq '.' || echo "❌ Health check failed"

echo ""
echo "2. Checking demo users in database..."
docker exec -i medlinkpro_postgres psql -U postgres -d medlinkpro -c "
SELECT 
    email, 
    first_name, 
    last_name, 
    role, 
    status, 
    is_email_verified,
    password_hash IS NOT NULL as has_password
FROM users 
WHERE email LIKE '%@medlinkpro.demo' 
ORDER BY email;
"

echo ""
echo "3. Testing login with verbose output..."
echo "Request payload: {\"email\":\"admin@medlinkpro.demo\",\"password\":\"Admin123!\"}"
echo ""
echo "Response:"
curl -X POST http://localhost:3001/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@medlinkpro.demo","password":"Admin123!"}' \
  -w "\nHTTP Status: %{http_code}\nResponse Time: %{time_total}s\n" \
  -v

echo ""
echo "4. Checking recent audit logs..."
docker exec -i medlinkpro_postgres psql -U postgres -d medlinkpro -c "
SELECT 
    action, 
    success, 
    error_message, 
    ip_address,
    created_at
FROM auth_audit_logs 
ORDER BY created_at DESC 
LIMIT 5;
"

echo ""
echo "5. Testing with different user..."
echo "Testing billing.manager@medlinkpro.demo..."
curl -X POST http://localhost:3001/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"billing.manager@medlinkpro.demo","password":"Admin123!"}' \
  -s | jq '.' || echo "❌ JSON parse failed"

echo ""
echo "🔍 Debug complete! Check the output above for issues."