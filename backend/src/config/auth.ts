// src/config/auth.ts
import { AuthConfig } from '../types/auth';

export const authConfig: AuthConfig = {
  jwt: {
    secret: process.env.JWT_SECRET || 'fallback_secret_never_use_in_production',
    expiresIn: '24h', // Access token expires in 24 hours
    refreshExpiresIn: '7d', // Refresh token expires in 7 days
  },
  
  password: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    saltRounds: 12, // Higher for better security
  },
  
  security: {
    maxFailedAttempts: 5, // Lock account after 5 failed attempts
    lockoutDuration: 30, // Lock for 30 minutes
    sessionTimeout: 480, // 8 hours in minutes
    requireTwoFactor: false, // Can be enabled for high-security environments
  },
  
  hipaa: {
    passwordExpiration: 90, // Force password change every 90 days
    sessionLogging: true, // Log all authentication events
    auditRetention: 2555, // 7 years in days (HIPAA requirement)
  },
};

// Validate auth configuration
export const validateAuthConfig = (): void => {
  const requiredVars = ['JWT_SECRET', 'PHI_ENCRYPTION_KEY'];
  const missing = requiredVars.filter(varName => !process.env[varName]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
  
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }
  
  if (process.env.PHI_ENCRYPTION_KEY && process.env.PHI_ENCRYPTION_KEY.length < 32) {
    throw new Error('PHI_ENCRYPTION_KEY must be at least 32 characters long');
  }
};

// Default permissions for each role
export const defaultRolePermissions = {
  admin: [
    'users:create', 'users:read', 'users:update', 'users:delete',
    'organizations:create', 'organizations:read', 'organizations:update', 'organizations:delete',
    'patients:create', 'patients:read', 'patients:update', 'patients:delete',
    'claims:create', 'claims:read', 'claims:update', 'claims:delete',
    'payments:create', 'payments:read', 'payments:update', 'payments:delete',
    'reports:read', 'settings:update', 'audit:read'
  ],
  
  billing_manager: [
    'patients:create', 'patients:read', 'patients:update',
    'claims:create', 'claims:read', 'claims:update', 'claims:delete',
    'payments:create', 'payments:read', 'payments:update',
    'reports:read', 'users:read'
  ],
  
  medical_coder: [
    'patients:read', 'patients:update',
    'claims:create', 'claims:read', 'claims:update',
    'reports:read'
  ],
  
  provider: [
    'patients:create', 'patients:read', 'patients:update',
    'claims:read', 'reports:read'
  ],
  
  staff: [
    'patients:create', 'patients:read', 'patients:update',
    'claims:read', 'reports:read'
  ],
  
  readonly: [
    'patients:read', 'claims:read', 'reports:read'
  ]
};

export default authConfig;