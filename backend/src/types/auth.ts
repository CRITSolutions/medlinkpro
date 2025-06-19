// src/types/auth.ts
import { Request } from 'express';

// User roles for RBAC
export enum UserRole {
  ADMIN = 'admin',
  BILLING_MANAGER = 'billing_manager',
  MEDICAL_CODER = 'medical_coder',
  PROVIDER = 'provider',
  STAFF = 'staff',
  READONLY = 'readonly'
}

// User status
export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended',
  PENDING_VERIFICATION = 'pending_verification'
}

// Base user interface
export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  status: UserStatus;
  organizationId: string | null;
  isEmailVerified: boolean;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  // HIPAA tracking
  hipaaTrainingCompleted: boolean;
  hipaaTrainingDate: Date | null;
  passwordLastChanged: Date;
  failedLoginAttempts: number;
  lastFailedLoginAt: Date | null;
  accountLockedUntil: Date | null;
}

// User creation interface (for registration)
export interface CreateUserDto {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  organizationId: string | null;
}

// User login interface
export interface LoginDto {
  email: string;
  password: string;
}

// JWT payload interface
export interface JwtPayload {
  userId: string;
  email: string;
  role: UserRole;
  organizationId: string | null;
  iat?: number;
  exp?: number;
}

// Auth response interface
export interface AuthResponse {
  user: Omit<User, 'passwordHash'>;
  token: string;
  expiresIn: number;
}

// Password reset interfaces
export interface PasswordResetRequestDto {
  email: string;
}

export interface PasswordResetDto {
  token: string;
  newPassword: string;
}

// Change password interface
export interface ChangePasswordDto {
  currentPassword: string;
  newPassword: string;
}

// Extended Request interface with user
export interface AuthenticatedRequest extends Request {
  user?: User;
}

// Refresh token interface
export interface RefreshTokenDto {
  refreshToken: string;
}

// Two-factor authentication interfaces
export interface TwoFactorSetupDto {
  secret: string;
  qrCode: string;
}

export interface TwoFactorVerifyDto {
  token: string;
  code: string;
}

// Session interface for tracking user sessions
export interface UserSession {
  id: string;
  userId: string;
  token: string;
  refreshToken: string;
  ipAddress: string;
  userAgent: string;
  isActive: boolean;
  expiresAt: Date;
  createdAt: Date;
  lastAccessedAt: Date;
}

// Audit log interface for HIPAA compliance
export interface AuthAuditLog {
  id: string;
  userId?: string;
  action: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  errorMessage?: string;
  timestamp: Date;
  additionalData?: Record<string, any>;
}

// Permission interface for granular access control
export interface Permission {
  id: string;
  name: string;
  description: string;
  resource: string;
  action: string;
}

// Role permissions mapping
export interface RolePermission {
  role: UserRole;
  permissions: Permission[];
}

// Auth configuration interface
export interface AuthConfig {
  jwt: {
    secret: string;
    expiresIn: string;
    refreshExpiresIn: string;
  };
  password: {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
    saltRounds: number;
  };
  security: {
    maxFailedAttempts: number;
    lockoutDuration: number; // in minutes
    sessionTimeout: number; // in minutes
    requireTwoFactor: boolean;
  };
  hipaa: {
    passwordExpiration: number; // in days
    sessionLogging: boolean;
    auditRetention: number; // in days
  };
}