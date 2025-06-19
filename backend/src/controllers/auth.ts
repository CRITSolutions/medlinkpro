// src/controllers/auth.ts
import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import { z } from 'zod';

import { UserModel } from '../models/User';
import { 
  CreateUserDto, 
  LoginDto, 
  AuthResponse, 
  JwtPayload, 
  AuthenticatedRequest,
  PasswordResetRequestDto,
  PasswordResetDto,
  ChangePasswordDto,
  UserRole,
  UserStatus
} from '../types/auth';
import { authConfig } from '../config/auth';
import { query } from '../config/database';

// Validation schemas
const registerSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/\d/, 'Password must contain at least one number')
    .regex(/[!@#$%^&*(),.?":{}|<>]/, 'Password must contain at least one special character'),
  firstName: z.string().min(1, 'First name is required').max(100, 'First name too long'),
  lastName: z.string().min(1, 'Last name is required').max(100, 'Last name too long'),
  role: z.nativeEnum(UserRole),
  organizationId: z.string().uuid().optional()
});

const loginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required')
});

const passwordResetRequestSchema = z.object({
  email: z.string().email('Invalid email format')
});

const passwordResetSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  newPassword: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/\d/, 'Password must contain at least one number')
    .regex(/[!@#$%^&*(),.?":{}|<>]/, 'Password must contain at least one special character')
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/\d/, 'Password must contain at least one number')
    .regex(/[!@#$%^&*(),.?":{}|<>]/, 'Password must contain at least one special character')
});

export class AuthController {
  // Register new user
  static async register(req: Request, res: Response): Promise<void> {
    try {
      // Validate input
      const validatedData = registerSchema.parse(req.body);

      // Check if user already exists
      const existingUser = await UserModel.findByEmail(validatedData.email);
      if (existingUser) {
        res.status(400).json({
          success: false,
          message: 'User with this email already exists'
        });
        return;
      }

      // Create user
      const user = await UserModel.create(validatedData);

      // Generate tokens
      const { token, refreshToken } = await AuthController.generateTokens(user);

      // Create session
      await AuthController.createSession(user.id, token, refreshToken, req);

      // Return response (exclude sensitive data)
      const response: AuthResponse = {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          status: user.status,
          organizationId: user.organizationId,
          isEmailVerified: user.isEmailVerified,
          lastLoginAt: user.lastLoginAt,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
          hipaaTrainingCompleted: user.hipaaTrainingCompleted,
          hipaaTrainingDate: user.hipaaTrainingDate,
          passwordLastChanged: user.passwordLastChanged,
          failedLoginAttempts: user.failedLoginAttempts,
          lastFailedLoginAt: user.lastFailedLoginAt,
          accountLockedUntil: user.accountLockedUntil
        },
        token,
        expiresIn: 24 * 60 * 60 // 24 hours in seconds
      };

      res.status(201).json({
        success: true,
        message: 'User registered successfully. Please verify your email.',
        data: response
      });

    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: error.errors
        });
        return;
      }

      console.error('Registration error:', error);
      res.status(500).json({
        success: false,
        message: 'Registration failed'
      });
    }
  }

  // Login user
  static async login(req: Request, res: Response): Promise<void> {
    try {
      // Validate input
      const validatedData = loginSchema.parse(req.body);

      // Find user
      const user = await UserModel.findByEmail(validatedData.email);
      if (!user) {
        res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
        return;
      }

      // Check if account is locked
      if (await UserModel.isAccountLocked(user.id)) {
        res.status(401).json({
          success: false,
          message: 'Account is locked due to multiple failed login attempts. Please try again later.'
        });
        return;
      }

      // Verify password
      const isPasswordValid = await UserModel.verifyPassword(user, validatedData.password);
      
      if (!isPasswordValid) {
        // Update failed login attempts
        await UserModel.updateLoginInfo(user.id, false);
        
        res.status(401).json({
          success: false,
          message: 'Invalid email or password'
        });
        return;
      }

      // Check user status
      if (user.status === UserStatus.INACTIVE || user.status === UserStatus.SUSPENDED) {
        res.status(401).json({
          success: false,
          message: 'Account is not active. Please contact administrator.'
        });
        return;
      }

      // Update successful login
      await UserModel.updateLoginInfo(user.id, true);

      // Generate tokens
      const { token, refreshToken } = await AuthController.generateTokens(user);

      // Create session
      await AuthController.createSession(user.id, token, refreshToken, req);

      // Return response
      const response: AuthResponse = {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          status: user.status,
          organizationId: user.organizationId,
          isEmailVerified: user.isEmailVerified,
          lastLoginAt: user.lastLoginAt,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
          hipaaTrainingCompleted: user.hipaaTrainingCompleted,
          hipaaTrainingDate: user.hipaaTrainingDate,
          passwordLastChanged: user.passwordLastChanged,
          failedLoginAttempts: user.failedLoginAttempts,
          lastFailedLoginAt: user.lastFailedLoginAt,
          accountLockedUntil: user.accountLockedUntil
        },
        token,
        expiresIn: 24 * 60 * 60 // 24 hours in seconds
      };

      res.json({
        success: true,
        message: 'Login successful',
        data: response
      });

    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: error.errors
        });
        return;
      }

      console.error('Login error:', error);
      res.status(500).json({
        success: false,
        message: 'Login failed'
      });
    }
  }

  // Logout user
  static async logout(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const authHeader = req.headers.authorization;
      const token = authHeader && authHeader.split(' ')[1];

      if (token) {
        // Invalidate session
        await query(
          'UPDATE user_sessions SET is_active = false WHERE token_hash = $1',
          [AuthController.hashToken(token)]
        );
      }

      res.json({
        success: true,
        message: 'Logout successful'
      });

    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        success: false,
        message: 'Logout failed'
      });
    }
  }

  // Get current user profile
  static async getProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated'
        });
        return;
      }

      res.json({
        success: true,
        data: {
          id: req.user.id,
          email: req.user.email,
          firstName: req.user.firstName,
          lastName: req.user.lastName,
          role: req.user.role,
          status: req.user.status,
          organizationId: req.user.organizationId,
          isEmailVerified: req.user.isEmailVerified,
          lastLoginAt: req.user.lastLoginAt,
          createdAt: req.user.createdAt,
          updatedAt: req.user.updatedAt,
          hipaaTrainingCompleted: req.user.hipaaTrainingCompleted,
          hipaaTrainingDate: req.user.hipaaTrainingDate,
          passwordLastChanged: req.user.passwordLastChanged
        }
      });

    } catch (error) {
      console.error('Get profile error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to get profile'
      });
    }
  }

  // Request password reset
  static async requestPasswordReset(req: Request, res: Response): Promise<void> {
    try {
      const validatedData = passwordResetRequestSchema.parse(req.body);

      const user = await UserModel.findByEmail(validatedData.email);
      if (!user) {
        // Don't reveal if user exists or not
        res.json({
          success: true,
          message: 'If the email exists, a password reset link has been sent.'
        });
        return;
      }

      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      await UserModel.setPasswordResetToken(user.id, resetToken);

      // TODO: Send email with reset link
      // For now, just return success (in production, send email)

      res.json({
        success: true,
        message: 'If the email exists, a password reset link has been sent.',
        // Include token in response for testing (remove in production)
        ...(process.env.NODE_ENV === 'development' && { resetToken })
      });

    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: error.errors
        });
        return;
      }

      console.error('Password reset request error:', error);
      res.status(500).json({
        success: false,
        message: 'Password reset request failed'
      });
    }
  }

  // Reset password with token
  static async resetPassword(req: Request, res: Response): Promise<void> {
    try {
      const validatedData = passwordResetSchema.parse(req.body);

      const user = await UserModel.findByPasswordResetToken(validatedData.token);
      if (!user) {
        res.status(400).json({
          success: false,
          message: 'Invalid or expired reset token'
        });
        return;
      }

      // Update password
      await UserModel.updatePassword(user.id, validatedData.newPassword);

      // Invalidate all existing sessions
      await query(
        'UPDATE user_sessions SET is_active = false WHERE user_id = $1',
        [user.id]
      );

      res.json({
        success: true,
        message: 'Password reset successful. Please login with your new password.'
      });

    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: error.errors
        });
        return;
      }

      console.error('Password reset error:', error);
      res.status(500).json({
        success: false,
        message: 'Password reset failed'
      });
    }
  }

  // Change password (authenticated user)
  static async changePassword(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated'
        });
        return;
      }

      const validatedData = changePasswordSchema.parse(req.body);

      // Verify current password
      const isCurrentPasswordValid = await UserModel.verifyPassword(req.user, validatedData.currentPassword);
      if (!isCurrentPasswordValid) {
        res.status(400).json({
          success: false,
          message: 'Current password is incorrect'
        });
        return;
      }

      // Update password
      await UserModel.updatePassword(req.user.id, validatedData.newPassword);

      // Invalidate all existing sessions except current
      const authHeader = req.headers.authorization;
      const currentToken = authHeader && authHeader.split(' ')[1];
      const currentTokenHash = currentToken ? AuthController.hashToken(currentToken) : null;

      await query(
        'UPDATE user_sessions SET is_active = false WHERE user_id = $1 AND token_hash != $2',
        [req.user.id, currentTokenHash]
      );

      res.json({
        success: true,
        message: 'Password changed successfully'
      });

    } catch (error) {
      if (error instanceof z.ZodError) {
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors: error.errors
        });
        return;
      }

      console.error('Change password error:', error);
      res.status(500).json({
        success: false,
        message: 'Password change failed'
      });
    }
  }

  // Verify email
  static async verifyEmail(req: Request, res: Response): Promise<void> {
    try {
      const { token } = req.params;

      if (!token) {
        res.status(400).json({
          success: false,
          message: 'Verification token is required'
        });
        return;
      }

      const user = await UserModel.verifyEmail(token);
      if (!user) {
        res.status(400).json({
          success: false,
          message: 'Invalid or expired verification token'
        });
        return;
      }

      res.json({
        success: true,
        message: 'Email verified successfully',
        data: {
          id: user.id,
          email: user.email,
          isEmailVerified: user.isEmailVerified,
          status: user.status
        }
      });

    } catch (error) {
      console.error('Email verification error:', error);
      res.status(500).json({
        success: false,
        message: 'Email verification failed'
      });
    }
  }

  // Refresh token
  static async refreshToken(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        res.status(401).json({
          success: false,
          message: 'Refresh token is required'
        });
        return;
      }

      // Verify refresh token
      const decoded = jwt.verify(refreshToken, authConfig.jwt.secret) as JwtPayload;

      // Check if session exists and is active
      const sessionCheck = await query(
        'SELECT user_id FROM user_sessions WHERE refresh_token_hash = $1 AND is_active = true AND expires_at > NOW()',
        [AuthController.hashToken(refreshToken)]
      );

      if (sessionCheck.rows.length === 0) {
        res.status(401).json({
          success: false,
          message: 'Invalid or expired refresh token'
        });
        return;
      }

      const user = await UserModel.findById(decoded.userId);
      if (!user || user.status !== UserStatus.ACTIVE) {
        res.status(401).json({
          success: false,
          message: 'User not found or inactive'
        });
        return;
      }

      // Generate new tokens
      const { token: newToken, refreshToken: newRefreshToken } = await AuthController.generateTokens(user);

      // Update session with new tokens
      await query(
        `UPDATE user_sessions 
         SET token_hash = $1, refresh_token_hash = $2, last_accessed_at = NOW()
         WHERE refresh_token_hash = $3`,
        [
          AuthController.hashToken(newToken),
          AuthController.hashToken(newRefreshToken),
          AuthController.hashToken(refreshToken)
        ]
      );

      res.json({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          token: newToken,
          refreshToken: newRefreshToken,
          expiresIn: 24 * 60 * 60 // 24 hours
        }
      });

    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        res.status(401).json({
          success: false,
          message: 'Invalid refresh token'
        });
        return;
      }

      console.error('Refresh token error:', error);
      res.status(500).json({
        success: false,
        message: 'Token refresh failed'
      });
    }
  }

  // Get all active sessions for current user
  static async getSessions(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated'
        });
        return;
      }

      const sessions = await query(
        `SELECT id, ip_address, user_agent, created_at, last_accessed_at, expires_at
         FROM user_sessions 
         WHERE user_id = $1 AND is_active = true AND expires_at > NOW()
         ORDER BY last_accessed_at DESC`,
        [req.user.id]
      );

      res.json({
        success: true,
        data: sessions.rows
      });

    } catch (error) {
      console.error('Get sessions error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to get sessions'
      });
    }
  }

  // Revoke a specific session
  static async revokeSession(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated'
        });
        return;
      }

      const { sessionId } = req.params;

      const result = await query(
        'UPDATE user_sessions SET is_active = false WHERE id = $1 AND user_id = $2',
        [sessionId, req.user.id]
      );

      if (result.rowCount === 0) {
        res.status(404).json({
          success: false,
          message: 'Session not found'
        });
        return;
      }

      res.json({
        success: true,
        message: 'Session revoked successfully'
      });

    } catch (error) {
      console.error('Revoke session error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to revoke session'
      });
    }
  }

  // Revoke all sessions except current
  static async revokeAllSessions(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          success: false,
          message: 'User not authenticated'
        });
        return;
      }

      const authHeader = req.headers.authorization;
      const currentToken = authHeader && authHeader.split(' ')[1];
      const currentTokenHash = currentToken ? AuthController.hashToken(currentToken) : null;

      await query(
        'UPDATE user_sessions SET is_active = false WHERE user_id = $1 AND token_hash != $2',
        [req.user.id, currentTokenHash]
      );

      res.json({
        success: true,
        message: 'All other sessions revoked successfully'
      });

    } catch (error) {
      console.error('Revoke all sessions error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to revoke sessions'
      });
    }
  }

  // Helper method to generate JWT tokens
  private static async generateTokens(user: any): Promise<{ token: string; refreshToken: string }> {
    const payload: JwtPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organizationId
    };

    const token = jwt.sign(payload, authConfig.jwt.secret as string, {
      expiresIn: authConfig.jwt.expiresIn
    });

    const refreshToken = jwt.sign(payload, authConfig.jwt.secret as string, {
      expiresIn: authConfig.jwt.refreshExpiresIn
    });

    return { token, refreshToken };
  }

  // Helper method to create user session
  private static async createSession(
    userId: string, 
    token: string, 
    refreshToken: string, 
    req: Request
  ): Promise<void> {
    const sessionData = {
      id: uuidv4(),
      userId,
      tokenHash: AuthController.hashToken(token),
      refreshTokenHash: AuthController.hashToken(refreshToken),
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
    };

    await query(
      `INSERT INTO user_sessions 
       (id, user_id, token_hash, refresh_token_hash, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        sessionData.id,
        sessionData.userId,
        sessionData.tokenHash,
        sessionData.refreshTokenHash,
        sessionData.ipAddress,
        sessionData.userAgent,
        sessionData.expiresAt
      ]
    );
  }

  // Helper method to hash tokens
  private static hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}