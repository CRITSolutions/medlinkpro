// src/middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { UserModel } from '../models/User';
import { JwtPayload, AuthenticatedRequest, UserRole } from '../types/auth';
import { authConfig, defaultRolePermissions } from '../config/auth';
import { query } from '../config/database';

// Extend Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

// Verify JWT token and attach user to request
export const authenticateToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      res.status(401).json({
        success: false,
        message: 'Access token required'
      });
      return;
    }

    // Verify token
    const decoded = jwt.verify(token, authConfig.jwt.secret) as JwtPayload;

    // Check if session is still active
    const sessionCheck = await query(
      'SELECT id FROM user_sessions WHERE token_hash = $1 AND is_active = true AND expires_at > NOW()',
      [hashToken(token)]
    );

    if (sessionCheck.rows.length === 0) {
      res.status(401).json({
        success: false,
        message: 'Session expired or invalid'
      });
      return;
    }

    // Get fresh user data
    const user = await UserModel.findById(decoded.userId);

    if (!user) {
      res.status(401).json({
        success: false,
        message: 'User not found'
      });
      return;
    }

    // Check if user account is active
    if (user.status !== 'active') {
      res.status(401).json({
        success: false,
        message: 'Account is not active'
      });
      return;
    }

    // Check if account is locked
    if (await UserModel.isAccountLocked(user.id)) {
      res.status(401).json({
        success: false,
        message: 'Account is locked due to multiple failed login attempts'
      });
      return;
    }

    // Update session last accessed time
    await query(
      'UPDATE user_sessions SET last_accessed_at = NOW() WHERE token_hash = $1',
      [hashToken(token)]
    );

    // Attach user to request
    req.user = user;
    next();

  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
      return;
    }

    res.status(500).json({
      success: false,
      message: 'Authentication error'
    });
  }
};

// Check if user has required role
export const requireRole = (...roles: UserRole[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
      return;
    }

    if (!roles.includes(req.user.role)) {
      res.status(403).json({
        success: false,
        message: 'Insufficient permissions'
      });
      return;
    }

    next();
  };
};

// Check if user has required permission
export const requirePermission = (permission: string) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
      return;
    }

    const userPermissions = defaultRolePermissions[req.user.role as keyof typeof defaultRolePermissions] || [];
    
    if (!userPermissions.includes(permission)) {
      res.status(403).json({
        success: false,
        message: `Permission ${permission} required`
      });
      return;
    }

    next();
  };
};

// Check if user belongs to same organization or is admin
export const requireSameOrganization = () => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
      return;
    }

    // Admins can access any organization
    if (req.user.role === UserRole.ADMIN) {
      next();
      return;
    }

    // Get organization ID from request params or body
    const requestedOrgId = req.params.organizationId || req.body.organizationId;

    if (requestedOrgId && req.user.organizationId !== requestedOrgId) {
      res.status(403).json({
        success: false,
        message: 'Access denied: different organization'
      });
      return;
    }

    next();
  };
};

// Optional authentication (doesn't fail if no token)
export const optionalAuth = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      next();
      return;
    }

    const decoded = jwt.verify(token, authConfig.jwt.secret) as JwtPayload;
    const user = await UserModel.findById(decoded.userId);

    if (user && user.status === 'active') {
      req.user = user;
    }

    next();
  } catch (error) {
    // Continue without authentication if token is invalid
    next();
  }
};

// Validate API key for external integrations
export const validateApiKey = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const apiKey = req.headers['x-api-key'] as string;

    if (!apiKey) {
      res.status(401).json({
        success: false,
        message: 'API key required'
      });
      return;
    }

    // Check API key in database (you'll need to create an api_keys table)
    const apiKeyCheck = await query(
      'SELECT user_id, permissions FROM api_keys WHERE key_hash = $1 AND is_active = true AND expires_at > NOW()',
      [hashToken(apiKey)]
    );

    if (apiKeyCheck.rows.length === 0) {
      res.status(401).json({
        success: false,
        message: 'Invalid or expired API key'
      });
      return;
    }

    const apiKeyData = apiKeyCheck.rows[0];
    const user = await UserModel.findById(apiKeyData.user_id);

    if (!user) {
      res.status(401).json({
        success: false,
        message: 'API key user not found'
      });
      return;
    }

    req.user = user;
    next();

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'API key validation error'
    });
  }
};

// Rate limiting by user ID
export const rateLimitByUser = (maxRequests: number, windowMs: number) => {
  const userRequestCounts: Map<string, { count: number; resetTime: number }> = new Map();

  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      next();
      return;
    }

    const userId = req.user.id;
    const now = Date.now();
    const userLimit = userRequestCounts.get(userId);

    if (!userLimit || now > userLimit.resetTime) {
      userRequestCounts.set(userId, {
        count: 1,
        resetTime: now + windowMs
      });
      next();
      return;
    }

    if (userLimit.count >= maxRequests) {
      res.status(429).json({
        success: false,
        message: 'Too many requests. Please try again later.'
      });
      return;
    }

    userLimit.count++;
    next();
  };
};

// HIPAA audit logging middleware
export const auditLog = (action: string) => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const auditData = {
        userId: req.user?.id || null,
        action,
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.headers['user-agent'],
        success: true, // Will be updated if request fails
        additionalData: {
          path: req.path,
          method: req.method,
          params: req.params,
          // Don't log sensitive data like passwords
          body: sanitizeLogData(req.body)
        }
      };

      // Store audit data in request for later use
      req.auditData = auditData;

      // Override res.json to capture response status
      const originalJson = res.json;
      res.json = function(body: any) {
        req.auditData.success = res.statusCode < 400;
        if (res.statusCode >= 400) {
          req.auditData.errorMessage = body.message || 'Unknown error';
        }
        
        // Log to database
        logAuditEvent(req.auditData);
        
        return originalJson.call(this, body);
      };

      next();
    } catch (error) {
      next();
    }
  };
};

// Helper function to hash tokens for database storage
function hashToken(token: string): string {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Helper function to sanitize log data (remove sensitive information)
function sanitizeLogData(data: any): any {
  if (!data || typeof data !== 'object') return data;
  
  const sensitiveFields = ['password', 'currentPassword', 'newPassword', 'token', 'secret'];
  const sanitized = { ...data };
  
  for (const field of sensitiveFields) {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  }
  
  return sanitized;
}

// Helper function to log audit events
async function logAuditEvent(auditData: any): Promise<void> {
  try {
    await query(
      `INSERT INTO auth_audit_logs 
       (user_id, action, ip_address, user_agent, success, error_message, additional_data) 
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        auditData.userId,
        auditData.action,
        auditData.ipAddress,
        auditData.userAgent,
        auditData.success,
        auditData.errorMessage || null,
        JSON.stringify(auditData.additionalData)
      ]
    );
  } catch (error) {
    console.error('Failed to log audit event:', error);
  }
}

// Extend Request interface for audit data
declare global {
  namespace Express {
    interface Request {
      auditData?: any;
    }
  }
}