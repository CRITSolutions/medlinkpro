// src/routes/auth.ts
import { Router } from 'express';
import { AuthController } from '../controllers/auth';
import { authenticateToken, requireRole, auditLog, rateLimitByUser } from '../middleware/auth';
import { UserRole } from '../types/auth';

const router = Router();

// Public routes (no authentication required)

/**
 * @route   POST /api/v1/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', 
  auditLog('USER_REGISTER'),
  AuthController.register
);

/**
 * @route   POST /api/v1/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', 
  auditLog('USER_LOGIN'),
  AuthController.login
);

/**
 * @route   POST /api/v1/auth/forgot-password
 * @desc    Request password reset
 * @access  Public
 */
router.post('/forgot-password', 
  auditLog('PASSWORD_RESET_REQUEST'),
  AuthController.requestPasswordReset
);

/**
 * @route   POST /api/v1/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 */
router.post('/reset-password', 
  auditLog('PASSWORD_RESET'),
  AuthController.resetPassword
);

/**
 * @route   GET /api/v1/auth/verify-email/:token
 * @desc    Verify email address
 * @access  Public
 */
router.get('/verify-email/:token', 
  auditLog('EMAIL_VERIFICATION'),
  AuthController.verifyEmail
);

/**
 * @route   POST /api/v1/auth/refresh-token
 * @desc    Refresh access token
 * @access  Public
 */
router.post('/refresh-token', 
  auditLog('TOKEN_REFRESH'),
  AuthController.refreshToken
);

// Protected routes (authentication required)

/**
 * @route   POST /api/v1/auth/logout
 * @desc    Logout user
 * @access  Private
 */
router.post('/logout', 
  authenticateToken,
  auditLog('USER_LOGOUT'),
  AuthController.logout
);

/**
 * @route   GET /api/v1/auth/profile
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/profile', 
  authenticateToken,
  auditLog('PROFILE_VIEW'),
  AuthController.getProfile
);

/**
 * @route   POST /api/v1/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.post('/change-password', 
  authenticateToken,
  auditLog('PASSWORD_CHANGE'),
  rateLimitByUser(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
  AuthController.changePassword
);

/**
 * @route   GET /api/v1/auth/sessions
 * @desc    Get all active sessions for current user
 * @access  Private
 */
router.get('/sessions', 
  authenticateToken,
  auditLog('SESSIONS_VIEW'),
  AuthController.getSessions
);

/**
 * @route   DELETE /api/v1/auth/sessions/:sessionId
 * @desc    Revoke a specific session
 * @access  Private
 */
router.delete('/sessions/:sessionId', 
  authenticateToken,
  auditLog('SESSION_REVOKE'),
  AuthController.revokeSession
);

/**
 * @route   DELETE /api/v1/auth/sessions
 * @desc    Revoke all sessions except current
 * @access  Private
 */
router.delete('/sessions', 
  authenticateToken,
  auditLog('ALL_SESSIONS_REVOKE'),
  AuthController.revokeAllSessions
);

// Admin-only routes

/**
 * @route   GET /api/v1/auth/users
 * @desc    Get all users (admin only)
 * @access  Private (Admin)
 */
router.get('/users', 
  authenticateToken,
  requireRole(UserRole.ADMIN),
  auditLog('USERS_LIST'),
  async (req, res) => {
    // This will be implemented when we create the UserController
    res.status(501).json({
      success: false,
      message: 'User management endpoints coming soon'
    });
  }
);

/**
 * @route   PUT /api/v1/auth/users/:userId/status
 * @desc    Update user status (admin only)
 * @access  Private (Admin)
 */
router.put('/users/:userId/status', 
  authenticateToken,
  requireRole(UserRole.ADMIN),
  auditLog('USER_STATUS_UPDATE'),
  async (req, res) => {
    // This will be implemented when we create the UserController
    res.status(501).json({
      success: false,
      message: 'User management endpoints coming soon'
    });
  }
);

/**
 * @route   GET /api/v1/auth/audit-logs
 * @desc    Get authentication audit logs (admin only)
 * @access  Private (Admin)
 */
router.get('/audit-logs', 
  authenticateToken,
  requireRole(UserRole.ADMIN),
  auditLog('AUDIT_LOGS_VIEW'),
  async (req, res) => {
    try {
      const { page = 1, limit = 50, userId, action, startDate, endDate } = req.query;
      
      let whereConditions = [];
      let queryParams = [];
      let paramCounter = 1;

      // Build dynamic WHERE clause
      if (userId) {
        whereConditions.push(`user_id = $${paramCounter}`);
        queryParams.push(userId);
        paramCounter++;
      }

      if (action) {
        whereConditions.push(`action = $${paramCounter}`);
        queryParams.push(action);
        paramCounter++;
      }

      if (startDate) {
        whereConditions.push(`timestamp >= $${paramCounter}`);
        queryParams.push(startDate);
        paramCounter++;
      }

      if (endDate) {
        whereConditions.push(`timestamp <= $${paramCounter}`);
        queryParams.push(endDate);
        paramCounter++;
      }

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';
      const offset = (Number(page) - 1) * Number(limit);

      queryParams.push(Number(limit), offset);

      const { query } = require('../config/database');
      
      const auditLogsQuery = `
        SELECT 
          al.*,
          u.email as user_email,
          u.first_name,
          u.last_name
        FROM auth_audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ${whereClause}
        ORDER BY al.timestamp DESC
        LIMIT $${paramCounter} OFFSET $${paramCounter + 1}
      `;

      const countQuery = `
        SELECT COUNT(*) as total FROM auth_audit_logs al ${whereClause}
      `;

      const [logsResult, countResult] = await Promise.all([
        query(auditLogsQuery, queryParams),
        query(countQuery, queryParams.slice(0, -2)) // Remove limit and offset for count
      ]);

      res.json({
        success: true,
        data: {
          logs: logsResult.rows,
          pagination: {
            page: Number(page),
            limit: Number(limit),
            total: Number(countResult.rows[0].total),
            totalPages: Math.ceil(Number(countResult.rows[0].total) / Number(limit))
          }
        }
      });

    } catch (error) {
      console.error('Audit logs error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve audit logs'
      });
    }
  }
);

// Health check for auth service
/**
 * @route   GET /api/v1/auth/health
 * @desc    Auth service health check
 * @access  Public
 */
router.get('/health', async (req, res) => {
  try {
    const { healthCheck } = require('../config/database');
    const dbHealth = await healthCheck();
    
    res.json({
      success: true,
      message: 'Auth service is healthy',
      data: {
        service: 'auth',
        status: 'healthy',
        timestamp: new Date().toISOString(),
        database: dbHealth
      }
    });
  } catch (error) {
    res.status(503).json({
      success: false,
      message: 'Auth service is unhealthy',
      data: {
        service: 'auth',
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    });
  }
});

export default router;