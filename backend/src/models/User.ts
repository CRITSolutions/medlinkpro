// src/models/User.ts
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { query, transaction } from '../config/database';
import { User, CreateUserDto, UserRole, UserStatus } from '../types/auth';
import { authConfig } from '../config/auth';

export class UserModel {
  // Create a new user
  static async create(userData: CreateUserDto): Promise<User> {
    const { email, password, firstName, lastName, role, organizationId } = userData;
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, authConfig.password.saltRounds);
    
    // Generate email verification token
    const emailVerificationToken = uuidv4();
    
    const createUserQuery = `
      INSERT INTO users (
        email, password_hash, first_name, last_name, role, 
        organization_id, email_verification_token, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING 
        id, email, first_name, last_name, role, status,
        organization_id, is_email_verified, last_login_at,
        hipaa_training_completed, hipaa_training_date, password_last_changed,
        failed_login_attempts, last_failed_login_at, account_locked_until,
        created_at, updated_at
    `;
    
    const values = [
      email.toLowerCase(),
      passwordHash,
      firstName,
      lastName,
      role,
      organizationId || null,
      emailVerificationToken,
      UserStatus.PENDING_VERIFICATION
    ];
    
    try {
      const result = await query(createUserQuery, values);
      return this.mapRowToUser(result.rows[0]);
    } catch (error: any) {
      if (error.code === '23505') { // Unique violation
        throw new Error('User with this email already exists');
      }
      throw error;
    }
  }

  // Find user by email
  static async findByEmail(email: string): Promise<User | null> {
    const findUserQuery = `
      SELECT 
        id, email, password_hash, first_name, last_name, role, status,
        organization_id, is_email_verified, last_login_at,
        hipaa_training_completed, hipaa_training_date, password_last_changed,
        failed_login_attempts, last_failed_login_at, account_locked_until,
        created_at, updated_at
      FROM users 
      WHERE email = $1
    `;
    
    const result = await query(findUserQuery, [email.toLowerCase()]);
    
    if (result.rows.length === 0) {
      return null;
    }
    
    return this.mapRowToUser(result.rows[0]);
  }

  // Find user by ID
  static async findById(id: string): Promise<User | null> {
    const findUserQuery = `
      SELECT 
        id, email, first_name, last_name, role, status,
        organization_id, is_email_verified, last_login_at,
        hipaa_training_completed, hipaa_training_date, password_last_changed,
        failed_login_attempts, last_failed_login_at, account_locked_until,
        created_at, updated_at
      FROM users 
      WHERE id = $1
    `;
    
    const result = await query(findUserQuery, [id]);
    
    if (result.rows.length === 0) {
      return null;
    }
    
    return this.mapRowToUser(result.rows[0]);
  }

  // Verify password
  static async verifyPassword(user: User, password: string): Promise<boolean> {
    const getUserPasswordQuery = `
      SELECT password_hash FROM users WHERE id = $1
    `;
    
    const result = await query(getUserPasswordQuery, [user.id]);
    
    if (result.rows.length === 0) {
      return false;
    }
    
    return await bcrypt.compare(password, result.rows[0].password_hash);
  }

  // Update user login information
  static async updateLoginInfo(userId: string, success: boolean): Promise<void> {
    if (success) {
      const updateQuery = `
        UPDATE users 
        SET 
          last_login_at = NOW(),
          failed_login_attempts = 0,
          last_failed_login_at = NULL,
          account_locked_until = NULL
        WHERE id = $1
      `;
      await query(updateQuery, [userId]);
    } else {
      const updateQuery = `
        UPDATE users 
        SET 
          failed_login_attempts = failed_login_attempts + 1,
          last_failed_login_at = NOW(),
          account_locked_until = CASE 
            WHEN failed_login_attempts + 1 >= $2 
            THEN NOW() + INTERVAL '${authConfig.security.lockoutDuration} minutes'
            ELSE account_locked_until
          END
        WHERE id = $1
      `;
      await query(updateQuery, [userId, authConfig.security.maxFailedAttempts]);
    }
  }

  // Check if account is locked
  static async isAccountLocked(userId: string): Promise<boolean> {
    const checkLockQuery = `
      SELECT account_locked_until 
      FROM users 
      WHERE id = $1 AND account_locked_until > NOW()
    `;
    
    const result = await query(checkLockQuery, [userId]);
    return result.rows.length > 0;
  }

  // Update password
  static async updatePassword(userId: string, newPassword: string): Promise<void> {
    const passwordHash = await bcrypt.hash(newPassword, authConfig.password.saltRounds);
    
    const updateQuery = `
      UPDATE users 
      SET 
        password_hash = $1,
        password_last_changed = NOW(),
        password_reset_token = NULL,
        password_reset_expires = NULL
      WHERE id = $2
    `;
    
    await query(updateQuery, [passwordHash, userId]);
  }

  // Set password reset token
  static async setPasswordResetToken(userId: string, token: string): Promise<void> {
    const updateQuery = `
      UPDATE users 
      SET 
        password_reset_token = $1,
        password_reset_expires = NOW() + INTERVAL '1 hour'
      WHERE id = $2
    `;
    
    await query(updateQuery, [token, userId]);
  }

  // Find user by password reset token
  static async findByPasswordResetToken(token: string): Promise<User | null> {
    const findUserQuery = `
      SELECT 
        id, email, first_name, last_name, role, status,
        organization_id, is_email_verified, last_login_at,
        hipaa_training_completed, hipaa_training_date, password_last_changed,
        failed_login_attempts, last_failed_login_at, account_locked_until,
        created_at, updated_at
      FROM users 
      WHERE password_reset_token = $1 AND password_reset_expires > NOW()
    `;
    
    const result = await query(findUserQuery, [token]);
    
    if (result.rows.length === 0) {
      return null;
    }
    
    return this.mapRowToUser(result.rows[0]);
  }

  // Verify email
  static async verifyEmail(token: string): Promise<User | null> {
    const verifyQuery = `
      UPDATE users 
      SET 
        is_email_verified = true,
        email_verification_token = NULL,
        status = $2
      WHERE email_verification_token = $1
      RETURNING 
        id, email, first_name, last_name, role, status,
        organization_id, is_email_verified, last_login_at,
        hipaa_training_completed, hipaa_training_date, password_last_changed,
        failed_login_attempts, last_failed_login_at, account_locked_until,
        created_at, updated_at
    `;
    
    const result = await query(verifyQuery, [token, UserStatus.ACTIVE]);
    
    if (result.rows.length === 0) {
      return null;
    }
    
    return this.mapRowToUser(result.rows[0]);
  }

  // Update user profile
  static async updateProfile(userId: string, updates: Partial<User>): Promise<User | null> {
    const allowedFields = ['first_name', 'last_name', 'role', 'status'];
    const updateFields: string[] = [];
    const values: any[] = [];
    let paramCounter = 1;

    Object.entries(updates).forEach(([key, value]) => {
      const dbField = key.replace(/([A-Z])/g, '_$1').toLowerCase();
      if (allowedFields.includes(dbField) && value !== undefined) {
        updateFields.push(`${dbField} = $${paramCounter}`);
        values.push(value);
        paramCounter++;
      }
    });

    if (updateFields.length === 0) {
      throw new Error('No valid fields to update');
    }

    values.push(userId);

    const updateQuery = `
      UPDATE users 
      SET ${updateFields.join(', ')}, updated_at = NOW()
      WHERE id = $${paramCounter}
      RETURNING 
        id, email, first_name, last_name, role, status,
        organization_id, is_email_verified, last_login_at,
        hipaa_training_completed, hipaa_training_date, password_last_changed,
        failed_login_attempts, last_failed_login_at, account_locked_until,
        created_at, updated_at
    `;

    const result = await query(updateQuery, values);
    
    if (result.rows.length === 0) {
      return null;
    }
    
    return this.mapRowToUser(result.rows[0]);
  }

  // Get all users (with pagination)
  static async findAll(page: number = 1, limit: number = 10, organizationId?: string): Promise<{ users: User[], total: number }> {
    const offset = (page - 1) * limit;
    
    let whereClause = '';
    let countWhereClause = '';
    const queryParams: any[] = [limit, offset];
    const countParams: any[] = [];
    
    if (organizationId) {
      whereClause = 'WHERE organization_id = $3';
      countWhereClause = 'WHERE organization_id = $1';
      queryParams.push(organizationId);
      countParams.push(organizationId);
    }
    
    const usersQuery = `
      SELECT 
        id, email, first_name, last_name, role, status,
        organization_id, is_email_verified, last_login_at,
        hipaa_training_completed, hipaa_training_date, password_last_changed,
        failed_login_attempts, last_failed_login_at, account_locked_until,
        created_at, updated_at
      FROM users 
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT $1 OFFSET $2
    `;
    
    const countQuery = `
      SELECT COUNT(*) as total FROM users ${countWhereClause}
    `;
    
    const [usersResult, countResult] = await Promise.all([
      query(usersQuery, queryParams),
      query(countQuery, countParams)
    ]);
    
    const users = usersResult.rows.map(row => this.mapRowToUser(row));
    const total = parseInt(countResult.rows[0].total, 10);
    
    return { users, total };
  }

  // Delete user (soft delete by updating status)
  static async delete(userId: string): Promise<boolean> {
    const deleteQuery = `
      UPDATE users 
      SET status = 'inactive', updated_at = NOW()
      WHERE id = $1
    `;
    
    const result = await query(deleteQuery, [userId]);
    return result.rowCount > 0;
  }

  // Helper method to map database row to User object
  private static mapRowToUser(row: any): User {
    return {
      id: row.id,
      email: row.email,
      firstName: row.first_name,
      lastName: row.last_name,
      role: row.role as UserRole,
      status: row.status as UserStatus,
      organizationId: row.organization_id,
      isEmailVerified: row.is_email_verified,
      lastLoginAt: row.last_login_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      hipaaTrainingCompleted: row.hipaa_training_completed,
      hipaaTrainingDate: row.hipaa_training_date,
      passwordLastChanged: row.password_last_changed,
      failedLoginAttempts: row.failed_login_attempts,
      lastFailedLoginAt: row.last_failed_login_at,
      accountLockedUntil: row.account_locked_until,
    };
  }
}