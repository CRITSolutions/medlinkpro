// src/config/database.ts - Clean database configuration
import { Pool } from 'pg';
import { logger } from '../utils/logger';

// Simple database config
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'medlinkpro',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'password',
  ssl: process.env.DB_SSL === 'true',
  max: 10, // max number of clients in the pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 30000,
};

// Create connection pool
const pool = new Pool(dbConfig);

// Handle pool errors
pool.on('error', (err) => {
  logger.error('Database pool error:', err);
});

// Test database connection
export const testConnection = async (): Promise<boolean> => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT NOW() as current_time');
    client.release();
    
    logger.info('✅ Database connection successful');
    logger.info(`Database time: ${result.rows[0].current_time}`);
    
    return true;
  } catch (error) {
    logger.error('❌ Database connection failed:', error);
    return false;
  }
};

// Simple query function
export const query = async (text: string, params?: any[]): Promise<any> => {
  try {
    const start = Date.now();
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    
    logger.debug(`Query executed in ${duration}ms`);
    return result;
  } catch (error) {
    logger.error('Query error:', error);
    throw error;
  }
};

// Close connections
export const closeConnections = async (): Promise<void> => {
  try {
    await pool.end();
    logger.info('Database connections closed');
  } catch (error) {
    logger.error('Error closing database connections:', error);
  }
};

// Validate database config
export const validateDatabaseConfig = (): void => {
  if (!dbConfig.host || !dbConfig.database || !dbConfig.user) {
    throw new Error('Missing required database configuration');
  }
  
  logger.info('✅ Database configuration validated');
};