import { Pool, PoolConfig } from 'pg';
import { logger } from '../logging';

interface DatabaseConfig extends PoolConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  ssl?: boolean | object;
  max: number;
  idleTimeoutMillis: number;
  connectionTimeoutMillis: number;
}

const dbConfig: DatabaseConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME || 'medlinkpro',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || '',
  
  // Connection pool settings
  max: 20, // Maximum number of connections
  idleTimeoutMillis: 30000, // Close idle connections after 30 seconds
  connectionTimeoutMillis: 2000, // Return an error after 2 seconds if connection could not be established
  
  // SSL configuration for production
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false, // Set to true in production with proper certificates
  } : false,
};

// Create connection pool
export const pool = new Pool(dbConfig);

// Handle pool errors
pool.on('error', (err: Error) => {
  logger.error('Unexpected error on idle client', err);
  process.exit(-1);
});

// Handle pool connection
pool.on('connect', () => {
  logger.debug('Connected to PostgreSQL database');
});

// Test database connection
export const testConnection = async (): Promise<boolean> => {
  try {
    const client = await pool.connect();
    const result = await client.query('SELECT NOW()');
    client.release();
    
    logger.info('Database connection successful', {
      timestamp: result.rows[0].now,
      host: dbConfig.host,
      database: dbConfig.database,
    });
    
    return true;
  } catch (error) {
    logger.error('Database connection failed', error);
    return false;
  }
};

// Set application context for Row Level Security
export const setAppContext = async (userId?: string, orgId?: string): Promise<void> => {
  const client = await pool.connect();
  
  try {
    if (userId) {
      await client.query('SET app.current_user_id = $1', [userId]);
    }
    if (orgId) {
      await client.query('SET app.current_org_id = $1', [orgId]);
    }
  } finally {
    client.release();
  }
};

// Execute query with automatic context setting
export const queryWithContext = async (
  text: string,
  params?: any[],
  userId?: string,
  orgId?: string
): Promise<any> => {
  const client = await pool.connect();
  
  try {
    // Set context for RLS
    if (userId) {
      await client.query('SET LOCAL app.current_user_id = $1', [userId]);
    }
    if (orgId) {
      await client.query('SET LOCAL app.current_org_id = $1', [orgId]);
    }
    
    // Execute the actual query
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
};

// Graceful shutdown
export const closeDatabase = async (): Promise<void> => {
  try {
    await pool.end();
    logger.info('Database connection pool closed');
  } catch (error) {
    logger.error('Error closing database connection pool', error);
  }
};

export { dbConfig };
export default pool;