// src/config/app.ts - Simple configuration
interface AppConfig {
  port: number;
  host: string;
  nodeEnv: string;
  apiVersion: string;
  cors: {
    origin: string | boolean;
    credentials: boolean;
  };
}

export const config: AppConfig = {
  port: parseInt(process.env.PORT || '3001'),
  host: process.env.HOST || 'localhost',
  nodeEnv: process.env.NODE_ENV || 'development',
  apiVersion: process.env.API_VERSION || 'v1',
  cors: {
    origin: process.env.CORS_ORIGIN || true,
    credentials: process.env.CORS_CREDENTIALS === 'true'
  }
};

// Validate configuration
export const validateConfig = (): void => {
  if (config.port < 1 || config.port > 65535) {
    throw new Error('PORT must be between 1 and 65535');
  }
  
  if (!config.apiVersion) {
    throw new Error('API_VERSION is required');
  }
  
  console.log('✅ Configuration validated successfully');
};