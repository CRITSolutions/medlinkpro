// src/server.ts - Updated with config and database
import 'dotenv/config';
import App from './app';
import { config, validateConfig } from './config/app';
import { validateDatabaseConfig, testConnection, closeConnections } from './config/database';
import { logger } from './utils/logger';

class Server {
  private app: App;

  constructor() {
    this.app = new App();
  }

  public async start(): Promise<void> {
    try {
      // Validate configuration
      validateConfig();
      validateDatabaseConfig();
      
      // Test database connection
      logger.info('Testing database connection...');
      const dbConnected = await testConnection();
      
      if (!dbConnected) {
        logger.warn('⚠️  Database connection failed, but server will start anyway');
        logger.warn('Make sure PostgreSQL is running and environment variables are set correctly');
      }
      
      // Initialize app
      await this.app.initialize();
      
      const server = this.app.getApp().listen(config.port, config.host, () => {
        logger.info(`🚀 MedLinkPro Server started successfully!`);
        logger.info(`📋 Environment: ${config.nodeEnv}`);
        logger.info(`🌐 Server: http://${config.host}:${config.port}`);
        logger.info(`📋 Health check: http://${config.host}:${config.port}/health`);
        logger.info(`🧪 Test endpoint: http://${config.host}:${config.port}/api/${config.apiVersion}/test`);
        logger.info(`🔧 API Version: ${config.apiVersion}`);
      });

      // Graceful shutdown
      process.on('SIGTERM', () => {
        logger.info('SIGTERM received, shutting down gracefully');
        server.close(async () => {
          await closeConnections();
          process.exit(0);
        });
      });

      process.on('SIGINT', () => {
        logger.info('SIGINT received, shutting down gracefully');
        server.close(async () => {
          await closeConnections();
          process.exit(0);
        });
      });

    } catch (error) {
      logger.error('Failed to start server:', error);
      process.exit(1);
    }
  }
}

// Start the server
if (require.main === module) {
  const server = new Server();
  server.start().catch((error) => {
    logger.error('Unhandled server startup error:', error);
    process.exit(1);
  });
}

export default Server;