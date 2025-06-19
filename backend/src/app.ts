// src/app.ts - Updated with Authentication Integration
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { logger } from './utils/logger';
import { config } from './config/app';

// Import auth routes
import authRoutes from './routes/auth';

class App {
  private app: express.Application;

  constructor() {
    this.app = express();
    this.initializeSecurityMiddleware();
    this.initializeMiddleware();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }

  private initializeSecurityMiddleware(): void {
    // Security headers
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'), // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'), // limit each IP to 100 requests per windowMs
      message: {
        success: false,
        message: 'Too many requests from this IP, please try again later.',
        retryAfter: Math.ceil(parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000') / 1000)
      },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({
          success: false,
          message: 'Too many requests from this IP, please try again later.',
          retryAfter: Math.ceil(parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000') / 1000)
        });
      }
    });

    this.app.use(limiter);
  }

  private initializeMiddleware(): void {
    // CORS with config
    this.app.use(cors({
          origin: [
            'http://localhost:5173',
            'http://localhost:3000',
            'http://127.0.0.1:5173'
          ],
          credentials: true,  // Required for authentication cookies
          methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
          allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
          exposedHeaders: ['X-Total-Count', 'X-Page-Count']
        }));
            
    // Body parsing middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    
    // Request logging middleware
    this.app.use((req, _res, next) => {
      const startTime = Date.now();
      
      // Log request
      logger.info(`${req.method} ${req.url}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString()
      });

      // Log response time
      _res.on('finish', () => {
        const duration = Date.now() - startTime;
        logger.info(`${req.method} ${req.url} - ${_res.statusCode} - ${duration}ms`);
      });
      
      next();
    });
  }

  private initializeRoutes(): void {
    // Health check with enhanced database status
    this.app.get('/health', async (_req, res) => {
      logger.info('Health check requested');
      
      // Test database connection
      let dbStatus = 'disconnected';
      let dbError: string | null = null;
      
      try {
        const { testConnection } = await import('./config/database');
        const isConnected = await testConnection();
        dbStatus = isConnected ? 'connected' : 'disconnected';
      } catch (error) {
        dbStatus = 'error';
        dbError = error instanceof Error ? error.message : 'Unknown database error';
        logger.warn('Database health check failed:', error);
      }
      
      res.json({
        success: true,
        data: {
          status: 'healthy',
          timestamp: new Date().toISOString(),
          version: '1.0.0',
          environment: config.nodeEnv,
          apiVersion: config.apiVersion,
          database: {
            status: dbStatus,
            error: dbError
          },
          security: {
            rateLimiting: 'active',
            cors: 'configured',
            helmet: 'active'
          }
        }
      });
    });

    // API Routes
    const apiRouter = express.Router();
    
    // Mount authentication routes
    apiRouter.use('/auth', authRoutes);
    
    // Test endpoint
    apiRouter.get('/test', (_req, res) => {
      logger.info('Test endpoint requested');
      res.json({
        success: true,
        message: 'API is working!',
        environment: config.nodeEnv,
        apiVersion: config.apiVersion,
        timestamp: new Date().toISOString()
      });
    });

    // Mount API router
    this.app.use(`/api/${config.apiVersion}`, apiRouter);

    // Root endpoint
    this.app.get('/', (_req, res) => {
      res.json({
        success: true,
        message: 'MedLinkPro API Server',
        version: '1.0.0',
        documentation: `/api/${config.apiVersion}/docs`,
        health: '/health'
      });
    });
  }

  private initializeErrorHandling(): void {
    // 404 handler
    this.app.use('*', (req, res) => {
      logger.warn(`404 - Endpoint not found: ${req.method} ${req.originalUrl}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      res.status(404).json({
        success: false,
        message: 'Endpoint not found',
        error: {
          code: 'NOT_FOUND',
          path: req.originalUrl,
          method: req.method,
          timestamp: new Date().toISOString()
        }
      });
    });

    // Global error handler
    this.app.use((error: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
      logger.error('Unhandled error:', {
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip
      });

      // Don't leak error details in production
      const isDevelopment = config.nodeEnv === 'development';
      
      res.status(error.status || 500).json({
        success: false,
        message: isDevelopment ? error.message : 'Internal server error',
        error: {
          code: error.code || 'INTERNAL_ERROR',
          timestamp: new Date().toISOString(),
          ...(isDevelopment && { stack: error.stack })
        }
      });
    });
  }

  public async initialize(): Promise<void> {
    try {
      // Test database connection on startup
      const { testConnection } = await import('./config/database');
      const isConnected = await testConnection();
      
      if (!isConnected) {
        throw new Error('Database connection failed');
      }
      
      logger.info('Database connection established');
      logger.info('Application initialized successfully');
      
    } catch (error) {
      logger.error('Failed to initialize application:', error);
      throw error;
    }
  }

  public getApp(): express.Application {
    return this.app;
  }
}

export default App;