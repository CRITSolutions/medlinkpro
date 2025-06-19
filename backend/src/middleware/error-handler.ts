import { Request, Response, NextFunction } from 'express';
import { logger } from '../config/logging';

export interface AppError extends Error {
  statusCode?: number;
  status?: string;
  isOperational?: boolean;
  code?: string;
}

export const errorHandler = (
  error: AppError,
  req: Request,
  res: Response,
  _next: NextFunction
): void => {
  // Set default error values
  error.statusCode = error.statusCode || 500;
  error.status = error.status || 'error';

  // Log the error (with HIPAA-safe logging)
  logger.error('Application error occurred', {
    error: error.message,
    stack: error.stack,
    statusCode: error.statusCode,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: (req as any).user?.id,
    organizationId: (req as any).user?.organizationId,
  });

  // Send error response
  const errorResponse = {
    error: error.message || 'Internal Server Error',
    code: error.code || 'INTERNAL_ERROR',
    status: error.status,
    timestamp: new Date().toISOString(),
    ...(process.env.NODE_ENV === 'development' && {
      stack: error.stack,
      details: error,
    }),
  };

  res.status(error.statusCode).json(errorResponse);
};