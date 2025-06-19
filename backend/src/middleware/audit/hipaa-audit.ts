import { Request, Response, NextFunction } from 'express';
import { logHipaaEvent } from '../../config/logging';

export const hipaaAuditMiddleware = (req: Request, _res: Response, next: NextFunction): void => {
  // Skip audit for health checks and non-sensitive endpoints
  const skipPaths = ['/health', '/api/health', '/favicon.ico'];
  if (skipPaths.includes(req.path)) {
    return next();
  }

  // Determine if this request involves PHI (Protected Health Information)
  const phiPaths = [
    '/api/v1/patients',
    '/api/v1/claims',
    '/api/v1/payments',
    '/api/v1/insurance',
  ];
  
  const involvesPhi = phiPaths.some(path => req.path.startsWith(path));
  
  // Get user information from request (will be set by auth middleware)
  const userId = (req as any).user?.id;
  const organizationId = (req as any).user?.organizationId;
  const userRole = (req as any).user?.role;
  
  // Log HIPAA audit event
  logHipaaEvent('API_ACCESS', {
    userId,
    organizationId,
    userRole,
    method: req.method,
    path: req.path,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    requestId: (req as any).requestId,
    involvesPhi,
    timestamp: new Date().toISOString(),
  });

  // If this involves PHI, add additional tracking
  if (involvesPhi && userId) {
    // Extract patient ID from request if available
    const patientId = req.params.patientId || req.body?.patientId || req.query?.patientId;
    
    if (patientId) {
      logHipaaEvent('PHI_ACCESS', {
        userId,
        organizationId,
        patientId,
        action: `${req.method}_${req.path}`,
        ip: req.ip,
        requestId: (req as any).requestId,
        timestamp: new Date().toISOString(),
      });
    }
  }

  next();
};