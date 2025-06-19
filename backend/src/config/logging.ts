import winston from 'winston';
import path from 'path';
import fs from 'fs';

// Ensure logs directory exists
const logsDir = path.dirname(process.env.LOG_FILE || 'logs/medlinkpro.log');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format for HIPAA compliance
const hipaaFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss.SSS'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    // Remove sensitive information from logs
    const sanitizedMeta = sanitizeLogData(meta);
    
    return JSON.stringify({
      timestamp,
      level: level.toUpperCase(),
      message,
      ...sanitizedMeta,
      source: 'medlinkpro-backend'
    });
  })
);

// Sanitize sensitive data from logs (HIPAA compliance)
const sanitizeLogData = (data: any): any => {
  if (typeof data !== 'object' || data === null) {
    return data;
  }

  const sensitiveFields = [
    'password',
    'token',
    'authorization',
    'ssn',
    'social_security_number',
    'date_of_birth',
    'dob',
    'phone',
    'email',
    'address',
    'medical_record_number',
    'mrn',
    'policy_number',
    'account_number',
    'credit_card',
    'bank_account'
  ];

  const sanitized = { ...data };

  for (const key in sanitized) {
    if (sensitiveFields.some(field => key.toLowerCase().includes(field))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof sanitized[key] === 'object') {
      sanitized[key] = sanitizeLogData(sanitized[key]);
    }
  }

  return sanitized;
};

// Create logger instance
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: hipaaFormat,
  defaultMeta: {
    service: 'medlinkpro-backend',
    environment: process.env.NODE_ENV || 'development'
  },
  transports: [
    // File transport for all logs
    new winston.transports.File({
      filename: process.env.LOG_FILE || 'logs/medlinkpro.log',
      maxsize: 10485760, // 10MB
      maxFiles: 5,
      tailable: true
    }),
    
    // Separate file for errors
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      maxsize: 10485760, // 10MB
      maxFiles: 5,
      tailable: true
    }),
    
    // Separate file for HIPAA audit events
    new winston.transports.File({
      filename: 'logs/hipaa-audit.log',
      level: 'info',
      maxsize: 10485760, // 10MB
      maxFiles: 10, // Keep more audit files
      tailable: true,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          // Only log HIPAA-related events to this file
          if (meta.hipaaEvent || meta.phiAccess || meta.auditEvent) {
            return JSON.stringify({
              timestamp,
              level: level.toUpperCase(),
              message,
              ...sanitizeLogData(meta),
              auditType: 'HIPAA_COMPLIANCE'
            });
          }
          return '';
        })
      )
    })
  ],
  
  // Handle uncaught exceptions
  exceptionHandlers: [
    new winston.transports.File({ filename: 'logs/exceptions.log' })
  ],
  
  // Handle unhandled promise rejections
  rejectionHandlers: [
    new winston.transports.File({ filename: 'logs/rejections.log' })
  ]
});

// Add console transport for development
if (process.env.NODE_ENV === 'development') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple(),
      winston.format.printf(({ level, message, timestamp, ...meta }) => {
        const metaString = Object.keys(meta).length ? 
          `\n${JSON.stringify(sanitizeLogData(meta), null, 2)}` : '';
        return `${timestamp} [${level}]: ${message}${metaString}`;
      })
    )
  }));
}

// HIPAA-specific logging functions
export const logHipaaEvent = (event: string, details: any = {}): void => {
  logger.info(event, {
    hipaaEvent: true,
    auditEvent: true,
    ...details,
    timestamp: new Date().toISOString()
  });
};

export const logPhiAccess = (userId: string, patientId: string, action: string, details: any = {}): void => {
  logger.info(`PHI Access: ${action}`, {
    phiAccess: true,
    auditEvent: true,
    userId,
    patientId,
    action,
    ...details,
    timestamp: new Date().toISOString()
  });
};

export const logSecurityEvent = (event: string, severity: 'low' | 'medium' | 'high', details: any = {}): void => {
  const logLevel = severity === 'high' ? 'error' : severity === 'medium' ? 'warn' : 'info';
  
  logger[logLevel](`Security Event: ${event}`, {
    securityEvent: true,
    auditEvent: true,
    severity,
    ...details,
    timestamp: new Date().toISOString()
  });
};

export default logger;