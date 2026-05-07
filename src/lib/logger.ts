// =============================================================================
// FILE: src/lib/logger.ts
// PURPOSE: Structured logging utility for consistent log output
//          Logs with timestamp, level, message, and context
//          Makes errors easier to track in production
// =============================================================================

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogContext {
  [key: string]: any;
}

class Logger {
  private formatTimestamp(): string {
    return new Date().toISOString();
  }

  private formatMessage(level: LogLevel, message: string, context?: LogContext): string {
    const timestamp = this.formatTimestamp();
    const contextStr = context && Object.keys(context).length > 0 
      ? ` | ${JSON.stringify(context)}` 
      : '';
    return `[${timestamp}] [${level.toUpperCase()}] ${message}${contextStr}`;
  }

  debug(message: string, context?: LogContext) {
    if (typeof window === 'undefined' && process.env.NODE_ENV === 'development') {
      console.log(this.formatMessage('debug', message, context));
    }
  }

  info(message: string, context?: LogContext) {
    console.log(this.formatMessage('info', message, context));
  }

  warn(message: string, context?: LogContext) {
    console.warn(this.formatMessage('warn', message, context));
  }

  error(message: string, error?: Error | LogContext, context?: LogContext) {
    const finalContext = error instanceof Error 
      ? { ...context, error: error.message, stack: error.stack }
      : { ...error, ...context };
    
    console.error(this.formatMessage('error', message, finalContext));
  }
}

export const logger = new Logger();
