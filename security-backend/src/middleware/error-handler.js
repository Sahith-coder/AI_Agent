'use strict';

/**
 * Central error handling middleware.
 * Must be registered after all routes.
 */

// JSON parse error handler — catches SyntaxError from express.json()
function jsonParseErrorHandler(err, req, res, next) {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      error: 'Parse error',
      message: 'Request body contains invalid JSON.',
    });
  }

  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Payload too large',
      message: 'Request body exceeds the allowed size limit.',
    });
  }

  next(err);
}

// General error handler — safe responses without stack traces
function generalErrorHandler(err, req, res, _next) {
  const status = err.status || err.statusCode || 500;
  const isProduction = process.env.NODE_ENV === 'production';

  const response = {
    error: status >= 500 ? 'Internal server error' : 'Request error',
    message: isProduction && status >= 500
      ? 'An unexpected error occurred.'
      : err.message || 'An unexpected error occurred.',
  };

  // Log server errors
  if (status >= 500) {
    console.error(`[ERROR] ${err.message}`, err.stack || '');
  }

  res.status(status).json(response);
}

module.exports = { jsonParseErrorHandler, generalErrorHandler };
