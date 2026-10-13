'use strict';

const path = require('node:path');

// Load .env from security-backend root if present
try {
  require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });
} catch {
  // dotenv is optional at runtime — env vars can be set externally
}

const config = {
  env: process.env.NODE_ENV || 'development',
  host: process.env.HOST || '127.0.0.1',
  port: parseInt(process.env.SECURITY_PORT, 10) || 4000,
  sqlitePath: process.env.SQLITE_PATH || path.join(__dirname, '..', '..', 'data', 'traceguard.db'),
  logLevel: process.env.LOG_LEVEL || 'info',

  // JSON body size limit
  jsonLimit: '1mb',

  // CORS origins for local development
  corsOrigins: process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(',').map(s => s.trim())
    : ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000'],

  // Query defaults
  defaultEventLimit: 50,
  maxEventLimit: 500,
};

module.exports = config;
