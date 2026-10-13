'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const config = require('./config');
const { jsonParseErrorHandler, generalErrorHandler } = require('./middleware/error-handler');

// Route modules
const healthRoutes = require('./routes/health.routes');
const securityRoutes = require('./routes/security.routes');
const eventsRoutes = require('./routes/events.routes');
const tracesRoutes = require('./routes/traces.routes');
const statsRoutes = require('./routes/stats.routes');
const retrievalRoutes = require('./routes/retrieval.routes');
const dashboardRoutes = require('./routes/dashboard.routes');
const attackLabRoutes = require('./routes/attack-lab.routes');

/**
 * Create and configure the Express application.
 * Separated from server.js so tests can import the app without starting a listener.
 */
function createApp() {
  const app = express();

  // ---------------------------------------------------------------------------
  // Security headers
  // ---------------------------------------------------------------------------
  app.use(helmet({
    contentSecurityPolicy: false, // API-only backend, no HTML served
  }));

  // ---------------------------------------------------------------------------
  // CORS
  // ---------------------------------------------------------------------------
  app.use(cors({
    origin: config.corsOrigins,
    methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Trace-Id'],
    maxAge: 86400,
  }));

  // ---------------------------------------------------------------------------
  // Body parsing with size limits
  // ---------------------------------------------------------------------------
  app.use(express.json({ limit: config.jsonLimit }));

  // ---------------------------------------------------------------------------
  // Routes
  // ---------------------------------------------------------------------------
  app.use('/api', healthRoutes);
  app.use('/api', securityRoutes);
  app.use('/api', eventsRoutes);
  app.use('/api', tracesRoutes);
  app.use('/api', statsRoutes);
  app.use('/api', retrievalRoutes);
  app.use('/api', dashboardRoutes);
  app.use('/api', attackLabRoutes);

  // ---------------------------------------------------------------------------
  // 404 fallback
  // ---------------------------------------------------------------------------
  app.use((req, res) => {
    res.status(404).json({
      error: 'Not found',
      message: `No route matches ${req.method} ${req.path}`,
    });
  });

  // ---------------------------------------------------------------------------
  // Error handlers (must be last)
  // ---------------------------------------------------------------------------
  app.use(jsonParseErrorHandler);
  app.use(generalErrorHandler);

  return app;
}

module.exports = createApp;
