'use strict';

const { Router } = require('express');
const db = require('../db/database');

const router = Router();

router.get('/health', (req, res) => {
  const dbHealthy = db.isHealthy();

  const response = {
    service: 'traceguard-security-backend',
    status: dbHealthy ? 'healthy' : 'degraded',
    database: dbHealthy ? 'connected' : 'unavailable',
    timestamp: new Date().toISOString(),
    uptime_seconds: Math.floor(process.uptime()),
  };

  const statusCode = dbHealthy ? 200 : 503;
  res.status(statusCode).json(response);
});

module.exports = router;
