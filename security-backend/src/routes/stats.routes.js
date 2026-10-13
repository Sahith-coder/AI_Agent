'use strict';

const { Router } = require('express');
const auditService = require('../services/audit-service');

const router = Router();

/**
 * GET /api/stats
 *
 * Aggregate event statistics from the actual database.
 * Never returns fabricated metrics.
 */
router.get('/stats', (req, res, next) => {
  try {
    const stats = auditService.getStats();

    res.status(200).json({
      generated_at: new Date().toISOString(),
      ...stats,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
