'use strict';

const { Router } = require('express');
const { DashboardService } = require('../services/dashboard-service');

const router = Router();
const dashboardService = new DashboardService();

/**
 * GET /api/dashboard/overview
 * Returns real, database-derived summary metrics across interactions,
 * security events, retrieval provenance, tool activity, and the latest Attack Lab run.
 */
router.get('/dashboard/overview', (req, res, next) => {
  try {
    const overview = dashboardService.getOverview();
    res.status(200).json(overview);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/dashboard/trends
 * Returns time-bucketed event statistics for 24h, 7d, or 30d.
 */
router.get('/dashboard/trends', (req, res, next) => {
  try {
    const { window } = req.query;
    const trends = dashboardService.getTrends({ window: window || '24h' });
    res.status(200).json(trends);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/dashboard/alerts
 * Returns paginated, filtered security alerts and events.
 */
router.get('/dashboard/alerts', (req, res, next) => {
  try {
    const alerts = dashboardService.getAlerts(req.query);
    res.status(200).json(alerts);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/dashboard/retrieval
 * Returns retrieval provenance counts, source breakdown, and recent records.
 */
router.get('/dashboard/retrieval', (req, res, next) => {
  try {
    const { page, limit } = req.query;
    const summary = dashboardService.getRetrievalSummary({ page, limit });
    res.status(200).json(summary);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/dashboard/tools
 * Returns tool activity counts, outcome breakdown, and risk indicators.
 */
router.get('/dashboard/tools', (req, res, next) => {
  try {
    const { page, limit, outcome } = req.query;
    const summary = dashboardService.getToolSummary({ page, limit, outcome });
    res.status(200).json(summary);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
