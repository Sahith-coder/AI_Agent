'use strict';

const { Router } = require('express');
const { validateEventFilters } = require('../middleware/request-validation');
const auditService = require('../services/audit-service');

const router = Router();

/**
 * GET /api/events
 *
 * List security events with validated pagination and filtering.
 * Query params: trace_id, severity, stage, event_type, page, limit
 */
router.get('/events', validateEventFilters, (req, res, next) => {
  try {
    const { trace_id, severity, stage, event_type, page, limit } = req.query;

    const result = auditService.listEvents({
      trace_id: trace_id || undefined,
      severity: severity || undefined,
      stage: stage || undefined,
      event_type: event_type || undefined,
      page: page || undefined,
      limit: limit || undefined,
    });

    res.status(200).json({
      data: result,
      events: result,
      pagination: result.pagination || { page: 1, limit: result.length, total: result.length, total_pages: 1 },
      count: result.length,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
