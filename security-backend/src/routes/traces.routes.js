'use strict';

const { Router } = require('express');
const { validateTraceIdParam, validateTraceStatusUpdate } = require('../middleware/request-validation');
const auditService = require('../services/audit-service');

const router = Router();

/**
 * POST /api/traces
 *
 * Create a new trace independently of chatbot interactions.
 * Initial status: 'processing'.
 */
router.post('/traces', (req, res, next) => {
  try {
    const { request_summary } = req.body || {};
    const interaction = auditService.createInteraction(null, request_summary || null);

    res.status(201).json({
      trace_id: interaction.trace_id,
      status: interaction.status,
      created_at: interaction.created_at,
      updated_at: interaction.updated_at,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * PATCH /api/traces/:traceId/status
 *
 * Update the status of a trace adhering to lifecycle state-transition rules.
 */
router.patch('/traces/:traceId/status', validateTraceIdParam, validateTraceStatusUpdate, (req, res, next) => {
  try {
    const { traceId } = req.params;
    const { status } = req.body;

    const updated = auditService.updateInteractionStatus(traceId, status);

    res.status(200).json({
      trace_id: updated.trace_id,
      previous_status: updated.previous_status,
      status: updated.status,
      updated_at: updated.updated_at,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/traces/:traceId
 *
 * Get the complete trace for an interaction: interaction record + all events in stable sequence order.
 */
router.get('/traces/:traceId', validateTraceIdParam, (req, res, next) => {
  try {
    const { traceId } = req.params;

    const trace = auditService.getTrace(traceId);

    if (!trace) {
      return res.status(404).json({
        error: 'Not found',
        message: `No trace found with ID: ${traceId}`,
      });
    }

    res.status(200).json({
      trace_id: traceId,
      interaction: trace.interaction,
      events: trace.events,
      retrieval_records: trace.retrieval_records || [],
      tool_events: trace.tool_events || [],
      event_count: trace.events.length,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
