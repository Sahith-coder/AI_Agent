'use strict';

const { Router } = require('express');
const { RetrievalService } = require('../services/retrieval-service');
const auditService = require('../services/audit-service');

const router = Router();
const defaultRetrievalService = new RetrievalService();

/**
 * POST /api/retrieval/search
 *
 * Execute retrieval search with indirect-injection inspection and ambiguity handling.
 */
router.post('/retrieval/search', async (req, res, next) => {
  try {
    const { query, trace_id, options } = req.body || {};

    if (!query || typeof query !== 'string' || query.trim().length === 0) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'Request body must include a non-empty "query" string.',
      });
    }

    if (query.length > 1000) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'Query exceeds maximum allowed length of 1000 characters.',
      });
    }

    if (trace_id !== undefined && trace_id !== null && typeof trace_id !== 'string') {
      return res.status(400).json({
        error: 'Validation error',
        message: '"trace_id" must be a string.',
      });
    }

    const result = await defaultRetrievalService.search({
      query,
      trace_id: trace_id || null,
      options: options || {},
    });

    res.status(200).json(result);
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/retrieval/clarify
 *
 * Resolve a pending clarification session by user candidate selection.
 * Resumes the original trace back into processing state.
 */
router.post('/retrieval/clarify', async (req, res, next) => {
  try {
    const { session_id, candidate_id } = req.body || {};

    if (!session_id || typeof session_id !== 'string' || session_id.trim().length === 0) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'Request body must include a "session_id" string.',
      });
    }

    if (!candidate_id || typeof candidate_id !== 'string' || candidate_id.trim().length === 0) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'Request body must include a "candidate_id" string.',
      });
    }

    const result = await defaultRetrievalService.clarify({
      session_id: session_id.trim(),
      candidate_id: candidate_id.trim(),
    });

    res.status(200).json(result);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/retrieval/sessions/:sessionId
 *
 * Inspect the state of a clarification session.
 */
router.get('/retrieval/sessions/:sessionId', (req, res, next) => {
  try {
    const { sessionId } = req.params;
    const session = auditService.getClarificationSession(sessionId);

    if (!session) {
      return res.status(404).json({
        error: 'Not found',
        message: `Clarification session '${sessionId}' was not found.`,
      });
    }

    res.status(200).json(session);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/retrieval/records/:traceId
 *
 * List provenance records recorded for a trace.
 */
router.get('/retrieval/records/:traceId', (req, res, next) => {
  try {
    const { traceId } = req.params;
    const records = auditService.listRetrievalRecords(traceId);

    res.status(200).json({
      trace_id: traceId,
      total_records: records.length,
      records,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
