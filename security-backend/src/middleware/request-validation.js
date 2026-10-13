'use strict';

const { VALID_STATUSES } = require('../services/trace-service');

/**
 * Request validation middleware.
 * Provides reusable validators for common route needs.
 */

/**
 * Validate that the JSON body contains the required field 'content' as a non-empty string.
 * Optionally validate 'stage' against allowed values.
 */
function validateEvaluationRequest(req, res, next) {
  const { content, stage } = req.body;

  if (content === undefined || content === null) {
    return res.status(400).json({
      error: 'Validation error',
      message: 'Request body must include a "content" field.',
    });
  }

  if (typeof content !== 'string') {
    return res.status(400).json({
      error: 'Validation error',
      message: '"content" must be a string.',
    });
  }

  if (content.trim().length === 0) {
    return res.status(400).json({
      error: 'Validation error',
      message: '"content" must not be empty.',
    });
  }

  const allowedStages = ['prompt', 'output', 'retrieved_content'];
  if (stage !== undefined && stage !== null) {
    if (typeof stage !== 'string' || !allowedStages.includes(stage)) {
      return res.status(400).json({
        error: 'Validation error',
        message: `"stage" must be one of: ${allowedStages.join(', ')}`,
      });
    }
  }

  next();
}

/**
 * Validate trace_id parameter format.
 */
function validateTraceIdParam(req, res, next) {
  const { traceId } = req.params;

  if (!traceId || typeof traceId !== 'string' || traceId.trim().length === 0) {
    return res.status(400).json({
      error: 'Validation error',
      message: 'A valid traceId parameter is required.',
    });
  }

  next();
}

/**
 * Validate status update request body for trace lifecycle.
 */
function validateTraceStatusUpdate(req, res, next) {
  const { status } = req.body;

  if (!status || typeof status !== 'string') {
    return res.status(400).json({
      error: 'Validation error',
      message: `"status" field is required and must be a string. Allowed: ${VALID_STATUSES.join(', ')}`,
    });
  }

  if (!VALID_STATUSES.includes(status)) {
    return res.status(400).json({
      error: 'Validation error',
      message: `Invalid status: '${status}'. Allowed: ${VALID_STATUSES.join(', ')}`,
    });
  }

  next();
}

/**
 * Validate query parameters for event listing.
 */
function validateEventFilters(req, res, next) {
  const { limit, page, severity, stage } = req.query;

  if (limit !== undefined) {
    const parsed = parseInt(limit, 10);
    if (isNaN(parsed) || parsed < 1 || parsed > 500) {
      return res.status(400).json({
        error: 'Validation error',
        message: '"limit" must be a positive integer between 1 and 500.',
      });
    }
  }

  if (page !== undefined) {
    const parsedPage = parseInt(page, 10);
    if (isNaN(parsedPage) || parsedPage < 1) {
      return res.status(400).json({
        error: 'Validation error',
        message: '"page" must be a positive integer greater than or equal to 1.',
      });
    }
  }

  const allowedSeverities = ['critical', 'high', 'medium', 'low', 'info'];
  if (severity !== undefined && !allowedSeverities.includes(severity)) {
    return res.status(400).json({
      error: 'Validation error',
      message: `"severity" must be one of: ${allowedSeverities.join(', ')}`,
    });
  }

  const allowedStages = ['prompt', 'output', 'retrieved_content', 'tool'];
  if (stage !== undefined && !allowedStages.includes(stage)) {
    return res.status(400).json({
      error: 'Validation error',
      message: `"stage" must be one of: ${allowedStages.join(', ')}`,
    });
  }

  next();
}

module.exports = {
  validateEvaluationRequest,
  validateTraceIdParam,
  validateTraceStatusUpdate,
  validateEventFilters,
};
