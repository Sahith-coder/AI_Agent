'use strict';

const crypto = require('node:crypto');

/**
 * TraceGuard Trace & ID Service
 *
 * Provides ID generation, validation, and trace lifecycle state-machine logic.
 */

const VALID_STATUSES = [
  'processing',
  'needs_clarification',
  'completed',
  'blocked',
  'failed',
  'cancelled',
];

const TERMINAL_STATUSES = ['completed', 'blocked', 'failed', 'cancelled'];

/**
 * Documented state-transition map for trace lifecycle.
 * Terminal states have no valid outward transitions.
 */
const ALLOWED_TRANSITIONS = {
  processing: ['needs_clarification', 'completed', 'blocked', 'failed', 'cancelled'],
  needs_clarification: ['processing', 'failed', 'cancelled'],
  completed: [],
  blocked: [],
  failed: [],
  cancelled: [],
  // Backward-compatibility alias for legacy 'active' status
  active: ['processing', 'needs_clarification', 'completed', 'blocked', 'failed', 'cancelled'],
};

/**
 * Generate a new trace ID.
 * @returns {string}
 */
function generateTraceId() {
  return `tg-${crypto.randomUUID()}`;
}

/**
 * Generate a new event ID.
 * @returns {string}
 */
function generateEventId() {
  return `ev-${crypto.randomUUID()}`;
}

/**
 * Generate a new retrieval ID.
 * @returns {string}
 */
function generateRetrievalId() {
  return `ret-${crypto.randomUUID()}`;
}

/**
 * Generate a new tool event ID.
 * @returns {string}
 */
function generateToolEventId() {
  return `tool-${crypto.randomUUID()}`;
}

/**
 * Generate a new Attack Lab test run ID.
 * @returns {string}
 */
function generateRunId() {
  return `run-${crypto.randomUUID()}`;
}

/**
 * Generate a new test result ID.
 * @returns {string}
 */
function generateResultId() {
  return `res-${crypto.randomUUID()}`;
}

/**
 * Validate that a string looks like a TraceGuard trace ID.
 * @param {string} id
 * @returns {boolean}
 */
function isValidTraceId(id) {
  if (!id || typeof id !== 'string') return false;
  return /^tg-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id);
}

/**
 * Validate trace status transitions according to the lifecycle state machine.
 * @param {string} currentStatus
 * @param {string} targetStatus
 * @throws {Error} if the transition is illegal or either status is invalid
 */
function validateTransition(currentStatus, targetStatus) {
  if (!VALID_STATUSES.includes(targetStatus)) {
    const error = new Error(`Invalid status: '${targetStatus}'. Allowed statuses: ${VALID_STATUSES.join(', ')}`);
    error.statusCode = 400;
    throw error;
  }

  if (currentStatus === targetStatus) {
    return; // No-op transition
  }

  if (TERMINAL_STATUSES.includes(currentStatus)) {
    const error = new Error(`Cannot transition from terminal status '${currentStatus}' to '${targetStatus}'. Terminal traces cannot be restarted.`);
    error.statusCode = 400;
    throw error;
  }

  const validTargets = ALLOWED_TRANSITIONS[currentStatus] || [];
  if (!validTargets.includes(targetStatus)) {
    const error = new Error(`Illegal state transition from '${currentStatus}' to '${targetStatus}'.`);
    error.statusCode = 400;
    throw error;
  }
}

/**
 * Generate a new clarification session ID.
 * @returns {string}
 */
function generateSessionId() {
  return `cs-${crypto.randomUUID()}`;
}

/**
 * Generate a new candidate ID.
 * @returns {string}
 */
function generateCandidateId() {
  return `cand-${crypto.randomUUID()}`;
}

module.exports = {
  VALID_STATUSES,
  TERMINAL_STATUSES,
  ALLOWED_TRANSITIONS,
  generateTraceId,
  generateEventId,
  generateRetrievalId,
  generateToolEventId,
  generateRunId,
  generateResultId,
  generateSessionId,
  generateCandidateId,
  isValidTraceId,
  validateTransition,
};
