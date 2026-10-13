'use strict';

const db = require('../db/database');
const {
  generateTraceId,
  generateEventId,
  generateRetrievalId,
  generateToolEventId,
  generateRunId,
  generateResultId,
  validateTransition,
} = require('./trace-service');

/**
 * TraceGuard Audit Service
 *
 * Persistence layer for interactions, security events, retrieval provenance,
 * tool events, and Attack Lab test results using SQLite (sql.js).
 */

// ---- Interaction / Trace management ----

/**
 * Create a new interaction record.
 * @param {string|null} [traceId]
 * @param {string|null} [requestSummary]
 * @returns {{ trace_id: string, status: string, created_at: string, updated_at: string }}
 */
function createInteraction(traceId, requestSummary = null) {
  const id = traceId || generateTraceId();
  const now = new Date().toISOString();
  const initialStatus = 'processing';

  db.run(
    `INSERT INTO interactions (trace_id, created_at, updated_at, status, request_summary)
     VALUES (?, ?, ?, ?, ?)`,
    [id, now, now, initialStatus, requestSummary]
  );

  return { trace_id: id, status: initialStatus, created_at: now, updated_at: now };
}

/**
 * Get an existing interaction or null.
 * @param {string} traceId
 * @returns {Object|null}
 */
function getInteraction(traceId) {
  if (!traceId) return null;
  return db.get('SELECT * FROM interactions WHERE trace_id = ?', [traceId]);
}

/**
 * Get an existing interaction or create one.
 * @param {string|null} traceId
 * @param {string|null} [requestSummary]
 * @returns {{ trace_id: string, status: string, created_at: string, updated_at: string, is_new: boolean }}
 */
function getOrCreateInteraction(traceId, requestSummary = null) {
  if (traceId) {
    const existing = getInteraction(traceId);
    if (existing) {
      return {
        trace_id: existing.trace_id,
        status: existing.status,
        created_at: existing.created_at,
        updated_at: existing.updated_at,
        is_new: false,
      };
    }
  }
  const created = createInteraction(traceId, requestSummary);
  return { ...created, is_new: true };
}

/**
 * Update interaction status with state-machine validation.
 * @param {string} traceId
 * @param {string} targetStatus
 * @returns {Object} updated interaction
 */
function updateInteractionStatus(traceId, targetStatus) {
  const interaction = getInteraction(traceId);
  if (!interaction) {
    const error = new Error(`Interaction not found for trace_id: ${traceId}`);
    error.statusCode = 404;
    throw error;
  }

  // Validate state machine transition
  validateTransition(interaction.status, targetStatus);

  const now = new Date().toISOString();
  db.run(
    'UPDATE interactions SET status = ?, updated_at = ? WHERE trace_id = ?',
    [targetStatus, now, traceId]
  );

  return {
    trace_id: traceId,
    previous_status: interaction.status,
    status: targetStatus,
    updated_at: now,
  };
}

// ---- Security event management ----

/**
 * Add a security event correlated to an interaction.
 * Monotonically allocates sequence_no and validates parent_event_id inside a transaction.
 *
 * @param {Object} event
 * @returns {string} event_id
 */
function addSecurityEvent({
  trace_id,
  stage,
  event_type,
  threat_category = null,
  severity = 'info',
  policy_decision = null,
  rule_id = null,
  rule_version = '1.0.0',
  policy_version = '1.0.0',
  reason = null,
  source_id = null,
  execution_outcome = null,
  duration_ms = null,
  redacted_evidence = null,
  parent_event_id = null,
  call_id = null,
  metadata = null,
}) {
  return db.transaction(() => {
    // 1. Verify trace exists
    const interaction = db.get('SELECT trace_id FROM interactions WHERE trace_id = ?', [trace_id]);
    if (!interaction) {
      const err = new Error(`Foreign key violation: trace_id '${trace_id}' does not exist.`);
      err.statusCode = 400;
      throw err;
    }

    // 2. Verify parent_event_id if provided
    if (parent_event_id) {
      const parent = db.get('SELECT event_id FROM security_events WHERE event_id = ?', [parent_event_id]);
      if (!parent) {
        const err = new Error(`Foreign key violation: parent_event_id '${parent_event_id}' does not exist.`);
        err.statusCode = 400;
        throw err;
      }
    }

    // 3. Monotonically allocate sequence_no per trace
    const seqRow = db.get(
      'SELECT COALESCE(MAX(sequence_no), 0) + 1 AS next_seq FROM security_events WHERE trace_id = ?',
      [trace_id]
    );
    const sequence_no = seqRow ? seqRow.next_seq : 1;

    const eventId = generateEventId();
    const now = new Date().toISOString();
    const metadata_json = metadata ? (typeof metadata === 'string' ? metadata : JSON.stringify(metadata)) : null;

    db.getDatabase().run(
      `INSERT INTO security_events
        (event_id, trace_id, sequence_no, parent_event_id, call_id,
         timestamp, stage, event_type, threat_category, severity,
         policy_decision, rule_id, rule_version, policy_version, reason,
         source_id, execution_outcome, duration_ms, redacted_evidence, metadata_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        eventId, trace_id, sequence_no, parent_event_id, call_id,
        now, stage, event_type, threat_category, severity,
        policy_decision, rule_id, rule_version, policy_version, reason,
        source_id, execution_outcome, duration_ms, redacted_evidence, metadata_json,
      ]
    );

    return eventId;
  });
}

// ---- Query functions ----

/**
 * List events with optional filters, pagination, and stable sequence ordering.
 * @param {Object} filters — { trace_id, severity, stage, event_type, page, limit }
 * @returns {{ events: Array, data: Array, pagination: Object, total: number }}
 */
function listEvents(filters = {}) {
  const conditions = [];
  const params = [];

  if (filters.trace_id) {
    conditions.push('trace_id = ?');
    params.push(filters.trace_id);
  }
  if (filters.severity) {
    conditions.push('severity = ?');
    params.push(filters.severity);
  }
  if (filters.stage) {
    conditions.push('stage = ?');
    params.push(filters.stage);
  }
  if (filters.event_type) {
    conditions.push('event_type = ?');
    params.push(filters.event_type);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  // Count total matching rows
  const countRow = db.get(`SELECT COUNT(*) AS total FROM security_events ${where}`, params);
  const total = countRow ? countRow.total : 0;

  // Pagination
  const page = Math.max(parseInt(filters.page, 10) || 1, 1);
  const limit = Math.min(Math.max(parseInt(filters.limit, 10) || 25, 1), 100);
  const offset = (page - 1) * limit;

  // Query page
  const queryParams = [...params, limit, offset];
  const orderClause = filters.trace_id
    ? 'ORDER BY sequence_no ASC, timestamp ASC'
    : 'ORDER BY timestamp DESC, sequence_no DESC';

  const rows = db.all(
    `SELECT * FROM security_events ${where} ${orderClause} LIMIT ? OFFSET ?`,
    queryParams
  );

  const totalPages = Math.ceil(total / limit) || (total === 0 ? 0 : 1);

  // Return array with attached pagination properties for complete backward-compatibility
  rows.data = rows;
  rows.events = rows;
  rows.pagination = {
    page,
    limit,
    total,
    total_pages: totalPages,
  };
  rows.total = total;
  rows.count = rows.length;

  return rows;
}

/**
 * Get a complete trace: interaction + correlated events, retrieval records, and tool events.
 * @param {string} traceId
 * @returns {{ interaction: Object, events: Array, retrieval_records: Array, tool_events: Array }|null}
 */
function getTrace(traceId) {
  const interaction = getInteraction(traceId);
  if (!interaction) return null;

  const events = db.all(
    'SELECT * FROM security_events WHERE trace_id = ? ORDER BY sequence_no ASC, timestamp ASC',
    [traceId]
  );

  const retrieval_records = db.all(
    'SELECT * FROM retrieval_records WHERE trace_id = ? ORDER BY retrieval_order ASC',
    [traceId]
  );

  const tool_events = db.all(
    'SELECT * FROM tool_events WHERE trace_id = ? ORDER BY timestamp ASC',
    [traceId]
  );

  return {
    interaction,
    events,
    retrieval_records,
    tool_events,
    event_count: events.length,
  };
}

// ---- Retrieval Provenance Storage (B4) ----

/**
 * Add a retrieval record linked to a trace.
 * @param {Object} record
 * @returns {string} retrieval_id
 */
function addRetrievalRecord({
  trace_id,
  event_id = null,
  call_id = null,
  source_id,
  source_label,
  source_version = null,
  source_hash = null,
  chunk_id = null,
  chunk_hash = null,
  retrieval_order = 1,
  relevance_score = null,
  trust_metadata = null,
  included_in_model_context = 1,
  redacted_excerpt = null,
}) {
  if (!trace_id || !source_id || !source_label) {
    const err = new Error('trace_id, source_id, and source_label are required.');
    err.statusCode = 400;
    throw err;
  }

  const interaction = getInteraction(trace_id);
  if (!interaction) {
    const err = new Error(`Foreign key violation: trace_id '${trace_id}' does not exist.`);
    err.statusCode = 400;
    throw err;
  }

  const retrievalId = generateRetrievalId();
  const trust_str = trust_metadata
    ? (typeof trust_metadata === 'string' ? trust_metadata : JSON.stringify(trust_metadata))
    : null;

  db.run(
    `INSERT INTO retrieval_records
      (retrieval_id, trace_id, event_id, call_id, source_id, source_label,
       source_version, source_hash, chunk_id, chunk_hash, retrieval_order,
       relevance_score, trust_metadata, included_in_model_context, redacted_excerpt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      retrievalId, trace_id, event_id, call_id, source_id, source_label,
      source_version, source_hash, chunk_id, chunk_hash, retrieval_order,
      relevance_score, trust_str, included_in_model_context ? 1 : 0, redacted_excerpt
    ]
  );

  return retrievalId;
}

/**
 * List retrieval records for a trace.
 * @param {string} traceId
 * @returns {Array<Object>}
 */
function listRetrievalRecords(traceId) {
  return db.all(
    'SELECT * FROM retrieval_records WHERE trace_id = ? ORDER BY retrieval_order ASC',
    [traceId]
  );
}

// ---- Dedicated Tool Event Storage (B5) ----

const VALID_TOOL_OUTCOMES = ['proposed', 'started', 'succeeded', 'failed', 'denied', 'unknown'];

/**
 * Add a tool execution event.
 * @param {Object} toolEvent
 * @returns {string} tool_event_id
 */
function addToolEvent({
  trace_id,
  event_id = null,
  sequence_no = null,
  parent_event_id = null,
  call_id = null,
  tool_name,
  tool_server_identity = null,
  sanitized_argument_summary,
  argument_hash = null,
  source_metadata = null,
  suspicion_indicators = null,
  execution_outcome = 'unknown',
  redacted_result_summary = null,
}) {
  if (!trace_id || !tool_name || !sanitized_argument_summary) {
    const err = new Error('trace_id, tool_name, and sanitized_argument_summary are required.');
    err.statusCode = 400;
    throw err;
  }

  if (!VALID_TOOL_OUTCOMES.includes(execution_outcome)) {
    const err = new Error(`Invalid execution_outcome: '${execution_outcome}'. Allowed: ${VALID_TOOL_OUTCOMES.join(', ')}`);
    err.statusCode = 400;
    throw err;
  }

  const interaction = getInteraction(trace_id);
  if (!interaction) {
    const err = new Error(`Foreign key violation: trace_id '${trace_id}' does not exist.`);
    err.statusCode = 400;
    throw err;
  }

  const toolEventId = generateToolEventId();
  const now = new Date().toISOString();
  const source_str = source_metadata ? (typeof source_metadata === 'string' ? source_metadata : JSON.stringify(source_metadata)) : null;
  const susp_str = suspicion_indicators ? (typeof suspicion_indicators === 'string' ? suspicion_indicators : JSON.stringify(suspicion_indicators)) : null;

  db.run(
    `INSERT INTO tool_events
      (tool_event_id, trace_id, event_id, sequence_no, parent_event_id,
       call_id, tool_name, tool_server_identity, sanitized_argument_summary,
       argument_hash, source_metadata, suspicion_indicators, timestamp,
       execution_outcome, redacted_result_summary)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      toolEventId, trace_id, event_id, sequence_no, parent_event_id,
      call_id, tool_name, tool_server_identity, sanitized_argument_summary,
      argument_hash, source_str, susp_str, now,
      execution_outcome, redacted_result_summary
    ]
  );

  return toolEventId;
}

/**
 * List tool events for a trace.
 * @param {string} traceId
 * @returns {Array<Object>}
 */
function listToolEvents(traceId) {
  return db.all(
    'SELECT * FROM tool_events WHERE trace_id = ? ORDER BY timestamp ASC',
    [traceId]
  );
}

// ---- Attack Lab Result Storage (B6) ----

const VALID_RUN_STATUSES = ['running', 'passed', 'failed', 'error', 'cancelled'];
const VALID_TEST_RESULTS = ['pass', 'fail', 'error', 'skipped'];

/**
 * Create a new Attack Lab test run.
 * @param {Object} run
 * @returns {string} run_id
 */
function createTestRun({
  test_suite_version,
  app_version = '0.1.0',
  rule_version = '1.0.0',
  policy_version = '1.0.0',
  status = 'running',
  test_case_count = 0,
  model_metadata = null,
}) {
  if (!test_suite_version) {
    const err = new Error('test_suite_version is required.');
    err.statusCode = 400;
    throw err;
  }
  if (!VALID_RUN_STATUSES.includes(status)) {
    const err = new Error(`Invalid status: '${status}'. Allowed: ${VALID_RUN_STATUSES.join(', ')}`);
    err.statusCode = 400;
    throw err;
  }

  const runId = generateRunId();
  const now = new Date().toISOString();
  const model_str = model_metadata ? (typeof model_metadata === 'string' ? model_metadata : JSON.stringify(model_metadata)) : null;

  db.run(
    `INSERT INTO test_runs
      (run_id, started_at, test_suite_version, app_version, rule_version,
       policy_version, status, test_case_count, model_metadata)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [runId, now, test_suite_version, app_version, rule_version, policy_version, status, test_case_count, model_str]
  );

  return runId;
}

/**
 * Update test run status.
 * @param {string} runId
 * @param {string} status
 */
function updateTestRunStatus(runId, status) {
  if (!VALID_RUN_STATUSES.includes(status)) {
    const err = new Error(`Invalid status: '${status}'`);
    err.statusCode = 400;
    throw err;
  }
  const now = new Date().toISOString();
  db.run('UPDATE test_runs SET status = ?, completed_at = ? WHERE run_id = ?', [status, now, runId]);
}

/**
 * Add an individual test result for a run.
 * @param {Object} result
 * @returns {string} result_id
 */
function addTestResult({
  run_id,
  case_id,
  trace_id = null,
  expected_classification = null,
  actual_findings = null,
  expected_decision = null,
  actual_decision = null,
  pass_fail_result,
  latency_ms = null,
  event_references = null,
}) {
  if (!run_id || !case_id || !pass_fail_result) {
    const err = new Error('run_id, case_id, and pass_fail_result are required.');
    err.statusCode = 400;
    throw err;
  }
  if (!VALID_TEST_RESULTS.includes(pass_fail_result)) {
    const err = new Error(`Invalid pass_fail_result: '${pass_fail_result}'. Allowed: ${VALID_TEST_RESULTS.join(', ')}`);
    err.statusCode = 400;
    throw err;
  }

  const run = db.get('SELECT run_id FROM test_runs WHERE run_id = ?', [run_id]);
  if (!run) {
    const err = new Error(`Foreign key violation: run_id '${run_id}' does not exist.`);
    err.statusCode = 400;
    throw err;
  }

  const resultId = generateResultId();
  const findings_str = actual_findings ? (typeof actual_findings === 'string' ? actual_findings : JSON.stringify(actual_findings)) : null;
  const refs_str = event_references ? (typeof event_references === 'string' ? event_references : JSON.stringify(event_references)) : null;

  db.run(
    `INSERT INTO test_results
      (result_id, run_id, case_id, trace_id, expected_classification,
       actual_findings, expected_decision, actual_decision, pass_fail_result,
       latency_ms, event_references)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      resultId, run_id, case_id, trace_id, expected_classification,
      findings_str, expected_decision, actual_decision, pass_fail_result,
      latency_ms, refs_str
    ]
  );

  return resultId;
}

/**
 * Get a test run with all its results.
 * @param {string} runId
 * @returns {Object|null}
 */
function getTestRun(runId) {
  const run = db.get('SELECT * FROM test_runs WHERE run_id = ?', [runId]);
  if (!run) return null;

  const results = db.all('SELECT * FROM test_results WHERE run_id = ?', [runId]);
  return { ...run, results, result_count: results.length };
}

// ---- Aggregate stats ----

/**
 * Compute aggregate event statistics from stored data.
 * @returns {Object}
 */
function getStats() {
  const totalEventsRow = db.get('SELECT COUNT(*) AS count FROM security_events');
  const totalEvents = totalEventsRow ? totalEventsRow.count : 0;

  const totalInteractionsRow = db.get('SELECT COUNT(*) AS count FROM interactions');
  const totalInteractions = totalInteractionsRow ? totalInteractionsRow.count : 0;

  const bySeverity = db.all(
    'SELECT severity, COUNT(*) AS count FROM security_events GROUP BY severity ORDER BY count DESC'
  );

  const byStage = db.all(
    'SELECT stage, COUNT(*) AS count FROM security_events GROUP BY stage ORDER BY count DESC'
  );

  const byDecision = db.all(
    "SELECT policy_decision, COUNT(*) AS count FROM security_events WHERE policy_decision IS NOT NULL GROUP BY policy_decision ORDER BY count DESC"
  );

  const recentRow = db.get(
    "SELECT COUNT(*) AS count FROM security_events WHERE timestamp >= datetime('now', '-1 day')"
  );
  const recentCount = recentRow ? recentRow.count : 0;

  return {
    total_events: totalEvents,
    total_interactions: totalInteractions,
    by_severity: bySeverity,
    by_stage: byStage,
    by_decision: byDecision,
    recent_24h: recentCount,
  };
}

module.exports = {
  createInteraction,
  getInteraction,
  getOrCreateInteraction,
  updateInteractionStatus,
  addSecurityEvent,
  listEvents,
  getTrace,
  addRetrievalRecord,
  listRetrievalRecords,
  addToolEvent,
  listToolEvents,
  createTestRun,
  updateTestRunStatus,
  addTestResult,
  getTestRun,
  getStats,
  VALID_TOOL_OUTCOMES,
};
