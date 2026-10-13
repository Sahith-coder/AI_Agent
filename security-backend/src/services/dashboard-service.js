'use strict';

const db = require('../db/database');
const auditService = require('./audit-service');

const VALID_WINDOWS = ['24h', '7d', '30d'];
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_STAGES = ['prompt', 'output', 'retrieved_content', 'tool_monitoring'];
const VALID_DECISIONS = ['block', 'redact', 'flag', 'allow'];
const VALID_TOOL_OUTCOMES = ['proposed', 'started', 'succeeded', 'failed', 'denied', 'unknown'];

class DashboardService {
  constructor() {
    this.db = db;
  }

  _getDb() {
    return db;
  }

  /**
   * GET /api/dashboard/overview
   * Real database-derived overview metrics.
   * Completely zero-valued when database is empty (no fabricated numbers).
   */
  getOverview() {
    const db = this._getDb();

    // 1. Interactions metrics (separating normal user traffic from synthetic Attack Lab benchmarks)
    const totalInteractionsRow = db.get('SELECT COUNT(*) AS count FROM interactions');
    const totalInteractions = totalInteractionsRow ? totalInteractionsRow.count : 0;

    const normalTrafficRow = db.get(
      "SELECT COUNT(*) AS count FROM interactions WHERE request_summary NOT LIKE '[ATTACK_LAB]%' OR request_summary IS NULL"
    );
    const normalTraffic = normalTrafficRow ? normalTrafficRow.count : 0;
    const syntheticBenchmark = totalInteractions - normalTraffic;

    const interactionStatusRows = db.all(
      'SELECT status, COUNT(*) AS count FROM interactions GROUP BY status'
    );
    const interactionsByStatus = {};
    for (const row of interactionStatusRows) {
      interactionsByStatus[row.status] = row.count;
    }

    // 2. Security Events metrics
    const totalEventsRow = db.get('SELECT COUNT(*) AS count FROM security_events');
    const totalEvents = totalEventsRow ? totalEventsRow.count : 0;

    const recentEventsRow = db.get(
      "SELECT COUNT(*) AS count FROM security_events WHERE timestamp >= datetime('now', '-1 day')"
    );
    const recent24h = recentEventsRow ? recentEventsRow.count : 0;

    const severityRows = db.all(
      'SELECT severity, COUNT(*) AS count FROM security_events GROUP BY severity'
    );
    const eventsBySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const row of severityRows) {
      eventsBySeverity[row.severity] = row.count;
    }

    const stageRows = db.all(
      'SELECT stage, COUNT(*) AS count FROM security_events GROUP BY stage'
    );
    const eventsByStage = { prompt: 0, output: 0, retrieved_content: 0, tool_monitoring: 0 };
    for (const row of stageRows) {
      eventsByStage[row.stage] = row.count;
    }

    const decisionRows = db.all(
      'SELECT policy_decision, COUNT(*) AS count FROM security_events WHERE policy_decision IS NOT NULL GROUP BY policy_decision'
    );
    const eventsByDecision = { block: 0, redact: 0, flag: 0, allow: 0 };
    for (const row of decisionRows) {
      eventsByDecision[row.policy_decision] = row.count;
    }

    // 3. Retrieval Records metrics
    const totalRetrievalRow = db.get('SELECT COUNT(*) AS count FROM retrieval_records');
    const totalRetrievals = totalRetrievalRow ? totalRetrievalRow.count : 0;

    const includedContextRow = db.get(
      'SELECT COUNT(*) AS count FROM retrieval_records WHERE included_in_model_context = 1'
    );
    const includedContext = includedContextRow ? includedContextRow.count : 0;
    const excludedContext = totalRetrievals - includedContext;

    const uniqueSourcesRow = db.get(
      'SELECT COUNT(DISTINCT source_id) AS count FROM retrieval_records'
    );
    const uniqueSources = uniqueSourcesRow ? uniqueSourcesRow.count : 0;

    // 4. Tool Events metrics (observational only, never counting proposed as successful)
    const totalToolEventsRow = db.get('SELECT COUNT(*) AS count FROM tool_events');
    const totalToolEvents = totalToolEventsRow ? totalToolEventsRow.count : 0;

    const uniqueToolsRow = db.get('SELECT COUNT(DISTINCT tool_name) AS count FROM tool_events');
    const uniqueTools = uniqueToolsRow ? uniqueToolsRow.count : 0;

    const outcomeRows = db.all(
      'SELECT execution_outcome, COUNT(*) AS count FROM tool_events GROUP BY execution_outcome'
    );
    const toolOutcomes = {
      proposed: 0,
      started: 0,
      succeeded: 0,
      failed: 0,
      denied: 0,
      unknown: 0,
    };
    for (const row of outcomeRows) {
      if (toolOutcomes[row.execution_outcome] !== undefined) {
        toolOutcomes[row.execution_outcome] = row.count;
      }
    }

    // 5. Latest Attack Lab Run summary
    const latestRun = auditService.getLatestTestRun();

    return {
      generated_at: new Date().toISOString(),
      interactions: {
        total: totalInteractions,
        normal_traffic: normalTraffic,
        synthetic_benchmark: syntheticBenchmark,
        by_status: interactionsByStatus,
      },
      security_events: {
        total: totalEvents,
        recent_24h: recent24h,
        by_severity: eventsBySeverity,
        by_stage: eventsByStage,
        by_policy_decision: eventsByDecision,
      },
      retrieval: {
        total_records: totalRetrievals,
        included_in_context: includedContext,
        excluded_from_context: excludedContext,
        unique_sources: uniqueSources,
      },
      tools: {
        total_events: totalToolEvents,
        unique_tools: uniqueTools,
        by_outcome: toolOutcomes,
      },
      latest_attack_lab_run: latestRun
        ? {
            run_id: latestRun.run_id,
            test_suite_version: latestRun.test_suite_version,
            status: latestRun.status,
            started_at: latestRun.started_at,
            completed_at: latestRun.completed_at,
            test_case_count: latestRun.test_case_count,
            passed_count: latestRun.passed_count,
            failed_count: latestRun.failed_count,
            error_count: latestRun.error_count,
            pass_rate: latestRun.pass_rate,
          }
        : null,
    };
  }

  /**
   * GET /api/dashboard/trends
   * Time-bucketed trends over 24h, 7d, or 30d.
   */
  getTrends({ window = '24h' } = {}) {
    if (!VALID_WINDOWS.includes(window)) {
      const err = new Error(`Invalid window parameter: '${window}'. Allowed: ${VALID_WINDOWS.join(', ')}`);
      err.statusCode = 400;
      throw err;
    }

    const db = this._getDb();
    const now = new Date();
    const buckets = [];

    let bucketCount = 24;
    let stepMs = 3600 * 1000; // 1 hour
    if (window === '7d') {
      bucketCount = 7;
      stepMs = 24 * 3600 * 1000; // 1 day
    } else if (window === '30d') {
      bucketCount = 30;
      stepMs = 24 * 3600 * 1000; // 1 day
    }

    const windowStartMs = now.getTime() - bucketCount * stepMs;
    const windowStartIso = new Date(windowStartMs).toISOString();

    // Pre-create empty buckets
    for (let i = 0; i < bucketCount; i++) {
      const bStart = new Date(windowStartMs + i * stepMs);
      const bEnd = new Date(windowStartMs + (i + 1) * stepMs);
      buckets.push({
        bucket_index: i,
        bucket_start: bStart.toISOString(),
        bucket_end: bEnd.toISOString(),
        event_count: 0,
        block_count: 0,
        redact_count: 0,
        flag_count: 0,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        by_stage: { prompt: 0, output: 0, retrieved_content: 0, tool_monitoring: 0 },
      });
    }

    // Query actual events in the range
    const events = db.all(
      'SELECT timestamp, severity, stage, policy_decision FROM security_events WHERE timestamp >= ? ORDER BY timestamp ASC',
      [windowStartIso]
    );

    for (const ev of events) {
      const evTime = new Date(ev.timestamp).getTime();
      const bucketIdx = Math.floor((evTime - windowStartMs) / stepMs);
      if (bucketIdx >= 0 && bucketIdx < bucketCount) {
        const bucket = buckets[bucketIdx];
        bucket.event_count++;
        if (ev.policy_decision === 'block') bucket.block_count++;
        if (ev.policy_decision === 'redact') bucket.redact_count++;
        if (ev.policy_decision === 'flag') bucket.flag_count++;

        if (bucket.by_severity[ev.severity] !== undefined) {
          bucket.by_severity[ev.severity]++;
        }
        if (bucket.by_stage[ev.stage] !== undefined) {
          bucket.by_stage[ev.stage]++;
        }
      }
    }

    return {
      window,
      bucket_count: buckets.length,
      range_start: windowStartIso,
      range_end: now.toISOString(),
      buckets,
      generated_at: now.toISOString(),
    };
  }

  /**
   * GET /api/dashboard/alerts
   * Paginated, validated query on security events with structured filtering.
   */
  getAlerts(filters = {}) {
    const db = this._getDb();

    // 1. Pagination validation
    const page = Math.max(1, parseInt(filters.page, 10) || 1);
    const limit = parseInt(filters.limit, 10) || 20;

    if (isNaN(limit) || limit < 1 || limit > 100) {
      const err = new Error('limit must be an integer between 1 and 100.');
      err.statusCode = 400;
      throw err;
    }

    const offset = (page - 1) * limit;

    // 2. Filter validations
    const conditions = [];
    const params = [];

    if (filters.severity) {
      if (!VALID_SEVERITIES.includes(filters.severity)) {
        const err = new Error(`Invalid severity: '${filters.severity}'. Allowed: ${VALID_SEVERITIES.join(', ')}`);
        err.statusCode = 400;
        throw err;
      }
      conditions.push('severity = ?');
      params.push(filters.severity);
    }

    if (filters.stage) {
      if (!VALID_STAGES.includes(filters.stage)) {
        const err = new Error(`Invalid stage: '${filters.stage}'. Allowed: ${VALID_STAGES.join(', ')}`);
        err.statusCode = 400;
        throw err;
      }
      conditions.push('stage = ?');
      params.push(filters.stage);
    }

    if (filters.policy_decision) {
      if (!VALID_DECISIONS.includes(filters.policy_decision)) {
        const err = new Error(`Invalid policy_decision: '${filters.policy_decision}'. Allowed: ${VALID_DECISIONS.join(', ')}`);
        err.statusCode = 400;
        throw err;
      }
      conditions.push('policy_decision = ?');
      params.push(filters.policy_decision);
    }

    if (filters.trace_id) {
      if (typeof filters.trace_id !== 'string' || filters.trace_id.trim().length === 0) {
        const err = new Error('trace_id must be a non-empty string.');
        err.statusCode = 400;
        throw err;
      }
      conditions.push('trace_id = ?');
      params.push(filters.trace_id.trim());
    }

    if (filters.event_type) {
      conditions.push('event_type = ?');
      params.push(filters.event_type.trim());
    }

    if (filters.start_time) {
      const startDate = new Date(filters.start_time);
      if (isNaN(startDate.getTime())) {
        const err = new Error(`Invalid start_time format: '${filters.start_time}'. Must be a valid ISO-8601 date.`);
        err.statusCode = 400;
        throw err;
      }
      conditions.push('timestamp >= ?');
      params.push(startDate.toISOString());
    }

    if (filters.end_time) {
      const endDate = new Date(filters.end_time);
      if (isNaN(endDate.getTime())) {
        const err = new Error(`Invalid end_time format: '${filters.end_time}'. Must be a valid ISO-8601 date.`);
        err.statusCode = 400;
        throw err;
      }
      conditions.push('timestamp <= ?');
      params.push(endDate.toISOString());
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    // Count matching rows
    const countRow = db.get(`SELECT COUNT(*) AS total FROM security_events ${whereClause}`, params);
    const total = countRow ? countRow.total : 0;

    // Query paginated rows (stable ordering)
    const rows = db.all(
      `SELECT * FROM security_events ${whereClause} ORDER BY timestamp DESC, sequence_no DESC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    const totalPages = Math.ceil(total / limit) || (total === 0 ? 0 : 1);

    return {
      data: rows,
      events: rows,
      pagination: {
        page,
        limit,
        total,
        total_pages: totalPages,
      },
    };
  }

  /**
   * GET /api/dashboard/retrieval
   * Summary of retrieval records, source provenance breakdown, and associated security findings.
   */
  getRetrievalSummary({ page = 1, limit = 20 } = {}) {
    const db = this._getDb();
    const p = Math.max(1, parseInt(page, 10) || 1);
    const l = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const offset = (p - 1) * l;

    // Total counts
    const totalRow = db.get('SELECT COUNT(*) AS count FROM retrieval_records');
    const totalRecords = totalRow ? totalRow.count : 0;

    const includedRow = db.get('SELECT COUNT(*) AS count FROM retrieval_records WHERE included_in_model_context = 1');
    const includedCount = includedRow ? includedRow.count : 0;
    const excludedCount = totalRecords - includedCount;

    const sourcesRow = db.get('SELECT COUNT(DISTINCT source_id) AS count FROM retrieval_records');
    const uniqueSources = sourcesRow ? sourcesRow.count : 0;

    // By source aggregation
    const sourceRows = db.all(`
      SELECT
        source_id,
        source_label,
        COUNT(*) AS retrieval_count,
        ROUND(AVG(relevance_score), 3) AS avg_relevance,
        SUM(CASE WHEN included_in_model_context = 1 THEN 1 ELSE 0 END) AS included_count,
        SUM(CASE WHEN included_in_model_context = 0 THEN 1 ELSE 0 END) AS excluded_count
      FROM retrieval_records
      GROUP BY source_id, source_label
      ORDER BY retrieval_count DESC
      LIMIT 20
    `);

    // Recent provenance records (paginated, with safe sanitized excerpts)
    const recentRecords = db.all(
      'SELECT * FROM retrieval_records ORDER BY retrieval_order ASC, retrieval_id DESC LIMIT ? OFFSET ?',
      [l, offset]
    );

    const sanitizedRecent = recentRecords.map(r => {
      let trust = null;
      try {
        if (r.trust_metadata) trust = JSON.parse(r.trust_metadata);
      } catch { trust = r.trust_metadata; }
      return {
        retrieval_id: r.retrieval_id,
        trace_id: r.trace_id,
        source_id: r.source_id,
        source_label: r.source_label,
        chunk_id: r.chunk_id,
        relevance_score: r.relevance_score,
        included_in_model_context: r.included_in_model_context,
        sanitized_excerpt: r.redacted_excerpt,
        trust_metadata: trust,
      };
    });

    // Associated security events in retrieval stage
    const securityFindingsRow = db.get(
      "SELECT COUNT(*) AS count FROM security_events WHERE stage = 'retrieved_content' OR event_type = 'indirect_prompt_injection'"
    );
    const securityFindingsCount = securityFindingsRow ? securityFindingsRow.count : 0;

    return {
      summary: {
        total_records: totalRecords,
        included_in_context: includedCount,
        excluded_from_context: excludedCount,
        unique_sources: uniqueSources,
      },
      by_source: sourceRows,
      recent_records: sanitizedRecent,
      security_findings_count: securityFindingsCount,
      pagination: {
        page: p,
        limit: l,
        total: totalRecords,
        total_pages: Math.ceil(totalRecords / l) || (totalRecords === 0 ? 0 : 1),
      },
    };
  }

  /**
   * GET /api/dashboard/tools
   * Observational tool monitoring activity, outcome breakdown, and risk indicators.
   */
  getToolSummary({ page = 1, limit = 20, outcome = null } = {}) {
    const db = this._getDb();
    const p = Math.max(1, parseInt(page, 10) || 1);
    const l = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));

    // Summary counts
    const totalRow = db.get('SELECT COUNT(*) AS count FROM tool_events');
    const totalEvents = totalRow ? totalRow.count : 0;

    const uniqueToolsRow = db.get('SELECT COUNT(DISTINCT tool_name) AS count FROM tool_events');
    const uniqueTools = uniqueToolsRow ? uniqueToolsRow.count : 0;

    const outcomeRows = db.all(
      'SELECT execution_outcome, COUNT(*) AS count FROM tool_events GROUP BY execution_outcome'
    );
    const outcomes = {
      proposed: 0,
      started: 0,
      succeeded: 0,
      failed: 0,
      denied: 0,
      unknown: 0,
    };
    for (const r of outcomeRows) {
      if (outcomes[r.execution_outcome] !== undefined) {
        outcomes[r.execution_outcome] = r.count;
      }
    }

    // Breakdown by tool name
    const byToolRows = db.all(`
      SELECT
        tool_name,
        COUNT(*) AS total_calls,
        SUM(CASE WHEN execution_outcome = 'proposed' THEN 1 ELSE 0 END) AS proposed_count,
        SUM(CASE WHEN execution_outcome = 'started' THEN 1 ELSE 0 END) AS started_count,
        SUM(CASE WHEN execution_outcome = 'succeeded' THEN 1 ELSE 0 END) AS succeeded_count,
        SUM(CASE WHEN execution_outcome = 'failed' THEN 1 ELSE 0 END) AS failed_count,
        SUM(CASE WHEN execution_outcome = 'denied' THEN 1 ELSE 0 END) AS denied_count,
        SUM(CASE WHEN execution_outcome = 'unknown' THEN 1 ELSE 0 END) AS unknown_count
      FROM tool_events
      GROUP BY tool_name
      ORDER BY total_calls DESC
      LIMIT 20
    `);

    // Risk indicators tally from security_events stage='tool_monitoring'
    const riskIndicatorRows = db.all(`
      SELECT rule_id, COUNT(*) AS count
      FROM security_events
      WHERE stage = 'tool_monitoring'
      GROUP BY rule_id
      ORDER BY count DESC
    `);
    const riskIndicators = {
      'TOOL-RISK-INJECTION-ARG': 0,
      'TOOL-RISK-SENSITIVE-RESULT': 0,
      'TOOL-RISK-EXFILTRATION-SEQUENCE': 0,
      'TOOL-RISK-RAPID-CALLS': 0,
      'TOOL-RISK-UNVERIFIED-SERVER': 0,
      'TOOL-RISK-LIFECYCLE-ANOMALY': 0,
    };
    for (const r of riskIndicatorRows) {
      if (r.rule_id) {
        riskIndicators[r.rule_id] = r.count;
      }
    }

    // Recent tool events (using existing listToolEventsFiltered)
    const recentFiltered = auditService.listToolEventsFiltered(null, { page: p, limit: l, outcome });

    return {
      summary: {
        total_events: totalEvents,
        unique_tools: uniqueTools,
        by_outcome: outcomes,
      },
      by_tool: byToolRows,
      risk_indicators: riskIndicators,
      recent_events: recentFiltered.tool_events,
      pagination: {
        page: p,
        limit: l,
        total: recentFiltered.total,
        total_pages: recentFiltered.total_pages,
      },
    };
  }
}

module.exports = {
  DashboardService,
  VALID_WINDOWS,
  VALID_SEVERITIES,
  VALID_STAGES,
  VALID_DECISIONS,
};
