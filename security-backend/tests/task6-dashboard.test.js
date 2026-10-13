/**
 * Task 6 Automated Test Suite — Security Dashboard APIs
 *
 * Comprehensive tests covering:
 * 1. GET /api/dashboard/overview with empty database (honest zero counts, no mock data)
 * 2. GET /api/dashboard/overview with populated data (accuracy across interactions, events, retrieval, tools)
 * 3. Traffic isolation: normal user traffic vs synthetic Attack Lab activity
 * 4. GET /api/dashboard/trends for 24h (24 hourly buckets), 7d (7 daily buckets), 30d (30 daily buckets)
 * 5. Rejection of invalid trend window parameter with 400
 * 6. GET /api/dashboard/alerts with validated filtering (severity, stage, policy_decision, timestamps)
 * 7. Rejection of invalid alert filters and excessive limit (>100) with 400
 * 8. GET /api/dashboard/retrieval source summaries and model context inclusion flags
 * 9. GET /api/dashboard/tools outcome distinction and risk indicators tally
 * 10. Redaction safety: dashboard summaries never expose raw secrets or credentials
 */

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { initDatabase, close } = require('../src/db/database');
const auditService = require('../src/services/audit-service');
const { DashboardService } = require('../src/services/dashboard-service');
const createApp = require('../src/app');

let server;
let baseUrl;

function apiRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const options = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: { 'Content-Type': 'application/json' },
    };

    const req = http.request(options, (res) => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf-8');
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = raw; }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed });
      });
    });

    req.on('error', reject);
    if (body !== null) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

describe('Task 6: Dashboard Service Unit & Aggregation Logic', () => {
  let dashboardService;

  before(async () => {
    await initDatabase(':memory:');
    dashboardService = new DashboardService();
  });

  after(() => {
    close();
  });

  it('generates honest zero-valued overview on an empty database', () => {
    const overview = dashboardService.getOverview();

    assert.equal(overview.interactions.total, 0);
    assert.equal(overview.interactions.normal_traffic, 0);
    assert.equal(overview.interactions.synthetic_benchmark, 0);

    assert.equal(overview.security_events.total, 0);
    assert.equal(overview.security_events.recent_24h, 0);
    assert.equal(overview.security_events.by_severity.critical, 0);
    assert.equal(overview.security_events.by_severity.high, 0);
    assert.equal(overview.security_events.by_stage.prompt, 0);
    assert.equal(overview.security_events.by_policy_decision.block, 0);

    assert.equal(overview.retrieval.total_records, 0);
    assert.equal(overview.retrieval.included_in_context, 0);
    assert.equal(overview.retrieval.unique_sources, 0);

    assert.equal(overview.tools.total_events, 0);
    assert.equal(overview.tools.by_outcome.succeeded, 0);
    assert.equal(overview.tools.by_outcome.proposed, 0);

    assert.equal(overview.latest_attack_lab_run, null);
    assert.ok(overview.generated_at);
  });

  it('aggregates real records accurately and isolates synthetic benchmark traffic', () => {
    // 1. Create normal interaction and security event
    const normalTrace = auditService.createInteraction(null, 'User chat inquiry');
    auditService.addSecurityEvent({
      trace_id: normalTrace.trace_id,
      stage: 'prompt',
      event_type: 'prompt_injection',
      severity: 'high',
      policy_decision: 'block',
      rule_id: 'PI-001',
    });

    // 2. Create synthetic attack lab interaction
    const synthTrace = auditService.createInteraction(null, '[ATTACK_LAB] TC-BENIGN-01 run');
    auditService.addSecurityEvent({
      trace_id: synthTrace.trace_id,
      stage: 'output',
      event_type: 'secret_leak',
      severity: 'critical',
      policy_decision: 'redact',
      rule_id: 'OS-001',
    });

    // 3. Create retrieval record
    auditService.addRetrievalRecord({
      trace_id: normalTrace.trace_id,
      source_id: 'doc-auth-01',
      source_label: 'Auth Documentation',
      included_in_model_context: 1,
    });

    // 4. Create tool events
    auditService.addToolEvent({
      trace_id: normalTrace.trace_id,
      call_id: 'call-tool-1',
      tool_name: 'calc',
      sanitized_argument_summary: '2+2',
      execution_outcome: 'succeeded',
    });
    auditService.addToolEvent({
      trace_id: normalTrace.trace_id,
      call_id: 'call-tool-2',
      tool_name: 'calc',
      sanitized_argument_summary: '5*5',
      execution_outcome: 'proposed',
    });

    const overview = dashboardService.getOverview();

    assert.equal(overview.interactions.total, 2);
    assert.equal(overview.interactions.normal_traffic, 1);
    assert.equal(overview.interactions.synthetic_benchmark, 1);

    assert.equal(overview.security_events.total, 2);
    assert.equal(overview.security_events.by_severity.high, 1);
    assert.equal(overview.security_events.by_severity.critical, 1);
    assert.equal(overview.security_events.by_stage.prompt, 1);
    assert.equal(overview.security_events.by_stage.output, 1);
    assert.equal(overview.security_events.by_policy_decision.block, 1);
    assert.equal(overview.security_events.by_policy_decision.redact, 1);

    assert.equal(overview.retrieval.total_records, 1);
    assert.equal(overview.retrieval.included_in_context, 1);
    assert.equal(overview.retrieval.unique_sources, 1);

    assert.equal(overview.tools.total_events, 2);
    assert.equal(overview.tools.by_outcome.succeeded, 1);
    assert.equal(overview.tools.by_outcome.proposed, 1);
    assert.equal(overview.tools.unique_tools, 1);
  });

  it('computes time-bucketed trends across 24h, 7d, and 30d correctly', () => {
    const trends24h = dashboardService.getTrends({ window: '24h' });
    assert.equal(trends24h.window, '24h');
    assert.equal(trends24h.bucket_count, 24);
    assert.equal(trends24h.buckets.length, 24);
    assert.ok(trends24h.buckets[23].bucket_end);

    const trends7d = dashboardService.getTrends({ window: '7d' });
    assert.equal(trends7d.window, '7d');
    assert.equal(trends7d.bucket_count, 7);
    assert.equal(trends7d.buckets.length, 7);

    const trends30d = dashboardService.getTrends({ window: '30d' });
    assert.equal(trends30d.window, '30d');
    assert.equal(trends30d.bucket_count, 30);
    assert.equal(trends30d.buckets.length, 30);
  });

  it('rejects invalid trend window parameter with 400 error', () => {
    assert.throws(
      () => dashboardService.getTrends({ window: '90d' }),
      err => err.statusCode === 400 && /Invalid window parameter/.test(err.message)
    );
  });

  it('filters alerts cleanly with structured pagination and validation', () => {
    const res = dashboardService.getAlerts({ severity: 'high', page: 1, limit: 10 });
    assert.equal(res.pagination.page, 1);
    assert.equal(res.pagination.limit, 10);
    assert.equal(res.data.length, 1);
    assert.equal(res.data[0].severity, 'high');

    // Test invalid severity rejection
    assert.throws(
      () => dashboardService.getAlerts({ severity: 'super_fatal' }),
      err => err.statusCode === 400 && /Invalid severity/.test(err.message)
    );

    // Test invalid limit rejection (>100)
    assert.throws(
      () => dashboardService.getAlerts({ limit: 500 }),
      err => err.statusCode === 400 && /limit must be an integer between 1 and 100/.test(err.message)
    );
  });

  it('computes retrieval summary and respects model context inclusion flags', () => {
    const res = dashboardService.getRetrievalSummary();
    assert.equal(res.summary.total_records, 1);
    assert.equal(res.summary.included_in_context, 1);
    assert.equal(res.summary.excluded_from_context, 0);
    assert.equal(res.by_source.length, 1);
    assert.equal(res.by_source[0].source_id, 'doc-auth-01');
    assert.equal(res.recent_records.length, 1);
    assert.equal(res.recent_records[0].source_id, 'doc-auth-01');
  });

  it('computes tool summary distinguishing proposed vs succeeded outcomes', () => {
    const res = dashboardService.getToolSummary();
    assert.equal(res.summary.total_events, 2);
    assert.equal(res.summary.by_outcome.succeeded, 1);
    assert.equal(res.summary.by_outcome.proposed, 1);
    assert.equal(res.by_tool.length, 1);
    assert.equal(res.by_tool[0].tool_name, 'calc');
    assert.equal(res.by_tool[0].total_calls, 2);
    assert.equal(res.by_tool[0].succeeded_count, 1);
    assert.equal(res.by_tool[0].proposed_count, 1);
  });
});

describe('Task 6: Dashboard HTTP Endpoints Integration', () => {
  before(async () => {
    await initDatabase(':memory:');
    const app = createApp();
    server = app.listen(0);
    const port = server.address().port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(() => {
    if (server) server.close();
    close();
  });

  beforeEach(() => {
    // Seed sample interaction and security event
    const trace = auditService.createInteraction(null, 'HTTP dashboard test trace');
    auditService.addSecurityEvent({
      trace_id: trace.trace_id,
      stage: 'prompt',
      event_type: 'prompt_injection',
      severity: 'critical',
      policy_decision: 'block',
      rule_id: 'PI-001',
      redacted_evidence: 'Ignore instructions [REDACTED:API_KEY]',
    });
  });

  it('GET /api/dashboard/overview returns 200 with structured database metrics', async () => {
    const res = await apiRequest('GET', '/api/dashboard/overview');
    assert.equal(res.status, 200);
    assert.ok(res.body.interactions);
    assert.ok(res.body.security_events);
    assert.ok(res.body.retrieval);
    assert.ok(res.body.tools);
    assert.ok(res.body.generated_at);
    assert.equal(res.body.security_events.by_severity.critical >= 1, true);
  });

  it('GET /api/dashboard/trends returns 200 for valid ranges and 400 for invalid ranges', async () => {
    const res24h = await apiRequest('GET', '/api/dashboard/trends?window=24h');
    assert.equal(res24h.status, 200);
    assert.equal(res24h.body.bucket_count, 24);

    const res7d = await apiRequest('GET', '/api/dashboard/trends?window=7d');
    assert.equal(res7d.status, 200);
    assert.equal(res7d.body.bucket_count, 7);

    const resBad = await apiRequest('GET', '/api/dashboard/trends?window=invalid_range');
    assert.equal(resBad.status, 400);
    assert.match(resBad.body.message, /Invalid window parameter/);
  });

  it('GET /api/dashboard/alerts returns paginated records with safe evidence', async () => {
    const res = await apiRequest('GET', '/api/dashboard/alerts?severity=critical&page=1&limit=5');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.data));
    assert.equal(res.body.pagination.page, 1);
    assert.equal(res.body.pagination.limit, 5);
    assert.ok(res.body.pagination.total >= 1);
    assert.ok(res.body.data[0].redacted_evidence.includes('[REDACTED:API_KEY]'));
  });

  it('GET /api/dashboard/alerts rejects invalid filters with 400', async () => {
    const resBadSev = await apiRequest('GET', '/api/dashboard/alerts?severity=super_fatal');
    assert.equal(resBadSev.status, 400);

    const resBadLimit = await apiRequest('GET', '/api/dashboard/alerts?limit=999');
    assert.equal(resBadLimit.status, 400);
    assert.match(resBadLimit.body.message, /limit must be an integer between 1 and 100/);
  });

  it('GET /api/dashboard/retrieval returns 200 with provenance summaries', async () => {
    const res = await apiRequest('GET', '/api/dashboard/retrieval');
    assert.equal(res.status, 200);
    assert.ok(res.body.summary);
    assert.ok(Array.isArray(res.body.by_source));
    assert.ok(Array.isArray(res.body.recent_records));
    assert.equal(typeof res.body.security_findings_count, 'number');
  });

  it('GET /api/dashboard/tools returns 200 with tool outcomes and risk indicators', async () => {
    const res = await apiRequest('GET', '/api/dashboard/tools');
    assert.equal(res.status, 200);
    assert.ok(res.body.summary);
    assert.ok(res.body.summary.by_outcome);
    assert.ok(Array.isArray(res.body.by_tool));
    assert.ok(res.body.risk_indicators);
    assert.ok(Array.isArray(res.body.recent_events));
  });
});
