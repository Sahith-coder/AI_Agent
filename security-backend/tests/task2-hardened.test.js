'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

const { initDatabase, close, _reset, run, get, all, getMigrationStatus } = require('../src/db/database');
const { applyMigrations } = require('../src/db/migrations');
const auditService = require('../src/services/audit-service');
const {
  isValidTraceId,
  validateTransition,
  VALID_STATUSES,
  TERMINAL_STATUSES,
} = require('../src/services/trace-service');
const policyEngine = require('../src/services/policy-engine');
const outputScanner = require('../src/services/output-scanner');
const createApp = require('../src/app');

let server;
let baseUrl;

function request(method, path, body = null) {
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
      res.on('data', (chunk) => chunks.push(chunk));
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

describe('Task 2 — Hardened Audit, Lifecycle, and Persistence Contracts', () => {
  before(async () => {
    _reset();
    await initDatabase(':memory:');
    const app = createApp();
    await new Promise((resolve) => {
      server = app.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(() => {
    return new Promise((resolve) => {
      server.close(() => {
        _reset();
        resolve();
      });
    });
  });

  // ---------------------------------------------------------------------------
  // 1 & 5. Creating a trace independently of a chat route & stable IDs
  // ---------------------------------------------------------------------------
  describe('1 & 5. Independent Trace Creation (POST /api/traces)', () => {
    it('should create a trace independently and return initial status processing', async () => {
      const res = await request('POST', '/api/traces', { request_summary: 'Standalone interaction test' });
      assert.equal(res.status, 201);
      assert.ok(isValidTraceId(res.body.trace_id), 'trace_id must be valid format');
      assert.equal(res.body.status, 'processing');
      assert.ok(res.body.created_at);
      assert.ok(res.body.updated_at);
    });
  });

  // ---------------------------------------------------------------------------
  // 2 & 3. Trace status transitions and invalid transitions
  // ---------------------------------------------------------------------------
  describe('2 & 3. Trace Lifecycle Status Transitions (PATCH /api/traces/:traceId/status)', () => {
    it('should support valid state transition: processing -> needs_clarification -> processing -> completed', async () => {
      const createRes = await request('POST', '/api/traces', {});
      const traceId = createRes.body.trace_id;

      // processing -> needs_clarification
      const p1 = await request('PATCH', `/api/traces/${traceId}/status`, { status: 'needs_clarification' });
      assert.equal(p1.status, 200);
      assert.equal(p1.body.status, 'needs_clarification');
      assert.equal(p1.body.previous_status, 'processing');

      // needs_clarification -> processing
      const p2 = await request('PATCH', `/api/traces/${traceId}/status`, { status: 'processing' });
      assert.equal(p2.status, 200);
      assert.equal(p2.body.status, 'processing');

      // processing -> completed
      const p3 = await request('PATCH', `/api/traces/${traceId}/status`, { status: 'completed' });
      assert.equal(p3.status, 200);
      assert.equal(p3.body.status, 'completed');
    });

    it('should prevent terminal status from transitioning (terminal traces cannot restart)', async () => {
      const createRes = await request('POST', '/api/traces', {});
      const traceId = createRes.body.trace_id;

      // Set to blocked (terminal)
      const pBlock = await request('PATCH', `/api/traces/${traceId}/status`, { status: 'blocked' });
      assert.equal(pBlock.status, 200);
      assert.equal(pBlock.body.status, 'blocked');

      // Attempt to restart: blocked -> processing must fail
      const pRestart = await request('PATCH', `/api/traces/${traceId}/status`, { status: 'processing' });
      assert.equal(pRestart.status, 400);
      assert.ok(pRestart.body.message.includes('terminal status'));
    });

    it('should reject invalid transition target or unknown status', async () => {
      const createRes = await request('POST', '/api/traces', {});
      const traceId = createRes.body.trace_id;

      const pInvalid = await request('PATCH', `/api/traces/${traceId}/status`, { status: 'non_existent_status' });
      assert.equal(pInvalid.status, 400);
    });

    it('should return 404 for unknown trace ID', async () => {
      const res = await request('PATCH', '/api/traces/tg-00000000-0000-0000-0000-000000000099/status', {
        status: 'completed',
      });
      assert.equal(res.status, 404);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Automatic trace creation for evaluation requests
  // ---------------------------------------------------------------------------
  describe('4. Automatic Trace Creation on Security Evaluate', () => {
    it('should automatically create a trace when trace_id is omitted', async () => {
      const res = await request('POST', '/api/security/evaluate', {
        stage: 'prompt',
        content: 'Tell me about distributed computing',
      });
      assert.equal(res.status, 200);
      assert.ok(isValidTraceId(res.body.trace_id));
      assert.ok(res.body.event_id.startsWith('ev-'));
      assert.equal(res.body.status, 'completed');
    });

    it('should return 404 when an unknown trace_id is supplied to evaluate', async () => {
      const res = await request('POST', '/api/security/evaluate', {
        trace_id: 'tg-00000000-0000-0000-0000-000000000000',
        stage: 'prompt',
        content: 'Evaluating with non-existent trace ID',
      });
      assert.equal(res.status, 404);
      assert.ok(res.body.message.includes('does not exist'));
    });
  });

  // ---------------------------------------------------------------------------
  // 6 & 7. Increasing sequence numbers and atomic allocation
  // ---------------------------------------------------------------------------
  describe('6 & 7. Monotonic Event Sequence Numbers and Ordering', () => {
    it('should assign monotonically increasing sequence numbers per trace (1, 2, 3...)', () => {
      const interaction = auditService.createInteraction(null, 'Sequence test');
      const traceId = interaction.trace_id;

      const e1 = auditService.addSecurityEvent({ trace_id: traceId, stage: 'prompt', event_type: 'step1' });
      const e2 = auditService.addSecurityEvent({ trace_id: traceId, stage: 'retrieved_content', event_type: 'step2' });
      const e3 = auditService.addSecurityEvent({ trace_id: traceId, stage: 'output', event_type: 'step3' });

      const trace = auditService.getTrace(traceId);
      assert.equal(trace.events.length, 3);
      assert.equal(trace.events[0].sequence_no, 1);
      assert.equal(trace.events[1].sequence_no, 2);
      assert.equal(trace.events[2].sequence_no, 3);
      assert.equal(trace.events[0].event_id, e1);
      assert.equal(trace.events[1].event_id, e2);
      assert.equal(trace.events[2].event_id, e3);
    });

    it('should allocate sequence numbers independently for different traces', () => {
      const t1 = auditService.createInteraction(null, 'Trace 1').trace_id;
      const t2 = auditService.createInteraction(null, 'Trace 2').trace_id;

      auditService.addSecurityEvent({ trace_id: t1, stage: 'prompt', event_type: 't1_e1' });
      auditService.addSecurityEvent({ trace_id: t2, stage: 'prompt', event_type: 't2_e1' });
      auditService.addSecurityEvent({ trace_id: t1, stage: 'output', event_type: 't1_e2' });

      const trace1 = auditService.getTrace(t1);
      const trace2 = auditService.getTrace(t2);

      assert.equal(trace1.events[0].sequence_no, 1);
      assert.equal(trace1.events[1].sequence_no, 2);
      assert.equal(trace2.events[0].sequence_no, 1);
    });
  });

  // ---------------------------------------------------------------------------
  // 8 & 9. Parent-event, call IDs, and foreign-key integrity
  // ---------------------------------------------------------------------------
  describe('8 & 9. Parent-Event, Call ID Correlation, and Foreign Key Integrity', () => {
    it('should preserve parent_event_id and call_id relationships', () => {
      const traceId = auditService.createInteraction(null, 'Hierarchy test').trace_id;
      const callId = 'call-tool-fetch-01';

      const parentEventId = auditService.addSecurityEvent({
        trace_id: traceId,
        stage: 'prompt',
        event_type: 'parent_call',
      });

      const childEventId = auditService.addSecurityEvent({
        trace_id: traceId,
        stage: 'output',
        event_type: 'child_call',
        parent_event_id: parentEventId,
        call_id: callId,
      });

      const trace = auditService.getTrace(traceId);
      const child = trace.events.find(e => e.event_id === childEventId);
      assert.equal(child.parent_event_id, parentEventId);
      assert.equal(child.call_id, callId);
    });

    it('should reject insertion with invalid trace_id (Foreign Key failure)', () => {
      assert.throws(() => {
        auditService.addSecurityEvent({
          trace_id: 'tg-00000000-0000-0000-0000-999999999999',
          stage: 'prompt',
          event_type: 'orphan_event',
        });
      }, /trace_id.*does not exist/);
    });

    it('should reject insertion with non-existent parent_event_id', () => {
      const traceId = auditService.createInteraction(null, 'FK parent test').trace_id;
      assert.throws(() => {
        auditService.addSecurityEvent({
          trace_id: traceId,
          stage: 'prompt',
          event_type: 'orphan_child',
          parent_event_id: 'ev-non-existent-parent',
        });
      }, /parent_event_id.*does not exist/);
    });
  });

  // ---------------------------------------------------------------------------
  // 10 & 11. Idempotent migrations & upgrading existing database with data
  // ---------------------------------------------------------------------------
  describe('10 & 11. Idempotent Migrations & Database Upgrade', () => {
    it('should report migration status and be idempotent on multiple runs', async () => {
      const { getDatabase } = require('../src/db/database');
      const status = getMigrationStatus(getDatabase());
      assert.ok(status.current_version >= 2);

      // Re-running applyMigrations should apply 0 additional migrations
      const reapplied = applyMigrations(getDatabase());
      assert.equal(reapplied.length, 0, 'Re-running migrations must be a safe no-op');
    });

    it('should safely upgrade a legacy database containing records without data loss', async () => {
      const initSqlJs = require('sql.js');
      const SQL = await initSqlJs();
      const legacyDb = new SQL.Database();

      // Create v1 schema manually
      legacyDb.exec(`
        CREATE TABLE interactions (
            trace_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            status TEXT NOT NULL DEFAULT 'active',
            request_summary TEXT
        );
        CREATE TABLE security_events (
            event_id TEXT PRIMARY KEY,
            trace_id TEXT NOT NULL,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            stage TEXT NOT NULL,
            event_type TEXT NOT NULL,
            threat_category TEXT,
            severity TEXT NOT NULL DEFAULT 'info',
            policy_decision TEXT,
            reason TEXT,
            source_id TEXT,
            execution_outcome TEXT,
            redacted_evidence TEXT
        );
        INSERT INTO interactions (trace_id, status, request_summary) VALUES ('tg-legacy-01', 'active', 'Pre-migration trace');
        INSERT INTO security_events (event_id, trace_id, stage, event_type, severity) VALUES ('ev-legacy-01', 'tg-legacy-01', 'prompt', 'scan_clean', 'info');
      `);

      // Run migrations on legacy database
      const applied = applyMigrations(legacyDb);
      assert.ok(applied.length > 0, 'Should apply missing migrations');

      // Verify legacy record survived
      const interactionCheck = legacyDb.exec("SELECT * FROM interactions WHERE trace_id = 'tg-legacy-01'");
      assert.equal(interactionCheck[0].values.length, 1);

      // Verify sequence_no was backfilled
      const eventCheck = legacyDb.exec("SELECT event_id, sequence_no FROM security_events WHERE event_id = 'ev-legacy-01'");
      assert.equal(eventCheck[0].values[0][1], 1, 'Legacy event sequence_no should be backfilled to 1');

      legacyDb.close();
    });
  });

  // ---------------------------------------------------------------------------
  // 12. Persistence across database close and reopen
  // ---------------------------------------------------------------------------
  describe('12. Persistence Across Close and Reopen', () => {
    it('should persist writes to disk file and restore exact records upon reopen', async () => {
      const tempDbPath = path.join(__dirname, '..', 'data', `test-persist-${Date.now()}.sqlite`);

      // 1. Initialize file-backed database and insert data
      _reset();
      await initDatabase(tempDbPath);

      const trace = auditService.createInteraction('tg-persist-test-100', 'File persistence test');
      auditService.addSecurityEvent({
        trace_id: trace.trace_id,
        stage: 'prompt',
        event_type: 'persistent_threat',
        severity: 'high',
        policy_decision: 'flag',
        reason: 'Testing file-backed persistence',
      });

      // 2. Close and unload from memory
      close();

      // Ensure file exists on disk
      assert.ok(fs.existsSync(tempDbPath), 'Database file must exist on disk');
      const stats = fs.statSync(tempDbPath);
      assert.ok(stats.size > 0, 'Database file must have non-zero size');

      // 3. Reopen the database from the disk file
      _reset();
      await initDatabase(tempDbPath);

      const restoredTrace = auditService.getTrace('tg-persist-test-100');
      assert.ok(restoredTrace, 'Trace must survive database reopen');
      assert.equal(restoredTrace.interaction.trace_id, 'tg-persist-test-100');
      assert.equal(restoredTrace.events.length, 1);
      assert.equal(restoredTrace.events[0].event_type, 'persistent_threat');

      // Cleanup
      close();
      _reset();
      try { fs.unlinkSync(tempDbPath); } catch {}
      // Re-init in-memory for subsequent tests
      await initDatabase(':memory:');
    });
  });

  // ---------------------------------------------------------------------------
  // 13. Retrieval record persistence (B4)
  // ---------------------------------------------------------------------------
  describe('13. Retrieval-Provenance Storage Support (B4)', () => {
    it('should persist and query retrieval records with provenance metadata', () => {
      const traceId = auditService.createInteraction(null, 'Retrieval test').trace_id;

      const retId = auditService.addRetrievalRecord({
        trace_id: traceId,
        source_id: 'kb-policy-handbook',
        source_label: 'Corporate Policy Handbook v2',
        source_version: '2.1.0',
        source_hash: 'sha256-abc123def456',
        chunk_id: 'chunk-42',
        chunk_hash: 'sha256-chunk42hash',
        retrieval_order: 1,
        relevance_score: 0.94,
        trust_metadata: { source_tier: 'internal_approved', author: 'compliance-team' },
        included_in_model_context: 1,
        redacted_excerpt: 'Employees must adhere to data security guidelines...',
      });

      assert.ok(retId.startsWith('ret-'));

      const records = auditService.listRetrievalRecords(traceId);
      assert.equal(records.length, 1);
      assert.equal(records[0].source_id, 'kb-policy-handbook');
      assert.equal(records[0].relevance_score, 0.94);
      assert.equal(records[0].included_in_model_context, 1);

      // Verify attached in getTrace
      const fullTrace = auditService.getTrace(traceId);
      assert.equal(fullTrace.retrieval_records.length, 1);
    });
  });

  // ---------------------------------------------------------------------------
  // 14 & 15. Tool-event state validation and unknown outcomes (B5)
  // ---------------------------------------------------------------------------
  describe('14 & 15. Dedicated Tool-Event Storage (B5)', () => {
    it('should validate tool execution states: proposed, started, succeeded, failed, denied, unknown', () => {
      const traceId = auditService.createInteraction(null, 'Tool test').trace_id;

      for (const outcome of ['proposed', 'started', 'succeeded', 'failed', 'denied', 'unknown']) {
        const id = auditService.addToolEvent({
          trace_id: traceId,
          tool_name: 'search_database',
          sanitized_argument_summary: 'query=security_logs',
          execution_outcome: outcome,
        });
        assert.ok(id.startsWith('tool-'));
      }

      const events = auditService.listToolEvents(traceId);
      assert.equal(events.length, 6);
    });

    it('should reject invalid tool execution outcome', () => {
      const traceId = auditService.createInteraction(null, 'Tool invalid test').trace_id;
      assert.throws(() => {
        auditService.addToolEvent({
          trace_id: traceId,
          tool_name: 'unsafe_tool',
          sanitized_argument_summary: 'arg=1',
          execution_outcome: 'illegal_state',
        });
      }, /Invalid execution_outcome/);
    });
  });

  // ---------------------------------------------------------------------------
  // 16. Attack Lab persistence contracts (B6)
  // ---------------------------------------------------------------------------
  describe('16. Attack Lab Test Run and Result Persistence (B6)', () => {
    it('should create test runs and store individual test results without fabricated metrics', () => {
      const runId = auditService.createTestRun({
        test_suite_version: '1.0.0-injection-benchmark',
        status: 'running',
        test_case_count: 5,
        model_metadata: { model: 'gemma-2b', provider: 'ollama' },
      });
      assert.ok(runId.startsWith('run-'));

      const resId = auditService.addTestResult({
        run_id: runId,
        case_id: 'TC-INJ-001',
        expected_classification: 'prompt_injection_indicator',
        actual_findings: [{ rule_id: 'PI-001' }],
        expected_decision: 'flag',
        actual_decision: 'flag',
        pass_fail_result: 'pass',
        latency_ms: 12.4,
      });
      assert.ok(resId.startsWith('res-'));

      auditService.updateTestRunStatus(runId, 'passed');

      const testRun = auditService.getTestRun(runId);
      assert.equal(testRun.status, 'passed');
      assert.equal(testRun.result_count, 1);
      assert.equal(testRun.results[0].case_id, 'TC-INJ-001');
      assert.equal(testRun.results[0].pass_fail_result, 'pass');
    });
  });

  // ---------------------------------------------------------------------------
  // 17 & 18. Pagination and filtering
  // ---------------------------------------------------------------------------
  describe('17 & 18. Validated Pagination and Event Filtering (B7)', () => {
    it('should support page, limit, and compute real total_pages', async () => {
      // Ensure test events exist for pagination
      const trace = auditService.createInteraction(null, 'Pagination seed trace');
      auditService.addSecurityEvent({ trace_id: trace.trace_id, stage: 'prompt', event_type: 'page_test_1' });
      auditService.addSecurityEvent({ trace_id: trace.trace_id, stage: 'output', event_type: 'page_test_2' });
      auditService.addSecurityEvent({ trace_id: trace.trace_id, stage: 'prompt', event_type: 'page_test_3' });

      const res = await request('GET', '/api/events?limit=2&page=1');
      assert.equal(res.status, 200);
      assert.ok(res.body.pagination);
      assert.equal(res.body.pagination.limit, 2);
      assert.equal(res.body.pagination.page, 1);
      assert.ok(typeof res.body.pagination.total === 'number');
      assert.ok(res.body.pagination.total_pages >= 1);
      assert.ok(res.body.data.length <= 2);
    });

    it('should reject invalid page or limit', async () => {
      const p1 = await request('GET', '/api/events?page=0');
      assert.equal(p1.status, 400);

      const p2 = await request('GET', '/api/events?limit=9999');
      assert.equal(p2.status, 400);
    });

    it('should filter events by severity, stage, and trace_id', async () => {
      const traceId = auditService.createInteraction(null, 'Filter API test').trace_id;
      auditService.addSecurityEvent({ trace_id: traceId, stage: 'prompt', event_type: 'clean', severity: 'info' });
      auditService.addSecurityEvent({ trace_id: traceId, stage: 'output', event_type: 'flagged', severity: 'high' });

      const resHigh = await request('GET', `/api/events?trace_id=${traceId}&severity=high`);
      assert.equal(resHigh.status, 200);
      assert.equal(resHigh.body.data.length, 1);
      assert.equal(resHigh.body.data[0].severity, 'high');
    });
  });

  // ---------------------------------------------------------------------------
  // 19. Stable trace ordering
  // ---------------------------------------------------------------------------
  describe('19. Stable Sequence Ordering for Traces', () => {
    it('should return events ordered strictly by sequence_no ASC in GET /api/traces/:traceId', async () => {
      const createRes = await request('POST', '/api/traces', {});
      const traceId = createRes.body.trace_id;

      auditService.addSecurityEvent({ trace_id: traceId, stage: 'prompt', event_type: 'first' });
      auditService.addSecurityEvent({ trace_id: traceId, stage: 'retrieved_content', event_type: 'second' });
      auditService.addSecurityEvent({ trace_id: traceId, stage: 'output', event_type: 'third' });

      const res = await request('GET', `/api/traces/${traceId}`);
      assert.equal(res.status, 200);
      assert.equal(res.body.events.length, 3);
      assert.equal(res.body.events[0].sequence_no, 1);
      assert.equal(res.body.events[1].sequence_no, 2);
      assert.equal(res.body.events[2].sequence_no, 3);
    });
  });

  // ---------------------------------------------------------------------------
  // 20. Policy precedence & redacted evidence safety
  // ---------------------------------------------------------------------------
  describe('20. Policy Precedence (B8) and Redacted Evidence Safety', () => {
    it('should enforce deterministic policy precedence: block > redact > flag > allow', () => {
      const findings = [
        { rule_id: 'PI-001', category: 'prompt_injection_indicator', severity: 'high', reason: 'Flag injection' },
        { rule_id: 'OS-001', category: 'synthetic_secret_exposure', severity: 'high', reason: 'Redact secret' },
        { rule_id: 'PI-004', category: 'data_exfiltration_indicator', severity: 'high', reason: 'Block exfiltration' },
      ];

      const result = policyEngine.evaluate(findings);
      assert.equal(result.decision, 'block', 'Block must take highest precedence');
    });

    it('should resolve equal-decision ties deterministically via severity and rule_id', () => {
      const findings = [
        { rule_id: 'PI-002', category: 'prompt_injection_indicator', severity: 'medium', reason: 'Medium injection' },
        { rule_id: 'PI-001', category: 'prompt_injection_indicator', severity: 'high', reason: 'High injection' },
      ];

      const result = policyEngine.evaluate(findings);
      assert.equal(result.decision, 'flag');
      assert.equal(result.severity, 'high');
      assert.equal(result.winning_rule, 'PI-001', 'Higher severity finding must win tie-breaker');
    });

    it('should never store raw secrets in audit evidence', async () => {
      const secret = 'DEMO_SECRET_74XQ9';
      const evalRes = await request('POST', '/api/security/evaluate', {
        stage: 'output',
        content: `Here is the token: ${secret} for authentication.`,
      });

      assert.equal(evalRes.status, 200);
      assert.equal(evalRes.body.decision, 'redact');
      assert.ok(!evalRes.body.sanitized_content.includes(secret));

      // Inspect database stored event
      const trace = auditService.getTrace(evalRes.body.trace_id);
      assert.ok(trace.events.length > 0);
      const storedEvent = trace.events[0];
      assert.ok(!storedEvent.redacted_evidence.includes(secret),
        'Stored audit evidence must not contain the raw secret');
      assert.ok(storedEvent.redacted_evidence.includes('***[DEMO_SECRET]'));
    });
  });
});
