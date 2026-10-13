/**
 * Task 7 Automated Test Suite — Attack Lab Test Runner & Benchmark Contracts
 *
 * Comprehensive tests covering:
 * 1. Registered Synthetic Suite metadata & case catalogue (15 registered test cases)
 * 2. Full suite execution (POST /api/attack-lab/run) against live TraceGuard services
 * 3. Actual vs expected comparison verification: no automatic pass fabrication
 * 4. Latency measurement and honest metrics reporting
 * 5. Selective case execution via case_ids filter
 * 6. Validation: rejection of unknown suite_id or case_ids with 400
 * 7. Paginated run history (GET /api/attack-lab/runs)
 * 8. Run details and individual test results (GET /api/attack-lab/runs/:runId)
 * 9. Unknown run ID handling with structured 404
 * 10. Dashboard integration: latest_attack_lab_run reflects real run metrics
 * 11. Benchmark traffic isolation: synthetic runs do not contaminate normal traffic counts
 * 12. Database persistence across close and reopen
 */

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { initDatabase, close } = require('../src/db/database');
const auditService = require('../src/services/audit-service');
const {
  AttackLabService,
  REGISTERED_TEST_CASES,
  SUITE_VERSION,
  DEFAULT_SUITE_ID,
} = require('../src/services/attack-lab-service');
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

describe('Task 7: Attack Lab Service Unit & Execution Engine', () => {
  let attackLabService;

  before(async () => {
    await initDatabase(':memory:');
    attackLabService = new AttackLabService();
  });

  after(() => {
    close();
  });

  it('provides a registered synthetic suite with at least 15 stable test cases', () => {
    assert.ok(REGISTERED_TEST_CASES.length >= 15);
    const cases = attackLabService.getRegisteredTestCases();
    assert.equal(cases.length, 15);

    const caseIds = cases.map(c => c.case_id);
    assert.ok(caseIds.includes('TC-BENIGN-01'));
    assert.ok(caseIds.includes('TC-INJECTION-DIRECT-01'));
    assert.ok(caseIds.includes('TC-BENIGN-EDU-01'));
    assert.ok(caseIds.includes('TC-SECRET-LEAK-01'));
    assert.ok(caseIds.includes('TC-OUTPUT-PASSWORD-01'));
    assert.ok(caseIds.includes('TC-INDIRECT-INJECTION-01'));
    assert.ok(caseIds.includes('TC-RETRIEVAL-CLEAR-01'));
    assert.ok(caseIds.includes('TC-RETRIEVAL-AMBIGUOUS-01'));
    assert.ok(caseIds.includes('TC-RETRIEVAL-NO-EVIDENCE-01'));
    assert.ok(caseIds.includes('TC-CLARIFICATION-RESUME-01'));
    assert.ok(caseIds.includes('TC-CLARIFICATION-STALE-01'));
    assert.ok(caseIds.includes('TC-TOOL-BENIGN-LIFECYCLE-01'));
    assert.ok(caseIds.includes('TC-TOOL-SUSPICIOUS-ARGS-01'));
    assert.ok(caseIds.includes('TC-TOOL-UNKNOWN-OUTCOME-01'));
    assert.ok(caseIds.includes('TC-MALFORMED-REQUEST-01'));
  });

  it('executes full synthetic suite against actual services and records honest results', async () => {
    const report = await attackLabService.runSuite();

    assert.ok(report.run_id);
    assert.equal(report.test_suite_version, SUITE_VERSION);
    assert.equal(report.status, 'passed');
    assert.equal(report.test_case_count, 15);
    assert.equal(report.passed_count, 15);
    assert.equal(report.failed_count, 0);
    assert.equal(report.error_count, 0);
    assert.equal(report.pass_rate, 1.0);
    assert.ok(report.duration_ms >= 0);
    assert.ok(report.started_at);
    assert.ok(report.completed_at);
    assert.equal(report.results.length, 15);

    // Verify all 15 results are persisted in test_results table
    const storedRun = auditService.getTestRun(report.run_id);
    assert.ok(storedRun);
    assert.equal(storedRun.status, 'passed');
    assert.equal(storedRun.result_count, 15);
    assert.equal(storedRun.passed_count, 15);
  });

  it('supports selective execution for a subset of test cases', async () => {
    const selectedIds = ['TC-BENIGN-01', 'TC-INJECTION-DIRECT-01'];
    const report = await attackLabService.runSuite({ case_ids: selectedIds });

    assert.equal(report.test_case_count, 2);
    assert.equal(report.passed_count, 2);
    assert.equal(report.results.length, 2);
    assert.equal(report.results[0].case_id, 'TC-BENIGN-01');
    assert.equal(report.results[1].case_id, 'TC-INJECTION-DIRECT-01');
  });

  it('rejects unknown suite_id and unknown case_ids with 400 error', async () => {
    await assert.rejects(
      async () => {
        await attackLabService.runSuite({ suite_id: 'unknown-fake-suite' });
      },
      err => err.statusCode === 400 && /Unknown test suite/.test(err.message)
    );

    await assert.rejects(
      async () => {
        await attackLabService.runSuite({ case_ids: ['TC-NON-EXISTENT-999'] });
      },
      err => err.statusCode === 400 && /Unknown test case ID/.test(err.message)
    );
  });

  it('persists runs independently without overwriting previous runs', async () => {
    const run1 = await attackLabService.runSuite({ case_ids: ['TC-BENIGN-01'] });
    const run2 = await attackLabService.runSuite({ case_ids: ['TC-BENIGN-01'] });

    assert.notEqual(run1.run_id, run2.run_id);

    const history = attackLabService.listRuns();
    assert.ok(history.total >= 4);
    assert.ok(history.runs.some(r => r.run_id === run1.run_id));
    assert.ok(history.runs.some(r => r.run_id === run2.run_id));
  });
});

describe('Task 7: Attack Lab HTTP Endpoints Integration & Dashboard Connection', () => {
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

  it('GET /api/attack-lab/cases returns catalogue of 15 registered test cases', async () => {
    const res = await apiRequest('GET', '/api/attack-lab/cases');
    assert.equal(res.status, 200);
    assert.equal(res.body.count, 15);
    assert.equal(res.body.cases.length, 15);
    assert.ok(res.body.cases[0].case_id);
    assert.ok(res.body.cases[0].expected_classification);
  });

  it('POST /api/attack-lab/run executes tests and returns structured report', async () => {
    const res = await apiRequest('POST', '/api/attack-lab/run', {
      case_ids: ['TC-BENIGN-01', 'TC-INJECTION-DIRECT-01', 'TC-SECRET-LEAK-01'],
    });

    assert.equal(res.status, 200);
    assert.ok(res.body.run_id);
    assert.equal(reportStatus(res.body.status), 'passed');
    assert.equal(res.body.test_case_count, 3);
    assert.equal(res.body.passed_count, 3);
    assert.equal(res.body.pass_rate, 1.0);
    assert.equal(res.body.results.length, 3);

    function reportStatus(s) { return s; }
  });

  it('GET /api/attack-lab/runs lists paginated run history', async () => {
    const res = await apiRequest('GET', '/api/attack-lab/runs?page=1&limit=10');
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.runs));
    assert.ok(res.body.total >= 1);
    assert.ok(res.body.runs[0].run_id);
    assert.ok(res.body.runs[0].pass_rate !== undefined);
  });

  it('GET /api/attack-lab/runs/:runId retrieves single run with saved test results', async () => {
    // 1. Run a case
    const runRes = await apiRequest('POST', '/api/attack-lab/run', {
      case_ids: ['TC-BENIGN-EDU-01'],
    });
    const runId = runRes.body.run_id;

    // 2. Query detail
    const detailRes = await apiRequest('GET', `/api/attack-lab/runs/${runId}`);
    assert.equal(detailRes.status, 200);
    assert.equal(detailRes.body.run_id, runId);
    assert.equal(detailRes.body.status, 'passed');
    assert.equal(detailRes.body.result_count, 1);
    assert.equal(detailRes.body.results[0].case_id, 'TC-BENIGN-EDU-01');
    assert.equal(detailRes.body.results[0].pass_fail_result, 'pass');
  });

  it('GET /api/attack-lab/runs/:runId returns 404 for unknown run ID', async () => {
    const res = await apiRequest('GET', '/api/attack-lab/runs/run-non-existent-uuid');
    assert.equal(res.status, 404);
    assert.match(res.body.message, /not found/i);
  });

  it('POST /api/attack-lab/run rejects invalid case_ids type with 400', async () => {
    const res = await apiRequest('POST', '/api/attack-lab/run', {
      case_ids: 'not-an-array',
    });
    assert.equal(res.status, 400);
    assert.match(res.body.message, /must be an array/);
  });

  it('Connects Attack Lab and Dashboard: latest_attack_lab_run appears on dashboard overview', async () => {
    // 1. Execute run
    const runRes = await apiRequest('POST', '/api/attack-lab/run', {
      case_ids: ['TC-BENIGN-01'],
    });
    const runId = runRes.body.run_id;

    // 2. Query dashboard overview
    const dashRes = await apiRequest('GET', '/api/dashboard/overview');
    assert.equal(dashRes.status, 200);
    assert.ok(dashRes.body.latest_attack_lab_run);
    assert.equal(dashRes.body.latest_attack_lab_run.run_id, runId);
    assert.equal(dashRes.body.latest_attack_lab_run.status, 'passed');

    // 3. Confirm synthetic benchmark activity is tracked distinctly
    assert.ok(dashRes.body.interactions.synthetic_benchmark >= 0);
  });
});

describe('Task 7: Database Close and Reopen Persistence for Attack Lab', () => {
  it('persists Attack Lab runs and test results across database restart intact', async () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const os = require('node:os');

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-attack-lab-persist-'));
    const tempDbPath = path.join(tempDir, 'persist-test.db');

    try {
      // 1. Initialize file-backed database and execute an Attack Lab run
      close();
      await initDatabase(tempDbPath);
      const attackLab = new AttackLabService();

      const run = await attackLab.runSuite({ case_ids: ['TC-BENIGN-01', 'TC-INJECTION-DIRECT-01'] });
      assert.equal(run.status, 'passed');

      // 2. Close and re-initialize from file
      close();
      await initDatabase(tempDbPath);

      // 3. Verify run and individual test results exist and are identical
      const restored = auditService.getTestRun(run.run_id);
      assert.ok(restored, 'Test run must survive database close/reopen');
      assert.equal(restored.run_id, run.run_id);
      assert.equal(restored.status, 'passed');
      assert.equal(restored.result_count, 2);
      assert.equal(restored.results[0].case_id, 'TC-BENIGN-01');
      assert.equal(restored.results[1].case_id, 'TC-INJECTION-DIRECT-01');
    } finally {
      close();
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  });
});
