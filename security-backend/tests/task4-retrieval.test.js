/**
 * Task 4 Automated Test Suite
 *
 * Comprehensive tests covering:
 * 1. Pluggable Retrieval Provider contract & SHA-256 content hashes
 * 2. Deterministic lexical scoring, normalization, and stable tie-breaking
 * 3. Case 1: Single clearly relevant source ('selected')
 * 4. Case 2: Material ambiguity & clarification ('needs_clarification')
 * 5. Case 3: No relevant evidence ('no_relevant_evidence')
 * 6. Case 4: Indirect injection inspection in retrieved content (PI-006, policy, security event)
 * 7. Accurate retrieval provenance persistence in retrieval_records (included_in_model_context: 0)
 * 8. Clarification workflow & trace resumption (POST /api/retrieval/clarify)
 * 9. Repeated submissions (idempotency) and invalid/stale/forged selections
 * 10. Trace lifecycle state machine validation (needs_clarification -> processing, terminal rejection)
 * 11. Clarification session persistence across database restart
 * 12. End-to-end HTTP API endpoints (search, clarify, session inspect, records)
 */

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { initDatabase, close } = require('../src/db/database');
const {
  SyntheticLocalRetrievalProvider,
  computeSha256,
} = require('../src/services/retrieval-provider');
const {
  RetrievalService,
  computeLexicalScore,
  tokenize,
  createSanitizedExcerpt,
} = require('../src/services/retrieval-service');
const auditService = require('../src/services/audit-service');
const createApp = require('../src/app');

let server;
let baseUrl;

/**
 * Helper: make an HTTP request to the test server.
 */
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

describe('Task 4: Retrieval Provider & Lexical Scoring Mechanics', () => {
  it('computes standard SHA-256 hashes accurately over canonical UTF-8 text', () => {
    const text = 'TraceGuard Security Baseline v3.0';
    const hash = computeSha256(text);
    assert.equal(typeof hash, 'string');
    assert.equal(hash.length, 64);
    assert.match(hash, /^[0-9a-f]{64}$/);
    // Deterministic: same text yields exact same hash
    assert.equal(computeSha256(text), hash);
  });

  it('SyntheticLocalRetrievalProvider initializes corpus with valid metadata and content hashes', () => {
    const provider = new SyntheticLocalRetrievalProvider();
    const source = provider.getSource('doc-security-hardening');
    assert.ok(source, 'Should retrieve document by source_id');
    assert.equal(source.source_id, 'doc-security-hardening');
    assert.equal(source.chunk_id, 'chunk-sec-01');
    assert.ok(source.text.length > 50);
    assert.equal(source.source_hash, computeSha256(source.text));
    assert.equal(source.chunk_hash, computeSha256(source.text));
    assert.ok(source.trust_metadata && typeof source.trust_metadata === 'object');
  });

  it('tokenizes text by stripping stopwords and punctuation cleanly', () => {
    const tokens = tokenize('What is the minimum TLS version and password policy?');
    assert.ok(!tokens.includes('what'));
    assert.ok(!tokens.includes('is'));
    assert.ok(!tokens.includes('the'));
    assert.ok(!tokens.includes('and'));
    assert.ok(tokens.includes('minimum'));
    assert.ok(tokens.includes('tls'));
    assert.ok(tokens.includes('version'));
    assert.ok(tokens.includes('password'));
    assert.ok(tokens.includes('policy'));
  });

  it('computes honest, bounded lexical scores between 0.0 and 1.0', () => {
    const docText = 'All internal communication must enforce minimum TLS version 1.3 with strong ciphers.';
    const highMatch = computeLexicalScore('minimum TLS version 1.3', docText);
    const zeroMatch = computeLexicalScore('pasta carbonara recipe', docText);

    assert.ok(highMatch > 0.6, `Expected high lexical match, got ${highMatch}`);
    assert.equal(zeroMatch, 0.0);
    assert.ok(highMatch <= 1.0 && highMatch >= 0.0);
  });

  it('sanitizes excerpts and redacts sensitive credentials before display or persistence', () => {
    const mockApiKey = ['sk', 'test', 'liveauthkey0123456789abcdef'].join('_');
    const sensitive = `Configuration key is ${mockApiKey} for staging access.`;
    const excerpt = createSanitizedExcerpt(sensitive);
    assert.ok(!excerpt.includes(mockApiKey));
    assert.ok(excerpt.includes('[REDACTED:API_KEY]'));
  });
});

describe('Task 4: Retrieval Sufficiency & Decision Logic (Unit/Service Layer)', () => {
  let retrievalService;
  let testTrace;

  before(async () => {
    await initDatabase(':memory:');
    retrievalService = new RetrievalService();
  });

  after(() => {
    close();
  });

  beforeEach(() => {
    testTrace = auditService.createInteraction(null, 'Unit test trace');
  });

  it('Case 1: Selects single clearly relevant source when score margin is sufficient', async () => {
    const result = await retrievalService.search({
      query: 'minimum TLS version and password length policy',
      trace_id: testTrace.trace_id,
    });

    assert.equal(result.retrieval_status, 'selected');
    assert.equal(result.needs_clarification, false);
    assert.equal(result.session_id, null);
    assert.ok(result.selected_candidate, 'Must have selected candidate');
    assert.equal(result.selected_candidate.source_id, 'doc-security-hardening');
    assert.ok(result.selected_candidate.relevance_score >= 0.25);

    // Verify trace status remained 'processing'
    const trace = auditService.getInteraction(testTrace.trace_id);
    assert.equal(trace.status, 'processing');
  });

  it('Case 2: Detects material ambiguity and requests clarification with session persistence', async () => {
    const result = await retrievalService.search({
      query: 'enterprise single sign-on authentication configuration',
      trace_id: testTrace.trace_id,
    });

    assert.equal(result.retrieval_status, 'needs_clarification');
    assert.equal(result.needs_clarification, true);
    assert.ok(result.session_id, 'Must return session_id');
    assert.ok(result.clarification_question, 'Must return clarification question');
    assert.ok(Array.isArray(result.candidates) && result.candidates.length >= 2);

    // Check competing sources OAuth2 and SAML are both returned as candidates
    const sourceIds = result.candidates.map(c => c.source_id);
    assert.ok(sourceIds.includes('doc-auth-oauth2'));
    assert.ok(sourceIds.includes('doc-auth-saml'));

    // Verify trace lifecycle transitioned to 'needs_clarification'
    const trace = auditService.getInteraction(testTrace.trace_id);
    assert.equal(trace.status, 'needs_clarification');

    // Verify clarification session was persisted in SQLite
    const session = auditService.getClarificationSession(result.session_id);
    assert.ok(session, 'Clarification session must be stored in database');
    assert.equal(session.trace_id, testTrace.trace_id);
    assert.equal(session.status, 'pending');
    assert.equal(session.candidates.length, result.candidates.length);
  });

  it('Case 3: Returns no_relevant_evidence when all candidate scores fall below threshold', async () => {
    const result = await retrievalService.search({
      query: 'traditional Italian recipe for homemade pasta carbonara with guanciale',
      trace_id: testTrace.trace_id,
    });

    assert.equal(result.retrieval_status, 'no_relevant_evidence');
    assert.equal(result.needs_clarification, false);
    assert.equal(result.selected_candidate, null);
    assert.ok(result.decision_reason.includes('minimum relevance threshold'));
  });

  it('Case 4: Inspects candidate content for indirect prompt injection (PI-006) and logs security event', async () => {
    const result = await retrievalService.search({
      query: 'partner vendor integration instructions and script tag',
      trace_id: testTrace.trace_id,
    });

    assert.ok(result.has_indirect_injection, 'Must detect indirect injection in retrieved document');
    const injectedCandidate = result.candidates.find(c => c.source_id === 'doc-retrieved-injection');
    assert.ok(injectedCandidate, 'Should evaluate injection candidate');
    assert.ok(injectedCandidate.has_security_findings, 'Candidate must flag security findings');
    assert.ok(injectedCandidate.is_blocked, 'Policy decision must block candidate from selection');

    // Verify security event was recorded in SQLite
    const events = auditService.listEvents({ trace_id: testTrace.trace_id, stage: 'retrieval_inspection' });
    assert.ok(events.length > 0, 'Must record retrieval inspection security event');
    const pi006Event = events.find(e => e.rule_id === 'PI-006');
    assert.ok(pi006Event, 'Must record PI-006 indirect injection event');
    assert.equal(pi006Event.event_type, 'scan_retrieval');
    assert.equal(pi006Event.policy_decision, 'block');
    assert.equal(pi006Event.source_id, 'doc-retrieved-injection');
  });

  it('Persists accurate retrieval provenance in retrieval_records with included_in_model_context = 0', async () => {
    await retrievalService.search({
      query: 'minimum TLS version and password policy',
      trace_id: testTrace.trace_id,
    });

    const records = auditService.listRetrievalRecords(testTrace.trace_id);
    assert.ok(records.length > 0, 'Must insert retrieval records');
    for (const r of records) {
      assert.equal(r.trace_id, testTrace.trace_id);
      assert.ok(r.source_id);
      assert.ok(r.source_hash);
      assert.ok(r.chunk_hash);
      // Accurately reflects that no LLM inference context was dispatched
      assert.equal(r.included_in_model_context, 0);
      assert.ok(r.retrieval_order >= 1);
    }
  });
});

describe('Task 4: Clarification Workflow, Stale Detection, and Trace Resumption', () => {
  let retrievalService;
  let provider;

  before(async () => {
    await initDatabase(':memory:');
    provider = new SyntheticLocalRetrievalProvider();
    retrievalService = new RetrievalService({ provider });
  });

  after(() => {
    close();
  });

  beforeEach(() => {
    provider.resetCorpus();
  });

  it('resolves pending clarification session and resumes trace back to processing', async () => {
    const trace = auditService.createInteraction(null, 'Ambiguity test trace');
    const searchRes = await retrievalService.search({
      query: 'enterprise single sign-on authentication configuration',
      trace_id: trace.trace_id,
    });

    assert.equal(searchRes.retrieval_status, 'needs_clarification');
    const chosenCandidate = searchRes.candidates[0];

    // Submit clarification
    const clarifyRes = await retrievalService.clarify({
      session_id: searchRes.session_id,
      candidate_id: chosenCandidate.candidate_id,
    });

    assert.equal(clarifyRes.status, 'resolved');
    assert.equal(clarifyRes.trace_status, 'processing');
    assert.equal(clarifyRes.trace_id, trace.trace_id, 'Must preserve original trace ID');
    assert.equal(clarifyRes.selected_candidate.candidate_id, chosenCandidate.candidate_id);

    // Verify trace in database is back in 'processing' state
    const updatedTrace = auditService.getInteraction(trace.trace_id);
    assert.equal(updatedTrace.status, 'processing');

    // Verify clarification session in database is marked 'resolved'
    const session = auditService.getClarificationSession(searchRes.session_id);
    assert.equal(session.status, 'resolved');
    assert.equal(session.selected_candidate_id, chosenCandidate.candidate_id);
    assert.ok(session.resolved_at);
  });

  it('safely handles repeated clarification submission idempotently', async () => {
    const trace = auditService.createInteraction(null, 'Idempotency trace');
    const searchRes = await retrievalService.search({
      query: 'enterprise single sign-on authentication configuration',
      trace_id: trace.trace_id,
    });
    const chosenCandidate = searchRes.candidates[0];

    // First call
    await retrievalService.clarify({
      session_id: searchRes.session_id,
      candidate_id: chosenCandidate.candidate_id,
    });

    // Repeated call with same candidate
    const repeatRes = await retrievalService.clarify({
      session_id: searchRes.session_id,
      candidate_id: chosenCandidate.candidate_id,
    });

    assert.equal(repeatRes.status, 'resolved');
    assert.ok(repeatRes.message.includes('idempotent'));
  });

  it('rejects candidate choice that does not belong to the session candidate set', async () => {
    const trace = auditService.createInteraction(null, 'Forged candidate trace');
    const searchRes = await retrievalService.search({
      query: 'enterprise single sign-on authentication configuration',
      trace_id: trace.trace_id,
    });

    await assert.rejects(
      async () => {
        await retrievalService.clarify({
          session_id: searchRes.session_id,
          candidate_id: 'cand-forged-fake-id-999',
        });
      },
      err => err.statusCode === 400 && /Selection rejected/.test(err.message)
    );
  });

  it('detects modified/stale source content and rejects stale clarification with 409 Conflict', async () => {
    const trace = auditService.createInteraction(null, 'Stale test trace');
    const searchRes = await retrievalService.search({
      query: 'enterprise single sign-on authentication configuration',
      trace_id: trace.trace_id,
    });
    const chosen = searchRes.candidates[0];

    // Mutate source text in provider to simulate external document update
    provider.setSourceText(chosen.source_id, chosen.chunk_id, 'Completely modified text content invalidating previous hash');

    await assert.rejects(
      async () => {
        await retrievalService.clarify({
          session_id: searchRes.session_id,
          candidate_id: chosen.candidate_id,
        });
      },
      err => err.statusCode === 409 && /Stale evidence rejected/.test(err.message)
    );

    // Verify session status updated to 'stale'
    const session = auditService.getClarificationSession(searchRes.session_id);
    assert.equal(session.status, 'stale');
  });

  it('rejects clarification attempt on a terminal trace', async () => {
    const trace = auditService.createInteraction(null, 'Terminal trace');
    const searchRes = await retrievalService.search({
      query: 'enterprise single sign-on authentication configuration',
      trace_id: trace.trace_id,
    });
    const chosen = searchRes.candidates[0];

    // Force trace to terminal status 'cancelled'
    auditService.updateInteractionStatus(trace.trace_id, 'cancelled');

    await assert.rejects(
      async () => {
        await retrievalService.clarify({
          session_id: searchRes.session_id,
          candidate_id: chosen.candidate_id,
        });
      },
      err => err.statusCode === 400 && /terminal status/.test(err.message)
    );
  });
});

describe('Task 4: HTTP API Endpoints Integration', () => {
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

  it('POST /api/retrieval/search validates request and creates trace when omitted', async () => {
    const res = await apiRequest('POST', '/api/retrieval/search', {
      query: 'minimum TLS version and password policy',
    });

    assert.equal(res.status, 200);
    assert.ok(res.body.trace_id);
    assert.equal(res.body.retrieval_status, 'selected');
    assert.equal(res.body.needs_clarification, false);
    assert.ok(res.body.selected_candidate);
  });

  it('POST /api/retrieval/search rejects invalid or empty queries with 400', async () => {
    const emptyRes = await apiRequest('POST', '/api/retrieval/search', { query: '   ' });
    assert.equal(emptyRes.status, 400);

    const missingRes = await apiRequest('POST', '/api/retrieval/search', {});
    assert.equal(missingRes.status, 400);
  });

  it('POST /api/retrieval/search triggers clarification on ambiguity and persists session', async () => {
    const res = await apiRequest('POST', '/api/retrieval/search', {
      query: 'enterprise single sign-on authentication configuration',
    });

    assert.equal(res.status, 200);
    assert.equal(res.body.retrieval_status, 'needs_clarification');
    assert.equal(res.body.needs_clarification, true);
    assert.ok(res.body.session_id);
    assert.ok(res.body.candidates.length >= 2);

    const sessionId = res.body.session_id;
    const chosenCandidateId = res.body.candidates[0].candidate_id;

    // Test GET /api/retrieval/sessions/:sessionId
    const sessionRes = await apiRequest('GET', `/api/retrieval/sessions/${sessionId}`);
    assert.equal(sessionRes.status, 200);
    assert.equal(sessionRes.body.session_id, sessionId);
    assert.equal(sessionRes.body.status, 'pending');

    // Test POST /api/retrieval/clarify
    const clarifyRes = await apiRequest('POST', '/api/retrieval/clarify', {
      session_id: sessionId,
      candidate_id: chosenCandidateId,
    });

    assert.equal(clarifyRes.status, 200);
    assert.equal(clarifyRes.body.status, 'resolved');
    assert.equal(clarifyRes.body.trace_status, 'processing');
    assert.equal(clarifyRes.body.selected_candidate.candidate_id, chosenCandidateId);

    // Test GET /api/retrieval/records/:traceId
    const recordsRes = await apiRequest('GET', `/api/retrieval/records/${res.body.trace_id}`);
    assert.equal(recordsRes.status, 200);
    assert.ok(recordsRes.body.total_records >= 2);
  });

  it('POST /api/retrieval/clarify returns 404 for non-existent session_id', async () => {
    const res = await apiRequest('POST', '/api/retrieval/clarify', {
      session_id: 'cs-nonexistent-session-000',
      candidate_id: 'cand-any',
    });
    assert.equal(res.status, 404);
  });

  it('POST /api/retrieval/search rejects queries exceeding maximum length of 1000 characters', async () => {
    const overlyLongQuery = 'authentication '.repeat(100);
    const res = await apiRequest('POST', '/api/retrieval/search', {
      query: overlyLongQuery,
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.message.includes('1000 characters'));
  });

  it('POST /api/retrieval/search rejects malformed trace_id with 400', async () => {
    const res = await apiRequest('POST', '/api/retrieval/search', {
      query: 'minimum TLS version',
      trace_id: 'invalid-trace-id-not-uuid',
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.message.includes('Invalid trace_id format'));
  });

  it('clarification sessions survive database close and reopen (restart recovery)', async () => {
    const fs = require('fs');
    const path = require('path');
    const os = require('os');

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-clarify-persist-'));
    const tempDbPath = path.join(tempDir, 'persist-test.db');

    try {
      // 1. Initialize file-backed database
      close();
      await initDatabase(tempDbPath);

      const trace = auditService.createInteraction(null, 'Restart recovery trace');
      const session = auditService.createClarificationSession({
        session_id: 'cs-restart-test-01',
        trace_id: trace.trace_id,
        query: 'enterprise single sign-on authentication configuration',
        candidates: [
          { candidate_id: 'cand-1', source_id: 'doc-auth-oauth2', relevance_score: 0.8 },
          { candidate_id: 'cand-2', source_id: 'doc-auth-saml', relevance_score: 0.78 },
        ],
        clarification_prompt: 'Select OAuth2 or SAML',
      });

      assert.equal(session.status, 'pending');

      // 2. Simulate server restart: close database and re-initialize from same file
      close();
      await initDatabase(tempDbPath);

      // 3. Verify session was restored intact
      const restored = auditService.getClarificationSession('cs-restart-test-01');
      assert.ok(restored, 'Clarification session must survive database close/reopen');
      assert.equal(restored.status, 'pending');
      assert.equal(restored.trace_id, trace.trace_id);
      assert.equal(restored.candidates.length, 2);
      assert.equal(restored.clarification_prompt, 'Select OAuth2 or SAML');
    } finally {
      close();
      try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  });
});
