'use strict';

const crypto = require('node:crypto');
const { SyntheticLocalRetrievalProvider, computeSha256 } = require('./retrieval-provider');
const { scanPrompt } = require('./prompt-scanner');
const { redactOutput } = require('./output-scanner');
const { evaluatePolicy } = require('./policy-engine');
const auditService = require('./audit-service');
const {
  generateCandidateId,
  generateEventId,
  isValidTraceId,
} = require('./trace-service');

/**
 * Standard English stopwords for lexical normalization.
 */
const STOPWORDS = new Set([
  'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and', 'any',
  'are', 'aren\'t', 'as', 'at', 'be', 'because', 'been', 'before', 'being', 'below',
  'between', 'both', 'but', 'by', 'can', 'can\'t', 'cannot', 'could', 'couldn\'t',
  'did', 'didn\'t', 'do', 'does', 'doesn\'t', 'doing', 'don\'t', 'down', 'during',
  'each', 'few', 'for', 'from', 'further', 'had', 'hadn\'t', 'has', 'hasn\'t',
  'have', 'haven\'t', 'having', 'he', 'her', 'here', 'hers', 'herself', 'him',
  'himself', 'his', 'how', 'i', 'if', 'in', 'into', 'is', 'isn\'t', 'it', 'it\'s',
  'its', 'itself', 'let\'s', 'me', 'more', 'most', 'mustn\'t', 'my', 'myself',
  'no', 'nor', 'not', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'ought',
  'our', 'ours', 'ourselves', 'out', 'over', 'own', 'same', 'shan\'t', 'she',
  'should', 'shouldn\'t', 'so', 'some', 'such', 'than', 'that', 'the', 'their',
  'theirs', 'them', 'themselves', 'then', 'there', 'these', 'they', 'this',
  'those', 'through', 'to', 'too', 'under', 'until', 'up', 'very', 'was',
  'wasn\'t', 'we', 'were', 'weren\'t', 'what', 'when', 'where', 'which', 'while',
  'who', 'whom', 'why', 'with', 'won\'t', 'would', 'wouldn\'t', 'you', 'your',
  'yours', 'yourself', 'yourselves'
]);

/**
 * Tokenize text into lowercased non-stopword tokens.
 * @param {string} text
 * @returns {Array<string>}
 */
function tokenize(text) {
  if (!text || typeof text !== 'string') return [];
  const words = text.toLowerCase().match(/[a-z0-9_.-]+/g) || [];
  return words.filter(w => w.length > 1 && !STOPWORDS.has(w));
}

/**
 * Compute honest lexical similarity score between query and document text.
 * Formula balances term coverage, term frequency, and exact phrase match.
 * Result is strictly bounded in [0.0, 1.0].
 *
 * @param {string} query
 * @param {string} text
 * @returns {number}
 */
function computeLexicalScore(query, text) {
  if (!query || !text) return 0.0;
  const qTokens = tokenize(query);
  if (qTokens.length === 0) return 0.0;

  const dTokens = tokenize(text);
  if (dTokens.length === 0) return 0.0;

  const dTokenSet = new Set(dTokens);
  let matchedCount = 0;
  for (const q of qTokens) {
    if (dTokenSet.has(q)) {
      matchedCount++;
    }
  }

  // 1. Term coverage: fraction of unique query terms present
  const uniqueQ = Array.from(new Set(qTokens));
  const coverage = uniqueQ.reduce((acc, q) => acc + (dTokenSet.has(q) ? 1 : 0), 0) / uniqueQ.length;

  // 2. Term frequency weight: count of total occurrences of query terms in doc
  let termFreq = 0;
  for (const t of dTokens) {
    if (uniqueQ.includes(t)) termFreq++;
  }
  const freqRatio = Math.min(1.0, termFreq / (qTokens.length * 2));

  // 3. Substring / phrase match bonus: if full normalized query phrase appears in doc
  const normQ = query.trim().toLowerCase();
  const normD = text.toLowerCase();
  const phraseBonus = normD.includes(normQ) ? 0.2 : 0.0;

  // Composite score: 60% coverage + 25% frequency + 15% phrase bonus
  const composite = (0.60 * coverage) + (0.25 * freqRatio) + (0.15 * phraseBonus);
  return Math.min(1.0, Math.max(0.0, parseFloat(composite.toFixed(4))));
}

/**
 * Sanitize candidate excerpt: mask any sensitive keys/tokens and truncate to length.
 * @param {string} text
 * @param {number} [maxLength=220]
 * @returns {string}
 */
function createSanitizedExcerpt(text, maxLength = 220) {
  if (!text) return '';
  const redacted = redactOutput(text).redacted_text;
  if (redacted.length <= maxLength) return redacted;
  return redacted.slice(0, maxLength).trim() + '...';
}

/**
 * Retrieval Runtime Service.
 */
class RetrievalService {
  constructor(options = {}) {
    this.provider = options.provider || new SyntheticLocalRetrievalProvider();
    this.minRelevanceThreshold = options.minRelevanceThreshold ?? 0.25;
    this.ambiguityMarginThreshold = options.ambiguityMarginThreshold ?? 0.10;
    this.maxCandidates = options.maxCandidates ?? 5;
    this.maxQueryLength = options.maxQueryLength ?? 1000;
  }

  /**
   * Execute retrieval search for a query linked to an active trace.
   *
   * @param {Object} params
   * @param {string} params.query
   * @param {string} [params.trace_id]
   * @param {Object} [params.options]
   * @returns {Object} Structured retrieval response
   */
  async search({ query, trace_id = null, options = {} }) {
    // 1. Input validation & bounded inputs
    if (!query || typeof query !== 'string' || query.trim().length === 0) {
      const err = new Error('Query parameter must be a non-empty string.');
      err.statusCode = 400;
      throw err;
    }

    if (query.length > this.maxQueryLength) {
      const err = new Error(`Query exceeds maximum allowed length of ${this.maxQueryLength} characters.`);
      err.statusCode = 400;
      throw err;
    }

    const trimmedQuery = query.trim();

    // 2. Trace resolution and lifecycle verification
    let activeTraceId = trace_id;
    if (activeTraceId) {
      if (!isValidTraceId(activeTraceId)) {
        const err = new Error(`Invalid trace_id format: '${activeTraceId}'.`);
        err.statusCode = 400;
        throw err;
      }
      const existingTrace = auditService.getInteraction(activeTraceId);
      if (!existingTrace) {
        const err = new Error(`Trace '${activeTraceId}' not found.`);
        err.statusCode = 404;
        throw err;
      }
      // Check if trace is in terminal state
      if (['completed', 'blocked', 'failed', 'cancelled'].includes(existingTrace.status)) {
        const err = new Error(`Cannot execute retrieval on terminal trace '${activeTraceId}' with status '${existingTrace.status}'.`);
        err.statusCode = 400;
        throw err;
      }
    } else {
      // Auto-create trace with initial status 'processing'
      const newTrace = auditService.createInteraction(null, `Retrieval search: "${trimmedQuery.slice(0, 80)}"`);
      activeTraceId = newTrace.trace_id;
    }

    // 3. Fetch candidates from pluggable provider
    const rawCandidates = await this.provider.search(trimmedQuery, options);

    // 4. Score and sort candidates deterministically
    const scoredCandidates = [];
    for (const raw of rawCandidates) {
      const score = computeLexicalScore(trimmedQuery, raw.text);
      const contentHash = raw.chunk_hash || computeSha256(raw.text);

      scoredCandidates.push({
        candidate_id: generateCandidateId(),
        source_id: raw.source_id,
        source_label: raw.source_label,
        source_version: raw.source_version || '1.0.0',
        chunk_id: raw.chunk_id || 'chunk-01',
        text: raw.text,
        content_hash: contentHash,
        source_hash: raw.source_hash || contentHash,
        relevance_score: score,
        trust_metadata: raw.trust_metadata || {},
        sanitized_excerpt: createSanitizedExcerpt(raw.text),
        is_blocked: false,
        has_security_findings: false,
        security_findings: [],
      });
    }

    // Stable tie-breaking: score DESC, then source_id ASC, then chunk_id ASC
    scoredCandidates.sort((a, b) => {
      if (b.relevance_score !== a.relevance_score) {
        return b.relevance_score - a.relevance_score;
      }
      if (a.source_id !== b.source_id) {
        return a.source_id.localeCompare(b.source_id);
      }
      return a.chunk_id.localeCompare(b.chunk_id);
    });

    const topCandidates = scoredCandidates.slice(0, this.maxCandidates);

    // 5. Inspect retrieved candidate content for Indirect Injection (PART D)
    const inspectionEventId = generateEventId();
    let hasBlockedCandidate = false;

    for (const cand of topCandidates) {
      const scanResult = scanPrompt(cand.text);
      if (scanResult.findings.length > 0) {
        cand.has_security_findings = true;
        cand.security_findings = scanResult.findings;

        // Evaluate against policy engine
        const policyResult = evaluatePolicy(scanResult.findings);
        cand.policy_decision = policyResult.decision;

        // Record security audit event for each finding
        for (const finding of scanResult.findings) {
          auditService.addSecurityEvent({
            trace_id: activeTraceId,
            stage: 'retrieval_inspection',
            event_type: 'scan_retrieval',
            threat_category: finding.category || 'indirect_injection_indicator',
            severity: finding.severity || 'high',
            policy_decision: policyResult.decision,
            rule_id: finding.rule_id || finding.rule || 'PI-006',
            rule_version: finding.rule_version || '1.0.0',
            reason: `Indirect injection scan: ${policyResult.reason}`,
            source_id: cand.source_id,
            redacted_evidence: cand.sanitized_excerpt,
            metadata_json: JSON.stringify({
              chunk_id: cand.chunk_id,
              location: finding.location,
            }),
          });
        }

        if (policyResult.decision === 'block') {
          cand.is_blocked = true;
          hasBlockedCandidate = true;
        }
      }
    }

    // 6. Record retrieval provenance in database (PART E)
    let orderIndex = 1;
    for (const cand of topCandidates) {
      auditService.addRetrievalRecord({
        trace_id: activeTraceId,
        event_id: null,
        call_id: null,
        source_id: cand.source_id,
        source_label: cand.source_label,
        source_version: cand.source_version,
        source_hash: cand.source_hash,
        chunk_id: cand.chunk_id,
        chunk_hash: cand.content_hash,
        retrieval_order: orderIndex++,
        relevance_score: cand.relevance_score,
        trust_metadata: cand.trust_metadata,
        included_in_model_context: 0, // Accurately reflects no LLM inference attempted in this task
        redacted_excerpt: cand.sanitized_excerpt,
      });
    }

    // 7. Evaluate Evidence Sufficiency & Ambiguity (PART C)
    const eligibleCandidates = topCandidates.filter(c => !c.is_blocked && c.relevance_score >= this.minRelevanceThreshold);

    // Case 3: No sufficiently relevant source
    if (eligibleCandidates.length === 0) {
      return {
        trace_id: activeTraceId,
        retrieval_status: 'no_relevant_evidence',
        needs_clarification: false,
        session_id: null,
        clarification_question: null,
        candidates: topCandidates.map(this._toPublicCandidate),
        selected_candidate: null,
        decision_reason: `No candidate sources met the minimum relevance threshold (${this.minRelevanceThreshold}).`,
        has_indirect_injection: topCandidates.some(c => c.has_security_findings),
      };
    }

    // Check for ambiguity among eligible candidates
    const topCand = eligibleCandidates[0];
    const competingCandidates = eligibleCandidates.filter(
      c => Math.abs(topCand.relevance_score - c.relevance_score) <= this.ambiguityMarginThreshold
    );

    // Case 2: Several materially competing sources -> Needs Clarification
    if (competingCandidates.length > 1) {
      const clarificationPrompt = `Multiple relevant sources found with similar relevance (${competingCandidates.map(c => c.source_label).join(' vs ')}). Please select the specific source required.`;

      // Persist clarification session to SQLite for restart recovery
      const session = auditService.createClarificationSession({
        trace_id: activeTraceId,
        query: trimmedQuery,
        candidates: competingCandidates.map(this._toSessionCandidate),
        clarification_prompt: clarificationPrompt,
      });

      // Update trace lifecycle status to 'needs_clarification'
      auditService.updateInteractionStatus(activeTraceId, 'needs_clarification');

      return {
        trace_id: activeTraceId,
        retrieval_status: 'needs_clarification',
        needs_clarification: true,
        session_id: session.session_id,
        clarification_question: clarificationPrompt,
        candidates: competingCandidates.map(this._toPublicCandidate),
        selected_candidate: null,
        decision_reason: `Material ambiguity detected: ${competingCandidates.length} sources fall within ambiguity margin (${this.ambiguityMarginThreshold}). Clarification required.`,
        has_indirect_injection: competingCandidates.some(c => c.has_security_findings),
      };
    }

    // Case 1: One clearly relevant source -> Selected
    return {
      trace_id: activeTraceId,
      retrieval_status: 'selected',
      needs_clarification: false,
      session_id: null,
      clarification_question: null,
      candidates: eligibleCandidates.map(this._toPublicCandidate),
      selected_candidate: this._toPublicCandidate(topCand),
      decision_reason: `Single clearly relevant source selected with relevance score ${topCand.relevance_score} (margin exceeds ${this.ambiguityMarginThreshold}).`,
      has_indirect_injection: topCand.has_security_findings,
    };
  }

  /**
   * Clarify a pending ambiguity session by user candidate selection.
   * Resumes the original trace back into 'processing' state.
   *
   * @param {Object} params
   * @param {string} params.session_id
   * @param {string} params.candidate_id
   * @returns {Object} Clarification resolution result
   */
  async clarify({ session_id, candidate_id }) {
    if (!session_id || typeof session_id !== 'string') {
      const err = new Error('session_id is required.');
      err.statusCode = 400;
      throw err;
    }

    if (!candidate_id || typeof candidate_id !== 'string') {
      const err = new Error('candidate_id is required.');
      err.statusCode = 400;
      throw err;
    }

    // 1. Retrieve persisted clarification session
    const session = auditService.getClarificationSession(session_id);
    if (!session) {
      const err = new Error(`Clarification session '${session_id}' not found.`);
      err.statusCode = 404;
      throw err;
    }

    // 2. Check repeated submission idempotency
    if (session.status === 'resolved') {
      if (session.selected_candidate_id === candidate_id) {
        const chosen = (session.candidates || []).find(c => c.candidate_id === candidate_id);
        return {
          trace_id: session.trace_id,
          session_id: session.session_id,
          status: 'resolved',
          trace_status: 'processing',
          selected_candidate: chosen || { candidate_id },
          message: 'Clarification session was already resolved with this candidate (idempotent).',
        };
      } else {
        const err = new Error(`Clarification session '${session_id}' has already been resolved with candidate '${session.selected_candidate_id}'.`);
        err.statusCode = 409;
        throw err;
      }
    }

    if (session.status !== 'pending') {
      const err = new Error(`Clarification session '${session_id}' is in non-actionable status '${session.status}'.`);
      err.statusCode = 400;
      throw err;
    }

    // 3. Validate candidate belongs to session
    const candidate = (session.candidates || []).find(c => c.candidate_id === candidate_id);
    if (!candidate) {
      const err = new Error(`Candidate '${candidate_id}' does not belong to session '${session_id}'. Selection rejected.`);
      err.statusCode = 400;
      throw err;
    }

    // 4. Verify candidate content integrity against current provider state (stale detection)
    const currentSource = this.provider.getSource(candidate.source_id, candidate.chunk_id);
    if (!currentSource || currentSource.chunk_hash !== candidate.content_hash) {
      auditService.updateClarificationSession(session_id, { status: 'stale' });
      const err = new Error(`Source content for '${candidate.source_id}' has changed or is unavailable since clarification was initiated. Stale evidence rejected.`);
      err.statusCode = 409;
      throw err;
    }

    // 5. Verify trace lifecycle transition
    const interaction = auditService.getInteraction(session.trace_id);
    if (!interaction) {
      const err = new Error(`Associated trace '${session.trace_id}' not found.`);
      err.statusCode = 404;
      throw err;
    }

    if (['completed', 'blocked', 'failed', 'cancelled'].includes(interaction.status)) {
      const err = new Error(`Associated trace '${session.trace_id}' is in terminal status '${interaction.status}' and cannot be resumed.`);
      err.statusCode = 400;
      throw err;
    }

    // 6. Transition trace from 'needs_clarification' back to 'processing'
    auditService.updateInteractionStatus(session.trace_id, 'processing');

    // 7. Resolve session in database
    auditService.updateClarificationSession(session_id, {
      status: 'resolved',
      selected_candidate_id: candidate_id,
    });

    // 8. Log resolution event
    auditService.addSecurityEvent({
      trace_id: session.trace_id,
      stage: 'retrieval_clarification',
      event_type: 'clarification_resolved',
      threat_category: null,
      severity: 'info',
      policy_decision: 'allow',
      rule_id: null,
      reason: `Ambiguity resolved by selecting candidate '${candidate.source_label}' (${candidate.source_id})`,
      source_id: candidate.source_id,
      redacted_evidence: candidate.sanitized_excerpt,
      metadata_json: JSON.stringify({
        session_id: session.session_id,
        candidate_id: candidate.candidate_id,
      }),
    });

    return {
      trace_id: session.trace_id,
      session_id: session.session_id,
      status: 'resolved',
      trace_status: 'processing',
      selected_candidate: candidate,
      message: 'Clarification resolved successfully. Trace resumed in processing state.',
    };
  }

  /**
   * Helper: Map candidate to public API candidate representation.
   */
  _toPublicCandidate(cand) {
    return {
      candidate_id: cand.candidate_id,
      source_id: cand.source_id,
      source_label: cand.source_label,
      source_version: cand.source_version,
      chunk_id: cand.chunk_id,
      relevance_score: cand.relevance_score,
      excerpt: cand.sanitized_excerpt,
      content_hash: cand.content_hash,
      has_security_findings: cand.has_security_findings,
      security_findings: cand.security_findings || [],
      is_blocked: cand.is_blocked || false,
      trust_metadata: cand.trust_metadata || {},
    };
  }

  /**
   * Helper: Map candidate for persistent clarification session storage.
   */
  _toSessionCandidate(cand) {
    return {
      candidate_id: cand.candidate_id,
      source_id: cand.source_id,
      source_label: cand.source_label,
      source_version: cand.source_version,
      chunk_id: cand.chunk_id,
      relevance_score: cand.relevance_score,
      content_hash: cand.content_hash,
      sanitized_excerpt: cand.sanitized_excerpt,
      trust_metadata: cand.trust_metadata,
    };
  }
}

module.exports = {
  RetrievalService,
  computeLexicalScore,
  tokenize,
  createSanitizedExcerpt,
};
