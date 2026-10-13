'use strict';

const crypto = require('node:crypto');
const auditService = require('./audit-service');
const promptScanner = require('./prompt-scanner');
const outputScanner = require('./output-scanner');
const { isValidTraceId, generateToolEventId } = require('./trace-service');

/**
 * Valid outcome vocabulary adhering to canonical TraceGuard schema.
 */
const VALID_OUTCOMES = ['proposed', 'started', 'succeeded', 'failed', 'denied', 'unknown'];

/**
 * Valid tool lifecycle state transitions for a given call_id.
 * Terminal outcomes (succeeded, failed, denied) cannot transition to new states.
 */
const ALLOWED_LIFECYCLE_TRANSITIONS = {
  proposed: ['started', 'succeeded', 'failed', 'denied', 'unknown'],
  started: ['succeeded', 'failed', 'denied', 'unknown'],
  unknown: ['started', 'succeeded', 'failed', 'denied'],
  // Terminal outcomes
  succeeded: [],
  failed: [],
  denied: [],
};

/**
 * Canonicalize data into a deterministic string representation.
 * @param {*} data
 * @returns {string}
 */
function canonicalizeData(data) {
  if (data === null || data === undefined) return '';
  if (typeof data === 'string') return data.trim();
  try {
    if (typeof data === 'object') {
      const sortedKeys = Object.keys(data).sort();
      const obj = {};
      for (const k of sortedKeys) {
        obj[k] = data[k];
      }
      return JSON.stringify(obj);
    }
    return String(data);
  } catch {
    return String(data);
  }
}

/**
 * Compute standard SHA-256 hash over canonical text.
 * @param {string} str
 * @returns {string}
 */
function computeHash(str) {
  if (!str) return null;
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

/**
 * Sanitize and redact sensitive data from summaries.
 * Bounded length prevents unrestricted log bloat.
 * @param {*} raw
 * @param {number} [maxLength=500]
 * @returns {string}
 */
function sanitizeSummary(raw, maxLength = 500) {
  if (raw === null || raw === undefined) return '';
  const str = typeof raw === 'string' ? raw : canonicalizeData(raw);
  const redacted = outputScanner.redactOutput(str).redacted_text;
  if (redacted.length > maxLength) {
    return redacted.substring(0, maxLength) + '... [truncated]';
  }
  return redacted;
}

/**
 * External network / transfer tools known to dispatch data.
 */
const EXTERNAL_NETWORK_TOOLS = /^(http|fetch|curl|webhook|send_email|export|exfiltrate|post_data|upload|external_api|download_upload)/i;

/**
 * Tool Monitor Service (Observational Only - Task 5)
 */
class ToolMonitorService {
  constructor(options = {}) {
    this.rapidCallsThreshold = options.rapidCallsThreshold ?? 5;
    this.sameToolRepeatThreshold = options.sameToolRepeatThreshold ?? 3;
    this.maxToolNameLength = options.maxToolNameLength ?? 100;
    this.maxSummaryLength = options.maxSummaryLength ?? 10000;
  }

  /**
   * Observe and record a tool invocation lifecycle event.
   *
   * @param {Object} observation
   * @param {string} observation.trace_id
   * @param {string} [observation.call_id]
   * @param {string} [observation.parent_event_id]
   * @param {string} observation.tool_name
   * @param {string} [observation.tool_server_identity]
   * @param {string} observation.outcome
   * @param {*} [observation.argument_summary]
   * @param {*} [observation.arguments]
   * @param {*} [observation.result_summary]
   * @param {*} [observation.result]
   * @param {*} [observation.source_metadata]
   * @param {string} [observation.timestamp]
   * @param {string} [observation.tool_event_id]
   * @returns {Object} Structured observation response
   */
  async observeTool(observation = {}) {
    const {
      trace_id,
      call_id = null,
      parent_event_id = null,
      tool_name,
      tool_server_identity = null,
      outcome,
      argument_summary,
      arguments: rawArgs,
      result_summary,
      result: rawResult,
      source_metadata = null,
      timestamp = null,
      tool_event_id = null,
    } = observation;

    // 1. Trace ID validation
    if (!trace_id || typeof trace_id !== 'string') {
      const err = new Error('trace_id is required and must be a string.');
      err.statusCode = 400;
      throw err;
    }

    if (!isValidTraceId(trace_id)) {
      const err = new Error(`Invalid trace_id format: '${trace_id}'.`);
      err.statusCode = 400;
      throw err;
    }

    const interaction = auditService.getInteraction(trace_id);
    if (!interaction) {
      const err = new Error(`Trace '${trace_id}' not found.`);
      err.statusCode = 404;
      throw err;
    }

    // 2. Call ID validation
    if (!call_id || typeof call_id !== 'string' || call_id.trim().length === 0) {
      const err = new Error('call_id is required and must be a non-empty string.');
      err.statusCode = 400;
      throw err;
    }

    const trimmedCallId = call_id.trim();
    if (trimmedCallId.length > 100) {
      const err = new Error('call_id is too long. Exceeds maximum allowed length of 100 characters.');
      err.statusCode = 400;
      throw err;
    }

    // 3. Tool Name validation
    if (!tool_name || typeof tool_name !== 'string' || tool_name.trim().length === 0) {
      const err = new Error('tool_name is required and must be a non-empty string.');
      err.statusCode = 400;
      throw err;
    }

    const trimmedToolName = tool_name.trim();
    if (trimmedToolName.length > this.maxToolNameLength) {
      const err = new Error(`tool_name is too long. Exceeds maximum allowed length of ${this.maxToolNameLength} characters.`);
      err.statusCode = 400;
      throw err;
    }

    if (!/^[a-zA-Z0-9_.-]+$/.test(trimmedToolName)) {
      const err = new Error('tool_name contains invalid characters. Must contain only alphanumeric, underscores, hyphens, and periods.');
      err.statusCode = 400;
      throw err;
    }

    // 4. Outcome validation
    if (!outcome || typeof outcome !== 'string') {
      const err = new Error('outcome is required and must be a valid execution outcome string.');
      err.statusCode = 400;
      throw err;
    }

    const normalizedOutcome = outcome.trim().toLowerCase();
    if (!VALID_OUTCOMES.includes(normalizedOutcome)) {
      const err = new Error(`Invalid execution outcome: '${outcome}'. Allowed values: ${VALID_OUTCOMES.join(', ')}`);
      err.statusCode = 400;
      throw err;
    }

    // 5. Lifecycle state machine & idempotency verification
    const priorCallEvents = auditService.getToolEventsByCallId(trace_id, trimmedCallId);
    let isIdempotent = false;
    let existingEventId = null;

    if (priorCallEvents.length > 0) {
      const latestPrior = priorCallEvents[priorCallEvents.length - 1];

      // Exact repeated event check: same call_id and same outcome
      if (latestPrior.execution_outcome === normalizedOutcome) {
        isIdempotent = true;
        existingEventId = latestPrior.tool_event_id;
      } else {
        // Transition check
        const allowedTargets = ALLOWED_LIFECYCLE_TRANSITIONS[latestPrior.execution_outcome] || [];
        if (!allowedTargets.includes(normalizedOutcome)) {
          const err = new Error(`Illegal tool lifecycle transition from '${latestPrior.execution_outcome}' to '${normalizedOutcome}' for call_id '${trimmedCallId}'.`);
          err.statusCode = 409;
          throw err;
        }
      }
    }

    // If idempotent repeat submission, return existing event record without duplicate insert
    if (isIdempotent) {
      const existing = priorCallEvents[priorCallEvents.length - 1];
      let suspicionIndicators = [];
      try {
        if (existing.suspicion_indicators) suspicionIndicators = JSON.parse(existing.suspicion_indicators);
      } catch { /* ignore */ }

      const idempAction = suspicionIndicators.some(i => i.severity === 'high')
        ? 'flag'
        : (suspicionIndicators.length > 0 ? 'monitor' : 'allow');

      return {
        success: true,
        status: 'observed',
        tool_event_id: existing.tool_event_id,
        trace_id,
        call_id: trimmedCallId,
        tool_name: existing.tool_name,
        tool_server_identity: existing.tool_server_identity,
        execution_outcome: existing.execution_outcome,
        outcome: existing.execution_outcome,
        argument_hash: existing.argument_hash,
        sanitized_argument_summary: existing.sanitized_argument_summary,
        redacted_result_summary: existing.redacted_result_summary,
        findings: suspicionIndicators,
        recommended_action: idempAction,
        risk_assessment: {
          has_risk_indicators: suspicionIndicators.length > 0,
          risk_level: suspicionIndicators.some(i => i.severity === 'high') ? 'high' : (suspicionIndicators.length > 0 ? 'medium' : 'none'),
          indicators: suspicionIndicators,
          recommended_action: suspicionIndicators.length > 0 ? 'Review flagged indicators from previous observation.' : 'None. Normal tool activity observed.',
        },
        idempotent: true,
        timestamp: existing.timestamp,
      };
    }

    // 6. Canonicalize, hash, and sanitize arguments and results
    const rawArgContent = rawArgs !== undefined ? rawArgs : (argument_summary !== undefined ? argument_summary : '');
    const canonicalArg = canonicalizeData(rawArgContent);
    const argumentHash = computeHash(canonicalArg);
    const sanitizedArgSummary = sanitizeSummary(rawArgContent);

    const rawResContent = rawResult !== undefined ? rawResult : (result_summary !== undefined ? result_summary : '');
    const canonicalRes = canonicalizeData(rawResContent);
    const sanitizedResSummary = sanitizeSummary(rawResContent);

    // 7. Explainable Risk Analysis (PART G)
    const indicators = [];

    // Indicator 1: Tool arguments containing prompt injection indicators
    if (canonicalArg) {
      const argScan = promptScanner.scanPrompt(canonicalArg);
      if (argScan.findings.length > 0) {
        indicators.push({
          rule: 'TOOL-RISK-INJECTION-ARG',
          rule_id: 'TOOL-RISK-INJECTION-ARG',
          severity: 'high',
          description: 'Tool arguments contain prompt injection indicators',
          findings: argScan.findings.map(f => ({
            rule_id: f.rule_id || f.rule,
            category: f.category,
            severity: f.severity,
            location: f.location,
            reason: f.reason,
          })),
        });
      }
    }

    // Indicator 2: Tool results containing sensitive-data or injection indicators
    if (canonicalRes) {
      const resOutputScan = outputScanner.scanOutput(canonicalRes);
      const resPromptScan = promptScanner.scanPrompt(canonicalRes);
      const combinedFindings = [...resOutputScan.findings, ...resPromptScan.findings];

      if (combinedFindings.length > 0) {
        indicators.push({
          rule: 'TOOL-RISK-SENSITIVE-RESULT',
          rule_id: 'TOOL-RISK-SENSITIVE-RESULT',
          severity: 'high',
          description: 'Tool result contains sensitive data exposure or injection indicators',
          findings: combinedFindings.map(f => ({
            rule_id: f.rule_id || f.rule,
            category: f.category,
            severity: f.severity,
            location: f.location,
          })),
        });
      }
    }

    // Indicator 3: Rapid / repeated tool invocations within trace
    const allTraceToolEvents = auditService.listToolEvents(trace_id);
    if (allTraceToolEvents.length >= this.rapidCallsThreshold) {
      indicators.push({
        rule: 'TOOL-RISK-RAPID-CALLS',
        rule_id: 'TOOL-RISK-RAPID-CALLS',
        severity: 'medium',
        description: `Unusually rapid tool activity: trace has accumulated ${allTraceToolEvents.length + 1} tool invocations (threshold: ${this.rapidCallsThreshold}).`,
      });
    }

    const sameToolEvents = allTraceToolEvents.filter(e => e.tool_name === trimmedToolName);
    if (sameToolEvents.length >= this.sameToolRepeatThreshold) {
      indicators.push({
        rule: 'TOOL-RISK-RAPID-CALLS',
        rule_id: 'TOOL-RISK-RAPID-CALLS',
        severity: 'medium',
        description: `Repeated tool invocation: tool '${trimmedToolName}' called ${sameToolEvents.length + 1} times within single trace.`,
      });
    }

    // Indicator 4: Sensitive retrieval followed by external data transmission request
    const priorRetrievalRecords = auditService.listRetrievalRecords(trace_id);
    if (priorRetrievalRecords.length > 0) {
      const isExternalTool = EXTERNAL_NETWORK_TOOLS.test(trimmedToolName);
      const hasUrlInArg = /https?:\/\/[^\s"']+/i.test(canonicalArg);

      if (isExternalTool || hasUrlInArg) {
        indicators.push({
          rule: 'TOOL-RISK-EXFILTRATION-SEQUENCE',
          rule_id: 'TOOL-RISK-EXFILTRATION-SEQUENCE',
          severity: 'high',
          description: `Data exfiltration sequence risk: trace retrieved ${priorRetrievalRecords.length} document chunk(s) prior to external transmission tool '${trimmedToolName}'.`,
          evidence: {
            linked_retrieval_source: priorRetrievalRecords[0].source_id,
            retrieval_records_count: priorRetrievalRecords.length,
          },
        });
      }
    }

    // Indicator 5: Missing or unverified tool server identity
    if (!tool_server_identity || /^(unverified|untrusted|unknown|mock_untrusted)$/i.test(tool_server_identity.trim())) {
      indicators.push({
        rule: 'TOOL-RISK-UNVERIFIED-SERVER',
        rule_id: 'TOOL-RISK-UNVERIFIED-SERVER',
        severity: 'low',
        description: `Tool invocation missing verified server or MCP identity (${tool_server_identity || 'absent'}).`,
      });
    }

    // Determine overall risk assessment
    const hasHigh = indicators.some(i => i.severity === 'high');
    const hasMed = indicators.some(i => i.severity === 'medium');
    const hasLow = indicators.some(i => i.severity === 'low');
    const riskLevel = hasHigh ? 'high' : (hasMed ? 'medium' : (hasLow ? 'low' : 'none'));
    const recommendedAction = hasHigh ? 'flag' : (hasMed ? 'monitor' : (hasLow ? 'verify' : 'allow'));

    // 8. Store tool event through audit service
    const eventTime = timestamp || new Date().toISOString();
    const storedToolEventId = auditService.addToolEvent({
      tool_event_id,
      trace_id,
      event_id: null,
      parent_event_id,
      call_id: trimmedCallId,
      tool_name: trimmedToolName,
      tool_server_identity: tool_server_identity ? tool_server_identity.trim() : null,
      sanitized_argument_summary: sanitizedArgSummary || '(empty)',
      argument_hash: argumentHash,
      source_metadata: source_metadata ? (typeof source_metadata === 'string' ? source_metadata : JSON.stringify(source_metadata)) : null,
      suspicion_indicators: indicators.length > 0 ? indicators : null,
      execution_outcome: normalizedOutcome,
      redacted_result_summary: sanitizedResSummary || null,
      timestamp: eventTime,
    });

    // 9. If risk indicators detected, log correlated security event in security_events
    if (indicators.length > 0) {
      const topIndicator = indicators.find(i => i.severity === 'high') || indicators[0];

      auditService.addSecurityEvent({
        trace_id,
        parent_event_id,
        call_id: trimmedCallId,
        stage: 'tool_monitoring',
        event_type: 'observe_tool_risk',
        threat_category: topIndicator.rule,
        severity: topIndicator.severity,
        policy_decision: 'flag', // Observational only: do not falsely claim to block execution
        rule_id: topIndicator.rule,
        rule_version: '1.0.0',
        reason: topIndicator.description,
        source_id: trimmedToolName,
        redacted_evidence: sanitizedArgSummary || sanitizedResSummary || null,
        metadata_json: JSON.stringify({
          indicators,
          outcome: normalizedOutcome,
          tool_server_identity,
        }),
      });
    }

    return {
      success: true,
      status: 'observed',
      tool_event_id: storedToolEventId,
      trace_id,
      call_id: trimmedCallId,
      tool_name: trimmedToolName,
      tool_server_identity: tool_server_identity ? tool_server_identity.trim() : null,
      execution_outcome: normalizedOutcome,
      outcome: normalizedOutcome,
      argument_hash: argumentHash,
      sanitized_argument_summary: sanitizedArgSummary,
      redacted_result_summary: sanitizedResSummary || null,
      findings: indicators,
      recommended_action: recommendedAction,
      risk_assessment: {
        has_risk_indicators: indicators.length > 0,
        risk_level: riskLevel,
        indicators,
        recommended_action: recommendedAction,
      },
      idempotent: false,
      timestamp: eventTime,
    };
  }

  /**
   * Validate if an outcome string belongs to the allowed vocabulary.
   * @param {string} outcome
   * @returns {boolean}
   */
  validateOutcome(outcome) {
    if (!outcome || typeof outcome !== 'string') return false;
    return VALID_OUTCOMES.includes(outcome.trim().toLowerCase());
  }
}

module.exports = {
  ToolMonitorService,
  VALID_OUTCOMES,
  ALLOWED_OUTCOMES: VALID_OUTCOMES,
  ALLOWED_LIFECYCLE_TRANSITIONS,
  canonicalizeData,
  computeHash,
  computeDeterministicArgHash: (data) => computeHash(canonicalizeData(data)),
  sanitizeSummary,
};
