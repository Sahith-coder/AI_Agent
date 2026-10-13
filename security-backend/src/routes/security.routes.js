'use strict';

const { Router } = require('express');
const { validateEvaluationRequest } = require('../middleware/request-validation');
const promptScanner = require('../services/prompt-scanner');
const outputScanner = require('../services/output-scanner');
const policyEngine = require('../services/policy-engine');
const auditService = require('../services/audit-service');

const router = Router();

/**
 * POST /api/security/evaluate
 *
 * Evaluate content through the appropriate scanner and policy engine.
 * Correlates findings to a new or existing valid trace, preserving monotonic sequence numbers.
 */
router.post('/security/evaluate', validateEvaluationRequest, (req, res, next) => {
  try {
    const { trace_id, stage = 'prompt', content, parent_event_id, call_id } = req.body;

    // 1. Resolve interaction / trace
    let interaction;
    if (trace_id) {
      interaction = auditService.getInteraction(trace_id);
      if (!interaction) {
        return res.status(404).json({
          error: 'Not found',
          message: `Supplied trace_id does not exist: ${trace_id}`,
        });
      }
    } else {
      interaction = auditService.createInteraction(
        null,
        content.substring(0, 200) // summary
      );
    }

    // 2. Run the appropriate scanner
    let findings = [];
    let sanitizedContent = content;
    let redactedEvidence = content;
    let redactionCount = 0;

    if (stage === 'prompt' || stage === 'retrieved_content') {
      const result = promptScanner.scanPrompt(content);
      findings = result.findings;
      // Truncate evidence summary safely to prevent log bloat
      redactedEvidence = content.length > 500
        ? content.substring(0, 500) + '... [truncated]'
        : content;
    } else if (stage === 'output') {
      const result = outputScanner.scanAndRedact(content);
      findings = result.findings;
      sanitizedContent = result.sanitized_content;
      redactedEvidence = result.redacted_evidence;
      redactionCount = result.redaction_count;
    }

    // 3. Run the policy engine with deterministic precedence
    const policy = policyEngine.evaluate(findings);

    // 4. Persist the security event (monotonic sequence allocation inside transaction)
    const primaryFinding = findings.length > 0 ? findings[0] : null;
    const eventId = auditService.addSecurityEvent({
      trace_id: interaction.trace_id,
      stage,
      event_type: findings.length > 0 ? 'threat_detected' : 'scan_clean',
      threat_category: primaryFinding ? primaryFinding.category : null,
      severity: policy.severity,
      policy_decision: policy.decision,
      rule_id: primaryFinding ? primaryFinding.rule_id : null,
      rule_version: '1.0.0',
      policy_version: policy.policy_version,
      reason: policy.reasons.join(' | '),
      source_id: null,
      execution_outcome: null,
      redacted_evidence: findings.length > 0
        ? redactedEvidence.substring(0, 1000)
        : null,
      parent_event_id: parent_event_id || null,
      call_id: call_id || null,
    });

    // 5. Update interaction status: 'blocked' if decision is block, 'completed' otherwise
    const targetStatus = policy.decision === 'block' ? 'blocked' : 'completed';
    try {
      auditService.updateInteractionStatus(interaction.trace_id, targetStatus);
    } catch {
      // If trace was already terminal, do not fail the evaluation
    }

    // 6. Return structured response
    res.status(200).json({
      trace_id: interaction.trace_id,
      status: targetStatus,
      stage,
      decision: policy.decision,
      severity: policy.severity,
      findings,
      matched_policies: policy.matched_policies,
      recommended_action: policy.recommended_action,
      sanitized_content: policy.decision === 'redact' ? sanitizedContent : undefined,
      redaction_count: redactionCount > 0 ? redactionCount : undefined,
      event_id: eventId,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
