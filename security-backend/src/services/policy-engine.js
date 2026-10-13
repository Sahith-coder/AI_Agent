'use strict';

/**
 * TraceGuard Policy Engine
 *
 * Deterministic policy evaluator that consumes scanner findings and returns
 * a structured policy decision.
 *
 * Conflict Resolution Rule:
 *   block > redact > flag > allow
 *
 * Secondary Resolution (same decision priority):
 *   highest severity (critical > high > medium > low > info) -> stable rule_id ordering.
 *
 * Scanner findings remain separate from the final policy decision.
 */

const POLICY_VERSION = '1.0.0';

// ---------------------------------------------------------------------------
// Decision priority (block > redact > flag > allow)
// ---------------------------------------------------------------------------
const DECISION_PRIORITY = { allow: 0, flag: 1, redact: 2, block: 3 };

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// ---------------------------------------------------------------------------
// Default policy mapping: category + severity → decision
// ---------------------------------------------------------------------------
const DEFAULT_POLICIES = [
  // Blocked patterns — explicitly configured high-risk content
  {
    policy_id: 'POL-BLOCK-EXFIL',
    match: { category: 'data_exfiltration_indicator', min_severity: 'high' },
    decision: 'block',
    label: 'Block high-severity data exfiltration indicators',
  },
  // Redact patterns — confirmed sensitive-data exposure in output
  {
    policy_id: 'POL-REDACT-SECRET',
    match: { category: 'synthetic_secret_exposure' },
    decision: 'redact',
    label: 'Redact synthetic secret exposure',
  },
  {
    policy_id: 'POL-REDACT-APIKEY-HIGH',
    match: { category: 'api_key_exposure', min_severity: 'high' },
    decision: 'redact',
    label: 'Redact high-severity API key exposure',
  },
  {
    policy_id: 'POL-REDACT-CRED',
    match: { category: 'credential_exposure' },
    decision: 'redact',
    label: 'Redact credential exposure',
  },
  // Flagged patterns — suspicious but monitoring-first policy
  {
    policy_id: 'POL-FLAG-INJECTION',
    match: { category: 'prompt_injection_indicator' },
    decision: 'flag',
    label: 'Flag prompt injection indicators for review',
  },
  {
    policy_id: 'POL-FLAG-EXTRACTION',
    match: { category: 'system_prompt_extraction' },
    decision: 'flag',
    label: 'Flag system prompt extraction attempts',
  },
  {
    policy_id: 'POL-FLAG-INDIRECT',
    match: { category: 'indirect_injection_indicator' },
    decision: 'flag',
    label: 'Flag indirect injection indicators',
  },
  {
    policy_id: 'POL-FLAG-APIKEY-MED',
    match: { category: 'api_key_exposure', min_severity: 'medium' },
    decision: 'flag',
    label: 'Flag medium-severity API key exposure',
  },
];

/**
 * Evaluate findings against the configured policy rules with deterministic conflict resolution.
 *
 * @param {Array<Object>} findings — array of scanner findings.
 * @param {Array<Object>} [policies] — optional custom policies; defaults to DEFAULT_POLICIES.
 * @returns {{ decision, severity, reasons, findings_count, matched_policies, recommended_action, policy_version, winning_rule }}
 */
function evaluate(findings, policies) {
  const activePolicies = Array.isArray(policies) ? policies : DEFAULT_POLICIES;

  if (!findings || findings.length === 0) {
    return {
      decision: 'allow',
      severity: 'info',
      reasons: ['No findings — content permitted.'],
      findings_count: 0,
      matched_policies: [],
      recommended_action: null,
      policy_version: POLICY_VERSION,
      winning_rule: null,
    };
  }

  let highestDecision = 'allow';
  let highestSeverityRank = -1;
  let highestSeverity = 'info';
  let winningRule = null;
  const reasons = [];
  const matchedPolicies = [];

  // Track candidate matches for deterministic tie-breaking
  const candidates = [];

  for (const finding of findings) {
    for (const policy of activePolicies) {
      if (!matchesPolicy(finding, policy.match)) continue;

      matchedPolicies.push(policy.label);
      reasons.push(`${policy.label}: ${finding.reason || finding.evidence_summary || finding.category}`);

      candidates.push({
        decision: policy.decision,
        decisionPriority: DECISION_PRIORITY[policy.decision],
        severity: finding.severity,
        severityRank: SEVERITY_RANK[finding.severity] ?? 0,
        ruleId: finding.rule_id || policy.policy_id || '',
        policyLabel: policy.label,
      });
    }

    const sRank = SEVERITY_RANK[finding.severity] ?? 0;
    if (sRank > highestSeverityRank) {
      highestSeverityRank = sRank;
      highestSeverity = finding.severity;
    }
  }

  if (candidates.length > 0) {
    // Sort candidates deterministically:
    // 1. Decision priority DESC (block > redact > flag > allow)
    // 2. Severity rank DESC (critical > high > medium > low > info)
    // 3. Rule ID ASC (stable alphabetical tie-breaker)
    candidates.sort((a, b) => {
      if (b.decisionPriority !== a.decisionPriority) {
        return b.decisionPriority - a.decisionPriority;
      }
      if (b.severityRank !== a.severityRank) {
        return b.severityRank - a.severityRank;
      }
      return a.ruleId.localeCompare(b.ruleId);
    });

    highestDecision = candidates[0].decision;
    winningRule = candidates[0].ruleId;
  } else if (findings.length > 0) {
    // If findings exist but no policy matched, default to flag
    highestDecision = 'flag';
    reasons.push('Findings present but no specific policy matched — defaulting to flag.');
    winningRule = findings[0].rule_id || 'DEFAULT_FLAG';
  }

  return {
    decision: highestDecision,
    severity: highestSeverity,
    reasons,
    findings_count: findings.length,
    matched_policies: [...new Set(matchedPolicies)],
    recommended_action: getRecommendation(highestDecision),
    policy_version: POLICY_VERSION,
    winning_rule: winningRule,
  };
}

/**
 * Check if a finding matches a policy's match criteria.
 */
function matchesPolicy(finding, match) {
  if (match.category && finding.category !== match.category) return false;

  if (match.min_severity) {
    const findingRank = SEVERITY_RANK[finding.severity] ?? 0;
    const minRank = SEVERITY_RANK[match.min_severity] ?? 0;
    if (findingRank < minRank) return false;
  }

  return true;
}

/**
 * Return a human-readable recommendation for a decision.
 */
function getRecommendation(decision) {
  switch (decision) {
    case 'allow':
      return null;
    case 'flag':
      return 'Review the flagged content. No automatic action was taken.';
    case 'redact':
      return 'Sensitive content has been redacted before delivery.';
    case 'block':
      return 'Content was blocked. Inspect the audit trace for details.';
    default:
      return null;
  }
}

/**
 * List default policy rules for introspection.
 */
function getPolicies() {
  return DEFAULT_POLICIES.map(p => ({
    id: p.policy_id,
    label: p.label,
    category: p.match.category,
    min_severity: p.match.min_severity || null,
    decision: p.decision,
  }));
}

module.exports = {
  evaluate,
  evaluatePolicy: evaluate,
  evaluateFindings: evaluate,
  getPolicies,
  POLICY_VERSION,
  DECISION_PRIORITY,
};
