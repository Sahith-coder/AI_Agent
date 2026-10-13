'use strict';

/**
 * TraceGuard Output Scanner
 *
 * Inspects model-generated output for configured sensitive-data patterns.
 * Returns structured findings with severity, evidence location spans, and redaction metadata.
 *
 * The scanner does NOT trust the model's claim that its output is safe.
 */

const { redact } = require('./redaction-service');
const { getRule } = require('./rule-catalogue');

// ---------------------------------------------------------------------------
// Sensitive-data detection rules
// Each rule: { id, category, severity, description, pattern, label }
// ---------------------------------------------------------------------------

const OUTPUT_RULES = [
  {
    id: 'OS-001',
    category: 'synthetic_secret_exposure',
    severity: 'high',
    description: 'Synthetic demo secret (DEMO_SECRET_* pattern)',
    pattern: /DEMO_SECRET_[A-Z0-9]{4,}/g,
    label: 'DEMO_SECRET',
  },
  {
    id: 'OS-002',
    category: 'synthetic_secret_exposure',
    severity: 'high',
    description: 'Synthetic secret key pattern (SECRET_KEY_*)',
    pattern: /SECRET_KEY_[A-Za-z0-9_]{4,}/g,
    label: 'SECRET_KEY',
  },
  {
    id: 'OS-003',
    category: 'api_key_exposure',
    severity: 'high',
    description: 'Generic API key pattern (sk-*, sk_live_*, sk_test_*)',
    pattern: /\bsk[-_](live|test|prod)?[-_]?[A-Za-z0-9]{20,}\b/g,
    label: 'API_KEY',
  },
  {
    id: 'OS-004',
    category: 'api_key_exposure',
    severity: 'medium',
    description: 'Bearer token in output',
    pattern: /Bearer\s+[A-Za-z0-9\-._~+/]{20,}/g,
    label: 'BEARER_TOKEN',
  },
  {
    id: 'OS-005',
    category: 'credential_exposure',
    severity: 'high',
    description: 'Password assignment in output',
    pattern: /password\s*[:=]\s*["']?[^\s"']{8,}["']?/gi,
    label: 'PASSWORD',
  },
  {
    id: 'OS-006',
    category: 'api_key_exposure',
    severity: 'medium',
    description: 'AWS-style access key pattern',
    pattern: /\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/g,
    label: 'AWS_KEY',
  },
  {
    id: 'OS-007',
    category: 'synthetic_secret_exposure',
    severity: 'high',
    description: 'Internal token pattern (INTERNAL_TOKEN_*)',
    pattern: /INTERNAL_TOKEN_[A-Za-z0-9_]{4,}/g,
    label: 'INTERNAL_TOKEN',
  },
];

/**
 * Scan output text for sensitive-data patterns with exact UTF-16 evidence location spans.
 * @param {string} text — the model output to scan.
 * @returns {{ findings: Array, summary: Object, redaction_matches: Array }}
 */
function scanOutput(text) {
  if (!text || typeof text !== 'string') {
    return {
      findings: [],
      summary: { total: 0, highest_severity: null },
      redaction_matches: [],
    };
  }

  const severityRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const findings = [];
  const redactionMatches = [];
  let highestRank = -1;
  let highestSeverity = null;

  for (const rule of OUTPUT_RULES) {
    const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g';
    const regex = new RegExp(rule.pattern.source, flags);
    const locations = [];
    let match;

    while ((match = regex.exec(text)) !== null) {
      locations.push({
        start_index: match.index,
        end_index: match.index + match[0].length,
        unit: 'utf16_code_units',
      });
      if (regex.lastIndex === match.index) {
        regex.lastIndex++;
      }
    }

    if (locations.length > 0) {
      const catalogEntry = getRule(rule.id);
      findings.push({
        rule_id: rule.id,
        rule_version: catalogEntry ? catalogEntry.version : '1.0.0',
        name: catalogEntry ? catalogEntry.name : rule.description,
        category: rule.category,
        severity: rule.severity,
        reason: `${rule.description} — ${locations.length} occurrence(s) detected.`,
        confidence: null,
        evidence_summary: `Matched rule ${rule.id}: ${rule.description}`,
        recommended_action: catalogEntry
          ? catalogEntry.recommended_action
          : 'Apply the configured output policy. Redact or block before returning to the user.',
        match_count: locations.length,
        location: locations[0],
        locations,
      });

      redactionMatches.push({
        pattern: new RegExp(rule.pattern.source, rule.pattern.flags),
        label: rule.label,
      });

      const rank = severityRank[rule.severity] ?? 0;
      if (rank > highestRank) {
        highestRank = rank;
        highestSeverity = rule.severity;
      }
    }
  }

  // Stable ordering: by severity rank DESC, then rule ID ASC
  findings.sort((a, b) => {
    const rA = severityRank[a.severity] ?? 0;
    const rB = severityRank[b.severity] ?? 0;
    if (rB !== rA) return rB - rA;
    return a.rule_id.localeCompare(b.rule_id);
  });

  return {
    findings,
    summary: {
      total: findings.length,
      highest_severity: highestSeverity,
    },
    redaction_matches: redactionMatches,
  };
}

/**
 * Scan and redact output text in one call.
 * Offsets in findings refer to the original, unredacted text.
 * @param {string} text
 * @returns {{ findings, summary, sanitized_content, redacted_evidence, redaction_count }}
 */
function scanAndRedact(text) {
  const result = scanOutput(text);

  if (result.redaction_matches.length === 0) {
    return {
      ...result,
      sanitized_content: text,
      redacted_evidence: text,
      redaction_count: 0,
    };
  }

  const { sanitized, redacted_evidence, redaction_count } = redact(text, result.redaction_matches);

  return {
    findings: result.findings,
    summary: result.summary,
    sanitized_content: sanitized,
    redacted_evidence,
    redaction_count,
  };
}

/**
 * Expose rule list for introspection / testing.
 */
function getRules() {
  return OUTPUT_RULES.map(r => ({
    id: r.id,
    category: r.category,
    severity: r.severity,
    description: r.description,
  }));
}

/**
 * Redact sensitive tokens from output text.
 * @param {string} text
 * @returns {{ redacted_text: string, findings: Array, redaction_count: number }}
 */
function redactOutput(text) {
  const res = scanAndRedact(text);
  return {
    redacted_text: res.sanitized_content,
    findings: res.findings,
    redaction_count: res.redaction_count,
  };
}

module.exports = { scanOutput, scanAndRedact, redactOutput, getRules };
