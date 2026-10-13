'use strict';

/**
 * TraceGuard Redaction Service
 *
 * Identifies sensitive spans in text and produces:
 *  - sanitized content (for display / return to the user)
 *  - redacted evidence (for audit storage — secret value replaced)
 *
 * Does NOT store raw secrets in event fields.
 */

/**
 * Redact all occurrences of matched patterns in the text.
 * @param {string} text — original text.
 * @param {Array<{ pattern: RegExp, label: string }>} matches — patterns to redact.
 * @returns {{ sanitized: string, redacted_evidence: string, redaction_count: number }}
 */
function redact(text, matches) {
  if (!text || typeof text !== 'string' || !matches || matches.length === 0) {
    return { sanitized: text, redacted_evidence: text, redaction_count: 0 };
  }

  let sanitized = text;
  let redactedEvidence = text;
  let count = 0;

  for (const { pattern, label } of matches) {
    // Ensure global flag for replacement
    const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');

    const found = sanitized.match(globalPattern);
    if (found) {
      count += found.length;
    }

    // Display version: fully masked
    sanitized = sanitized.replace(globalPattern, `[REDACTED:${label}]`);

    // Audit evidence version: partial — first 3 chars + mask
    redactedEvidence = redactedEvidence.replace(globalPattern, (match) => {
      const prefix = match.substring(0, Math.min(3, match.length));
      return `${prefix}***[${label}]`;
    });
  }

  return { sanitized, redacted_evidence: redactedEvidence, redaction_count: count };
}

module.exports = { redact };
