'use strict';

/**
 * TraceGuard Prompt Scanner
 *
 * Deterministic, rule-based scanner for detecting prompt-injection indicators
 * and suspicious content in user inputs and retrieved context.
 *
 * Provides exact UTF-16 evidence location spans, catalog integration,
 * stable finding ordering, and narrow false-positive control for quoted educational examples.
 */

const { getRule } = require('./rule-catalogue');

// ---------------------------------------------------------------------------
// Detection rules definitions
// ---------------------------------------------------------------------------

const DETECTION_RULES = [
  // ---- Instruction override / prompt injection indicators ----
  {
    id: 'PI-001',
    category: 'prompt_injection_indicator',
    severity: 'high',
    description: 'Attempt to override or ignore prior instructions',
    patterns: [
      /ignore[\s,.:;!?-]+(all[\s,.:;!?-]+)?(your[\s,.:;!?-]+)?(previous|prior|above|earlier|preceding)?[\s,.:;!?-]*(instructions|prompts|rules|directives)/i,
      /disregard[\s,.:;!?-]+(all[\s,.:;!?-]+)?(your[\s,.:;!?-]+)?(previous|prior|above|earlier)?[\s,.:;!?-]*(instructions|prompts|rules|guidelines)/i,
      /forget[\s,.:;!?-]+(all[\s,.:;!?-]+)?(your[\s,.:;!?-]+)?(previous|prior|above|earlier)?[\s,.:;!?-]*(instructions|prompts|rules|context)/i,
      /override[\s,.:;!?-]+(all[\s,.:;!?-]+)?(previous|prior|system)[\s,.:;!?-]+(instructions|prompts|rules)/i,
      /do[\s,.:;!?-]+not[\s,.:;!?-]+follow[\s,.:;!?-]+(your|the|any)[\s,.:;!?-]+(previous|prior|original)[\s,.:;!?-]+(instructions|rules|guidelines)/i,
    ],
    reason: 'Detected a pattern requesting the model to disregard its prior instructions.',
    recommended_action: 'Review the request under the configured content policy. This is a common prompt-injection indicator.',
  },
  {
    id: 'PI-002',
    category: 'prompt_injection_indicator',
    severity: 'high',
    description: 'Role-switching or identity override attempt',
    patterns: [
      /you[\s,.:;!?-]+are[\s,.:;!?-]+now[\s,.:;!?-]+(an?[\s,.:;!?-]+)?(unrestricted|unfiltered|jailbroken|evil|uncensored)/i,
      /enter[\s,.:;!?-]+(into[\s,.:;!?-]+)?(DAN|developer|god|admin|sudo)[\s,.:;!?-]+mode/i,
      /switch[\s,.:;!?-]+to[\s,.:;!?-]+(DAN|developer|unrestricted|unfiltered)[\s,.:;!?-]+mode/i,
      /act[\s,.:;!?-]+as[\s,.:;!?-]+(an?[\s,.:;!?-]+)?(unrestricted|unfiltered|jailbroken)[\s,.:;!?-]+(ai|assistant|model)/i,
      /pretend[\s,.:;!?-]+(you[\s,.:;!?-]+are|to[\s,.:;!?-]+be)[\s,.:;!?-]+(an?[\s,.:;!?-]+)?(unrestricted|unfiltered|evil)/i,
    ],
    reason: 'Detected an attempt to change the assistant identity or bypass safety constraints.',
    recommended_action: 'Flag or block this request. Role-switching is a common jailbreak technique.',
  },
  // ---- System/developer instruction disclosure ----
  {
    id: 'PI-003',
    category: 'system_prompt_extraction',
    severity: 'medium',
    description: 'Attempt to reveal hidden system or developer instructions',
    patterns: [
      /reveal[\s,.:;!?-]+(your|the|all)[\s,.:;!?-]+(system|hidden|internal|developer|secret)[\s,.:;!?-]+(prompt|instructions|rules|guidelines)/i,
      /show[\s,.:;!?-]+(me[\s,.:;!?-]+)?(your|the)[\s,.:;!?-]+(system|hidden|original|full)[\s,.:;!?-]+(prompt|instructions|message)/i,
      /what[\s,.:;!?-]+(are|is)[\s,.:;!?-]+your[\s,.:;!?-]+(system|hidden|original|initial)[\s,.:;!?-]+(prompt|instructions|message|directive)/i,
      /print[\s,.:;!?-]+(your|the)[\s,.:;!?-]+(system|initial|original)[\s,.:;!?-]+(prompt|instructions|message)/i,
      /output[\s,.:;!?-]+(your|the)[\s,.:;!?-]+(system|initial|full)[\s,.:;!?-]+(prompt|instructions|message)/i,
      /repeat[\s,.:;!?-]+(your|the)[\s,.:;!?-]+(system|initial|original)[\s,.:;!?-]+(prompt|instructions|message)[\s,.:;!?-]*(verbatim|exactly|word[\s,.:;!?-]*for[\s,.:;!?-]*word)?/i,
    ],
    reason: 'Detected a request to disclose system-level or developer instructions.',
    recommended_action: 'Review whether the request is attempting to extract confidential configuration.',
  },
  // ---- Secret / credential exfiltration ----
  {
    id: 'PI-004',
    category: 'data_exfiltration_indicator',
    severity: 'high',
    description: 'Request to disclose or exfiltrate secrets, keys, or credentials',
    patterns: [
      /give[\s,.:;!?-]+me[\s,.:;!?-]+(the|all|your|any)[\s,.:;!?-]+(api|secret|private|access)[\s,.:;!?-]*(key|token|credential|password)s?/i,
      /send[\s,.:;!?-]+(the|all|any)[\s,.:;!?-]+(data|secrets?|keys?|credentials?|passwords?)[\s,.:;!?-]+to[\s,.:;!?-]+/i,
      /\bexfiltrate\b/i,
      /leak[\s,.:;!?-]+(the|all|any)[\s,.:;!?-]+(secret|private|internal|confidential)[\s,.:;!?-]+(data|key|token|information)/i,
      /transfer[\s,.:;!?-]+(all|the|any)[\s,.:;!?-]+(data|secrets?|credentials?)[\s,.:;!?-]+(to|via|through)[\s,.:;!?-]+(http|https|ftp|external)/i,
    ],
    reason: 'Detected a request that may attempt to extract or exfiltrate secrets or credentials.',
    recommended_action: 'Evaluate under the data-protection policy. Block if disclosure would expose real credentials.',
  },
  // ---- Encoded / obfuscated instructions ----
  {
    id: 'PI-005',
    category: 'prompt_injection_indicator',
    severity: 'medium',
    description: 'Suspicious encoded or obfuscated instruction',
    patterns: [
      /base64[\s,.:;!?-]*(decode|encode|decrypt)[\s,.:;!?-]*[:=]?[\s,.:;!?-]*/i,
      /decode[\s,.:;!?-]+the[\s,.:;!?-]+following[\s,.:;!?-]+(and[\s,.:;!?-]+)?(execute|run|follow|obey)/i,
      /execute[\s,.:;!?-]+(this|the[\s,.:;!?-]+following)[\s,.:;!?-]+(encoded|base64|hex)[\s,.:;!?-]+(command|instruction|payload)/i,
    ],
    reason: 'Detected an instruction involving encoding/decoding combined with execution, which may hide a payload.',
    recommended_action: 'Inspect the full content for obfuscated injection attempts.',
  },
  // ---- Indirect injection markers in retrieved content ----
  {
    id: 'PI-006',
    category: 'indirect_injection_indicator',
    severity: 'high',
    description: 'Instruction embedded in retrieved/external content targeting the AI',
    patterns: [
      /\[INST\]/i,
      /\[SYSTEM\]/i,
      /<<\s*SYS\s*>>/i,
      /###\s*(instruction|system|user|assistant)\s*:/i,
      /BEGIN\s+INJECTION/i,
      /IMPORTANT:\s*(ignore|disregard|override)\s+(all\s+)?(other|previous)/i,
    ],
    reason: 'Detected markup or phrasing commonly used to inject instructions into a model via external content.',
    recommended_action: 'Treat the source document as suspicious. Record provenance and review the retrieval chain.',
  },
];

/**
 * Check if a matched span is an explicitly quoted phrase being analyzed in an educational query,
 * without active imperative attack payload commands.
 */
function isQuotedEducationalExample(text, start, end, matchedText) {
  // Check if span is directly enclosed in quotes
  const isEnclosedInQuotes =
    (start > 0 && (text[start - 1] === '"' || text[start - 1] === "'" || text[start - 1] === '`')) &&
    (end < text.length && (text[end] === '"' || text[end] === "'" || text[end] === '`'));

  if (!isEnclosedInQuotes) return false;

  // The quoted text must not contain an active payload command (e.g. "and give me...", "and output...")
  if (/and\s+(give|tell|reveal|show|output|leak|exfiltrate|send|act|switch|enter|pretend)/i.test(matchedText)) {
    return false;
  }

  // The outer prompt text must not contain imperative follow-up injection payload
  if (/(and|,)\s*(reveal|give|show|output|leak|exfiltrate|send|act|switch|enter|pretend|print)\b/i.test(text)) {
    return false;
  }

  // The surrounding context must be an educational/analytical inquiry
  const hasEducationalIntent =
    /(explain|what\s+(is|are|does|do)|meaning\s+of|define|tell\s+me\s+about|why\s+(do|does|is|are)|how\s+(do|does|is|are)|discuss|analysis\s+of)\b/i.test(text);

  return hasEducationalIntent;
}

/**
 * Find all occurrence locations for a set of regex patterns in text.
 */
function findPatternLocations(text, patterns, ruleId) {
  const rawLocations = [];

  for (const pattern of patterns) {
    const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
    const rx = new RegExp(pattern.source, flags);
    let match;

    while ((match = rx.exec(text)) !== null) {
      const start = match.index;
      const end = match.index + match[0].length;
      const matched = match[0];

      // Narrow contextual false-positive check for quoted examples in educational queries
      if (ruleId === 'PI-001' && isQuotedEducationalExample(text, start, end, matched)) {
        // Skip purely quoted educational example phrase
        if (rx.lastIndex === match.index) rx.lastIndex++;
        continue;
      }

      rawLocations.push({
        start_index: start,
        end_index: end,
        unit: 'utf16_code_units',
      });

      if (rx.lastIndex === match.index) {
        rx.lastIndex++;
      }
    }
  }

  if (rawLocations.length <= 1) return rawLocations;

  // Deduplicate overlapping or identical match spans
  rawLocations.sort((a, b) => a.start_index - b.start_index || (b.end_index - b.start_index) - (a.end_index - a.start_index));
  const deduplicated = [];
  for (const loc of rawLocations) {
    const isEnclosed = deduplicated.some(
      existing => existing.start_index <= loc.start_index && existing.end_index >= loc.end_index
    );
    if (!isEnclosed) {
      deduplicated.push(loc);
    }
  }

  return deduplicated;
}

/**
 * Scan a text input and return structured findings with exact UTF-16 location spans.
 * @param {string} text — the content to scan.
 * @returns {{ findings: Array<Object>, summary: { total: number, highest_severity: string|null } }}
 */
function scanPrompt(text) {
  if (!text || typeof text !== 'string') {
    return { findings: [], summary: { total: 0, highest_severity: null } };
  }

  const severityRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const findings = [];
  let highestRank = -1;
  let highestSeverity = null;

  for (const rule of DETECTION_RULES) {
    const locations = findPatternLocations(text, rule.patterns, rule.id);

    if (locations.length > 0) {
      const catalogEntry = getRule(rule.id);
      findings.push({
        rule: rule.id,
        rule_id: rule.id,
        rule_version: catalogEntry ? catalogEntry.version : '1.0.0',
        name: catalogEntry ? catalogEntry.name : rule.description,
        category: rule.category,
        severity: rule.severity,
        reason: rule.reason,
        confidence: null, // deterministic — no probabilistic score
        evidence_summary: `Matched rule ${rule.id}: ${rule.description}`,
        recommended_action: catalogEntry ? catalogEntry.recommended_action : rule.recommended_action,
        match_count: locations.length,
        location: locations[0],
        locations,
      });

      const rank = severityRank[rule.severity] ?? 0;
      if (rank > highestRank) {
        highestRank = rank;
        highestSeverity = rule.severity;
      }
    }
  }

  // Stable deterministic sorting: severity rank DESC, then rule ID ASC
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
  };
}

/**
 * Expose the rule list for introspection / testing.
 */
function getRules() {
  return DETECTION_RULES.map(r => ({
    id: r.id,
    category: r.category,
    severity: r.severity,
    description: r.description,
  }));
}

module.exports = { scanPrompt, getRules };
