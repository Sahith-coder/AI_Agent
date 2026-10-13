'use strict';

/**
 * TraceGuard Formal Security Rule Catalogue
 *
 * Defines canonical metadata for all deterministic detection rules
 * across prompt and output inspection stages.
 *
 * This catalogue is maintained independently of scanner execution mechanics
 * and policy engine conflict-resolution logic.
 */

const RULE_CATALOGUE = [
  // =========================================================================
  // Prompt & Retrieved Content Scanner Rules (PI-001 to PI-006)
  // =========================================================================
  {
    id: 'PI-001',
    version: '1.0.0',
    name: 'Instruction Override / Prompt Injection',
    description: 'Detects patterns that instruct the model to ignore, disregard, or override previous instructions or system rules.',
    stage: 'prompt',
    threat_category: 'prompt_injection_indicator',
    default_severity: 'high',
    detection_scope: 'Direct command phrases seeking to cancel antecedent instructions (e.g., "ignore all previous instructions", "disregard prior rules", "forget previous context").',
    limitations: 'Cannot catch highly novel semantic rephrasings without trigger terms; does not evaluate probabilistic intent; benign educational queries discussing the phrase in quotation marks are contextually distinguished.',
    recommended_action: 'Flag or block under configured content policy. Evaluate conversation context.',
    matching_conditions: {
      triggers: ['ignore', 'disregard', 'forget', 'override', 'do not follow'],
      targets: ['instructions', 'prompts', 'rules', 'directives', 'guidelines', 'context'],
      case_sensitive: false,
    },
    test_fixtures: ['TC-PI-001-DIRECT', 'TC-PI-001-DISREGARD', 'TC-PI-001-FORGET', 'TC-PI-001-PUNCTUATED'],
  },
  {
    id: 'PI-002',
    version: '1.0.0',
    name: 'Role-Switching / Identity Override',
    description: 'Detects attempts to alter the model identity, enter unrestricted modes, or bypass safety guardrails.',
    stage: 'prompt',
    threat_category: 'prompt_injection_indicator',
    default_severity: 'high',
    detection_scope: 'Jailbreak framing such as DAN mode, developer mode, god mode, or commands asserting the model is "now an unrestricted AI".',
    limitations: 'May not detect fictional storytelling where character play is legitimate and does not attack safety policies.',
    recommended_action: 'Flag or block request. Review for repeated jailbreak patterns from caller.',
    matching_conditions: {
      triggers: ['you are now', 'enter into mode', 'switch to mode', 'act as an', 'pretend you are'],
      keywords: ['unrestricted', 'unfiltered', 'jailbroken', 'evil', 'DAN', 'developer mode'],
      case_sensitive: false,
    },
    test_fixtures: ['TC-PI-002-UNRESTRICTED', 'TC-PI-002-DAN', 'TC-PI-002-ACT-AS'],
  },
  {
    id: 'PI-003',
    version: '1.0.0',
    name: 'System Prompt Extraction',
    description: 'Detects requests attempting to induce the model into disclosing its internal, system-level, or developer instructions.',
    stage: 'prompt',
    threat_category: 'system_prompt_extraction',
    default_severity: 'medium',
    detection_scope: 'Verbs requesting disclosure (reveal, show, output, print, repeat) applied to hidden/system prompts or directives.',
    limitations: 'Users asking how system prompts work generally will not match; matches specifically targeted extraction directives.',
    recommended_action: 'Flag for security review. Confirm system prompt contains no unredacted proprietary data.',
    matching_conditions: {
      triggers: ['reveal', 'show me', 'what is your', 'print', 'output', 'repeat'],
      targets: ['system prompt', 'hidden instructions', 'system message', 'developer directive'],
      case_sensitive: false,
    },
    test_fixtures: ['TC-PI-003-REVEAL', 'TC-PI-003-HIDDEN', 'TC-PI-003-WHAT-IS'],
  },
  {
    id: 'PI-004',
    version: '1.0.0',
    name: 'Credential / Secret Exfiltration Attempt',
    description: 'Detects instructions directing the model to extract, leak, transfer, or exfiltrate private credentials, keys, or passwords.',
    stage: 'prompt',
    threat_category: 'data_exfiltration_indicator',
    default_severity: 'high',
    detection_scope: 'Imperative commands to transfer, leak, or exfiltrate secrets, API keys, or databases to external URLs or destinations.',
    limitations: 'Requires explicit exfiltration intent verbs or combination of sensitive data keywords with extraction actions; conceptual discussions of data exfiltration are not flagged.',
    recommended_action: 'Block interaction immediately under data protection policy to prevent credential theft.',
    matching_conditions: {
      triggers: ['give me the api key', 'send secrets to', 'exfiltrate', 'leak confidential', 'transfer data to http'],
      case_sensitive: false,
    },
    test_fixtures: ['TC-PI-004-GIVE-KEY', 'TC-PI-004-SEND-EXTERNAL', 'TC-PI-004-EXFILTRATE-KEYWORD'],
  },
  {
    id: 'PI-005',
    version: '1.0.0',
    name: 'Encoded / Obfuscated Instruction Payload',
    description: 'Detects encoded payload instructions combined with execution commands designed to hide malicious directives.',
    stage: 'prompt',
    threat_category: 'prompt_injection_indicator',
    default_severity: 'medium',
    detection_scope: 'Instructions pairing encoding indicators (Base64, hex) with execution directives (decode and execute/run/follow).',
    limitations: 'Does not flag harmless Base64 data strings without decode-and-execute commands.',
    recommended_action: 'Flag for deeper inspection. Decode and inspect underlying payload before processing.',
    matching_conditions: {
      triggers: ['base64 decode and execute', 'decode the following and run', 'execute encoded payload'],
      case_sensitive: false,
    },
    test_fixtures: ['TC-PI-005-BASE64-EXEC'],
  },
  {
    id: 'PI-006',
    version: '1.0.0',
    name: 'Indirect Injection Marker in Context',
    description: 'Detects synthetic instruction boundary markup and injection delimiters embedded within external or retrieved context.',
    stage: 'prompt',
    threat_category: 'indirect_injection_indicator',
    default_severity: 'high',
    detection_scope: 'Model framing delimiters ([INST], [SYSTEM], <<SYS>>, ### instruction:) and injection signatures embedded in external content.',
    limitations: 'Only scans content presented as retrieved context or external document chunks.',
    recommended_action: 'Isolate or reject the retrieved document chunk. Record provenance trace evidence.',
    matching_conditions: {
      delimiters: ['[INST]', '[SYSTEM]', '<<SYS>>', '### instruction:', 'BEGIN INJECTION', 'IMPORTANT: ignore all other'],
      case_sensitive: false,
    },
    test_fixtures: ['TC-PI-006-INST', 'TC-PI-006-SYSTEM', 'TC-PI-006-RETRIEVED-OVERRIDE'],
  },

  // =========================================================================
  // Output Scanner Rules (OS-001 to OS-007)
  // =========================================================================
  {
    id: 'OS-001',
    version: '1.0.0',
    name: 'Synthetic Demo Secret Exposure',
    description: 'Detects synthetic demo secret tokens matching the standard DEMO_SECRET_* pattern in model output.',
    stage: 'output',
    threat_category: 'synthetic_secret_exposure',
    default_severity: 'high',
    detection_scope: 'Tokens matching DEMO_SECRET_[A-Z0-9]{4,}.',
    limitations: 'Targeted synthetic benchmark tokens only; does not cover custom vendor tokens.',
    recommended_action: 'Redact token in delivered response and store partially masked audit evidence.',
    matching_conditions: {
      pattern: 'DEMO_SECRET_[A-Z0-9]{4,}',
      regex_flags: 'g',
    },
    test_fixtures: ['TC-OS-001-DEMO-SECRET'],
  },
  {
    id: 'OS-002',
    version: '1.0.0',
    name: 'Synthetic Secret Key Exposure',
    description: 'Detects synthetic secret key tokens matching the SECRET_KEY_* pattern in model output.',
    stage: 'output',
    threat_category: 'synthetic_secret_exposure',
    default_severity: 'high',
    detection_scope: 'Tokens matching SECRET_KEY_[A-Za-z0-9_]{4,}.',
    limitations: 'Detects explicit SECRET_KEY prefixes; non-prefixed random strings are handled by specific credential rules.',
    recommended_action: 'Redact token before output reaches user; record audit event.',
    matching_conditions: {
      pattern: 'SECRET_KEY_[A-Za-z0-9_]{4,}',
      regex_flags: 'g',
    },
    test_fixtures: ['TC-OS-002-SECRET-KEY'],
  },
  {
    id: 'OS-003',
    version: '1.0.0',
    name: 'API Key Disclosure',
    description: 'Detects live, test, and production API keys matching standard sk-* service key formats in model output.',
    stage: 'output',
    threat_category: 'api_key_exposure',
    default_severity: 'high',
    detection_scope: 'Stripe, OpenAI, and service API keys starting with sk-, sk_live-, sk_test-, or sk-prod- followed by 20+ characters.',
    limitations: 'Keys with non-standard proprietary prefixes require dedicated regex patterns.',
    recommended_action: 'Redact API key immediately; trigger credential rotation alert if matching production pattern.',
    matching_conditions: {
      pattern: '\\bsk[-_](live|test|prod)?[-_]?[A-Za-z0-9]{20,}\\b',
      regex_flags: 'g',
    },
    test_fixtures: ['TC-OS-003-SK-LIVE', 'TC-OS-003-SK-TEST'],
  },
  {
    id: 'OS-004',
    version: '1.0.0',
    name: 'Bearer Token Disclosure',
    description: 'Detects HTTP Authorization Bearer tokens and JSON Web Tokens (JWT) leaked in model output.',
    stage: 'output',
    threat_category: 'api_key_exposure',
    default_severity: 'medium',
    detection_scope: 'Strings prefixed with "Bearer " followed by 20+ base64/url-safe characters.',
    limitations: 'Tokens without the "Bearer " header prefix are evaluated under general credential rules.',
    recommended_action: 'Redact Bearer token; mask signature and payload in audit logs.',
    matching_conditions: {
      pattern: 'Bearer\\s+[A-Za-z0-9\\-._~+/]{20,}',
      regex_flags: 'g',
    },
    test_fixtures: ['TC-OS-004-BEARER'],
  },
  {
    id: 'OS-005',
    version: '1.0.0',
    name: 'Password Assignment Disclosure',
    description: 'Detects plain-text password assignments (password: ... or password = ...) in model responses.',
    stage: 'output',
    threat_category: 'credential_exposure',
    default_severity: 'high',
    detection_scope: 'Assignments matching password [: =] "value" where value is 8+ characters.',
    limitations: 'May match dummy examples in code tutorials; redaction protects user safety regardless.',
    recommended_action: 'Redact password assignment and record credential exposure event.',
    matching_conditions: {
      pattern: 'password\\s*[:=]\\s*["\']?[^\\s"\']{8,}["\']?',
      regex_flags: 'gi',
    },
    test_fixtures: ['TC-OS-005-PASS-ASSIGN', 'TC-OS-005-PASS-COLON'],
  },
  {
    id: 'OS-006',
    version: '1.0.0',
    name: 'Cloud Access Key Disclosure',
    description: 'Detects Amazon Web Services (AWS) style access key identifiers in model responses.',
    stage: 'output',
    threat_category: 'api_key_exposure',
    default_severity: 'medium',
    detection_scope: '20-character uppercase alphanumeric tokens beginning with AKIA, ABIA, ACCA, or ASIA.',
    limitations: 'Detects key IDs; secret access keys (40 chars) are detected by companion credential patterns.',
    recommended_action: 'Redact access key and check cloud provider credential status.',
    matching_conditions: {
      pattern: '\\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\\b',
      regex_flags: 'g',
    },
    test_fixtures: ['TC-OS-006-AWS-KEY'],
  },
  {
    id: 'OS-007',
    version: '1.0.0',
    name: 'Internal Service Token Exposure',
    description: 'Detects internal backend service tokens matching the INTERNAL_TOKEN_* pattern in model responses.',
    stage: 'output',
    threat_category: 'synthetic_secret_exposure',
    default_severity: 'high',
    detection_scope: 'Tokens matching INTERNAL_TOKEN_[A-Za-z0-9_]{4,}.',
    limitations: 'Internal system architecture specific pattern.',
    recommended_action: 'Redact token immediately; verify service authentication boundary.',
    matching_conditions: {
      pattern: 'INTERNAL_TOKEN_[A-Za-z0-9_]{4,}',
      regex_flags: 'g',
    },
    test_fixtures: ['TC-OS-007-INTERNAL-TOKEN'],
  },
];

/**
 * Look up a rule by its ID.
 * @param {string} id - Rule ID (e.g. 'PI-001', 'OS-003')
 * @returns {Object|null} Rule metadata or null
 */
function getRule(id) {
  if (!id || typeof id !== 'string') return null;
  return RULE_CATALOGUE.find(r => r.id === id.toUpperCase()) || null;
}

/**
 * List rules with optional filtering by stage or severity.
 * @param {Object} [filter]
 * @param {string} [filter.stage]
 * @param {string} [filter.threat_category]
 * @param {string} [filter.severity]
 * @returns {Array<Object>}
 */
function listRules(filter = {}) {
  return RULE_CATALOGUE.filter(r => {
    if (filter.stage && r.stage !== filter.stage) return false;
    if (filter.threat_category && r.threat_category !== filter.threat_category) return false;
    if (filter.severity && r.default_severity !== filter.severity) return false;
    return true;
  });
}

/**
 * Return all prompt scanner rules.
 * @returns {Array<Object>}
 */
function getPromptRules() {
  return listRules({ stage: 'prompt' });
}

/**
 * Return all output scanner rules.
 * @returns {Array<Object>}
 */
function getOutputRules() {
  return listRules({ stage: 'output' });
}

module.exports = {
  RULE_CATALOGUE,
  getRule,
  listRules,
  getPromptRules,
  getOutputRules,
};
