'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { evaluate, getPolicies } = require('../src/services/policy-engine');

describe('Policy Engine', () => {
  describe('getPolicies()', () => {
    it('should return an array of policy rules', () => {
      const policies = getPolicies();
      assert.ok(Array.isArray(policies));
      assert.ok(policies.length >= 4, 'Expected at least 4 policy rules');
      for (const p of policies) {
        assert.ok(p.label);
        assert.ok(p.decision);
      }
    });
  });

  describe('allow decision', () => {
    it('should return allow when there are no findings', () => {
      const result = evaluate([]);
      assert.equal(result.decision, 'allow');
      assert.equal(result.severity, 'info');
      assert.equal(result.findings_count, 0);
      assert.equal(result.recommended_action, null);
    });

    it('should return allow for null findings', () => {
      const result = evaluate(null);
      assert.equal(result.decision, 'allow');
    });
  });

  describe('flag decision', () => {
    it('should flag prompt injection indicators', () => {
      const findings = [{
        rule_id: 'PI-001',
        category: 'prompt_injection_indicator',
        severity: 'high',
        reason: 'Instruction override detected.',
      }];
      const result = evaluate(findings);
      assert.equal(result.decision, 'flag');
      assert.equal(result.severity, 'high');
      assert.ok(result.reasons.length > 0);
      assert.ok(result.recommended_action);
    });

    it('should flag system prompt extraction attempts', () => {
      const findings = [{
        rule_id: 'PI-003',
        category: 'system_prompt_extraction',
        severity: 'medium',
        reason: 'System prompt extraction attempt.',
      }];
      const result = evaluate(findings);
      assert.equal(result.decision, 'flag');
    });

    it('should flag indirect injection indicators', () => {
      const findings = [{
        rule_id: 'PI-006',
        category: 'indirect_injection_indicator',
        severity: 'high',
        reason: 'Indirect injection markers.',
      }];
      const result = evaluate(findings);
      assert.equal(result.decision, 'flag');
    });
  });

  describe('redact decision', () => {
    it('should redact synthetic secret exposure', () => {
      const findings = [{
        rule_id: 'OS-001',
        category: 'synthetic_secret_exposure',
        severity: 'high',
        reason: 'DEMO_SECRET detected.',
      }];
      const result = evaluate(findings);
      assert.equal(result.decision, 'redact');
      assert.ok(result.recommended_action.includes('redacted'));
    });

    it('should redact credential exposure', () => {
      const findings = [{
        rule_id: 'OS-005',
        category: 'credential_exposure',
        severity: 'high',
        reason: 'Password found.',
      }];
      const result = evaluate(findings);
      assert.equal(result.decision, 'redact');
    });

    it('should redact high-severity API key exposure', () => {
      const findings = [{
        rule_id: 'OS-003',
        category: 'api_key_exposure',
        severity: 'high',
        reason: 'API key pattern detected.',
      }];
      const result = evaluate(findings);
      assert.equal(result.decision, 'redact');
    });
  });

  describe('block decision', () => {
    it('should block high-severity data exfiltration indicators', () => {
      const findings = [{
        rule_id: 'PI-004',
        category: 'data_exfiltration_indicator',
        severity: 'high',
        reason: 'Exfiltration attempt detected.',
      }];
      const result = evaluate(findings);
      assert.equal(result.decision, 'block');
      assert.ok(result.recommended_action.includes('blocked'));
    });
  });

  describe('Severity vs decision separation', () => {
    it('should use the highest severity from findings regardless of decision', () => {
      // Medium-severity API key exposure → flag decision, medium severity
      const findings = [{
        rule_id: 'OS-004',
        category: 'api_key_exposure',
        severity: 'medium',
        reason: 'Bearer token detected.',
      }];
      const result = evaluate(findings);
      assert.equal(result.severity, 'medium');
      assert.equal(result.decision, 'flag');
    });
  });

  describe('Multiple findings — highest decision wins', () => {
    it('should return block when block and flag findings coexist', () => {
      const findings = [
        {
          rule_id: 'PI-001',
          category: 'prompt_injection_indicator',
          severity: 'high',
          reason: 'Injection indicator.',
        },
        {
          rule_id: 'PI-004',
          category: 'data_exfiltration_indicator',
          severity: 'high',
          reason: 'Exfiltration.',
        },
      ];
      const result = evaluate(findings);
      assert.equal(result.decision, 'block', 'Block should win over flag');
    });

    it('should return redact when redact and flag findings coexist', () => {
      const findings = [
        {
          rule_id: 'PI-001',
          category: 'prompt_injection_indicator',
          severity: 'high',
          reason: 'Injection.',
        },
        {
          rule_id: 'OS-001',
          category: 'synthetic_secret_exposure',
          severity: 'high',
          reason: 'Secret found.',
        },
      ];
      const result = evaluate(findings);
      assert.equal(result.decision, 'redact', 'Redact should win over flag');
    });
  });

  describe('Default flag for unmatched findings', () => {
    it('should default to flag if findings exist but no policy matches', () => {
      const findings = [{
        rule_id: 'UNKNOWN-001',
        category: 'unknown_category',
        severity: 'low',
        reason: 'Unknown finding.',
      }];
      const result = evaluate(findings);
      assert.equal(result.decision, 'flag');
    });
  });
});
