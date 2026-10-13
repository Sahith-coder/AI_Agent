'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { scanOutput, scanAndRedact, getRules } = require('../src/services/output-scanner');
const { redact } = require('../src/services/redaction-service');

describe('Output Scanner', () => {
  describe('getRules()', () => {
    it('should return rules with required fields', () => {
      const rules = getRules();
      assert.ok(Array.isArray(rules));
      assert.ok(rules.length >= 7, 'Expected at least 7 output rules');
      for (const rule of rules) {
        assert.ok(rule.id);
        assert.ok(rule.category);
        assert.ok(rule.severity);
      }
    });
  });

  describe('Normal output', () => {
    it('should return no findings for a normal answer', () => {
      const result = scanOutput('The weather in London is currently 15°C with light clouds.');
      assert.equal(result.findings.length, 0);
      assert.equal(result.summary.total, 0);
    });

    it('should return no findings for a code snippet', () => {
      const result = scanOutput('function add(a, b) { return a + b; }');
      assert.equal(result.findings.length, 0);
    });

    it('should not flag normal numbers or words', () => {
      const result = scanOutput('The total count is 12345 and the status is active.');
      assert.equal(result.findings.length, 0);
    });
  });

  describe('Synthetic secret detection (OS-001)', () => {
    it('should detect DEMO_SECRET_74XQ pattern', () => {
      const result = scanOutput('The demo credential is DEMO_SECRET_74XQ9 for testing.');
      assert.ok(result.findings.some(f => f.rule_id === 'OS-001'));
      assert.equal(result.findings.find(f => f.rule_id === 'OS-001').category,
        'synthetic_secret_exposure');
    });

    it('should detect DEMO_SECRET_ABCD1234', () => {
      const result = scanOutput('Use DEMO_SECRET_ABCD1234 to authenticate.');
      assert.ok(result.findings.some(f => f.rule_id === 'OS-001'));
    });
  });

  describe('SECRET_KEY detection (OS-002)', () => {
    it('should detect SECRET_KEY_* pattern', () => {
      const result = scanOutput('The key is SECRET_KEY_Production_ABC123.');
      assert.ok(result.findings.some(f => f.rule_id === 'OS-002'));
    });
  });

  describe('API key detection (OS-003)', () => {
    it('should detect sk-live API key pattern', () => {
      const mockLiveKey = ['sk', 'live', 'abcdefghijklmnopqrstuvwx'].join('-');
      const result = scanOutput(`Your API key is ${mockLiveKey}`);
      assert.ok(result.findings.some(f => f.rule_id === 'OS-003'));
      assert.equal(result.findings.find(f => f.rule_id === 'OS-003').category,
        'api_key_exposure');
    });

    it('should detect sk_test API key pattern', () => {
      const mockTestKey = ['sk', 'test', 'mockkey0123456789abcdef'].join('_');
      const result = scanOutput(`Use this test key: ${mockTestKey}`);
      assert.ok(result.findings.some(f => f.rule_id === 'OS-003'));
    });
  });

  describe('Bearer token detection (OS-004)', () => {
    it('should detect Bearer tokens', () => {
      const result = scanOutput('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature');
      assert.ok(result.findings.some(f => f.rule_id === 'OS-004'));
    });
  });

  describe('Password detection (OS-005)', () => {
    it('should detect password assignments', () => {
      const result = scanOutput('The database password = "SuperSecr3t!"');
      assert.ok(result.findings.some(f => f.rule_id === 'OS-005'));
    });

    it('should detect password: value patterns', () => {
      const result = scanOutput('password: my_secure_password_123');
      assert.ok(result.findings.some(f => f.rule_id === 'OS-005'));
    });
  });

  describe('INTERNAL_TOKEN detection (OS-007)', () => {
    it('should detect INTERNAL_TOKEN patterns', () => {
      const result = scanOutput('Access with INTERNAL_TOKEN_AdminAccess789');
      assert.ok(result.findings.some(f => f.rule_id === 'OS-007'));
    });
  });
});

describe('Redaction Service', () => {
  it('should redact sensitive patterns and produce sanitized output', () => {
    const text = 'The secret is DEMO_SECRET_74XQ9 and the key is SECRET_KEY_Test1234.';
    const matches = [
      { pattern: /DEMO_SECRET_[A-Z0-9]{4,}/g, label: 'DEMO_SECRET' },
      { pattern: /SECRET_KEY_[A-Za-z0-9_]{4,}/g, label: 'SECRET_KEY' },
    ];
    const result = redact(text, matches);

    assert.ok(!result.sanitized.includes('DEMO_SECRET_74XQ9'),
      'Sanitized output must not contain the raw secret');
    assert.ok(result.sanitized.includes('[REDACTED:DEMO_SECRET]'),
      'Sanitized output must show redaction marker');
    assert.ok(!result.sanitized.includes('SECRET_KEY_Test1234'));

    // Redacted evidence should have partial prefix, not the full secret
    assert.ok(!result.redacted_evidence.includes('DEMO_SECRET_74XQ9'),
      'Audit evidence must not contain the full raw secret');
    assert.ok(result.redacted_evidence.includes('DEM***'),
      'Audit evidence should have partial prefix');

    assert.ok(result.redaction_count >= 2);
  });

  it('should not modify unrelated content', () => {
    const text = 'Normal text with no secrets.';
    const result = redact(text, []);
    assert.equal(result.sanitized, text);
    assert.equal(result.redacted_evidence, text);
    assert.equal(result.redaction_count, 0);
  });

  it('should preserve surrounding text', () => {
    const text = 'Before DEMO_SECRET_ABCD After';
    const matches = [
      { pattern: /DEMO_SECRET_[A-Z0-9]{4,}/g, label: 'DEMO_SECRET' },
    ];
    const result = redact(text, matches);
    assert.ok(result.sanitized.startsWith('Before '));
    assert.ok(result.sanitized.endsWith(' After'));
  });
});

describe('Output Scanner — scanAndRedact', () => {
  it('should detect and redact synthetic secrets in one call', () => {
    const text = 'Here is the credential: DEMO_SECRET_74XQ9 for your use.';
    const result = scanAndRedact(text);

    assert.ok(result.findings.length > 0, 'Should detect the secret');
    assert.ok(!result.sanitized_content.includes('DEMO_SECRET_74XQ9'),
      'Sanitized content must not contain the raw secret');
    assert.ok(result.sanitized_content.includes('[REDACTED:DEMO_SECRET]'));

    // Audit evidence must not contain the raw secret
    assert.ok(!result.redacted_evidence.includes('DEMO_SECRET_74XQ9'),
      'Persisted audit evidence must not reveal the raw secret');
    assert.ok(result.redaction_count > 0);
  });

  it('should pass through clean output without modification', () => {
    const text = 'This is a perfectly normal response about the weather.';
    const result = scanAndRedact(text);

    assert.equal(result.findings.length, 0);
    assert.equal(result.sanitized_content, text);
    assert.equal(result.redaction_count, 0);
  });
});
