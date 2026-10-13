'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { initDatabase, _reset } = require('../src/db/database');
const auditService = require('../src/services/audit-service');
const { isValidTraceId } = require('../src/services/trace-service');

describe('Audit Service', () => {
  before(async () => {
    _reset();
    await initDatabase(':memory:');
  });

  after(() => {
    _reset();
  });

  describe('createInteraction()', () => {
    it('should create an interaction with a generated trace_id', () => {
      const result = auditService.createInteraction(null, 'Test request');
      assert.ok(result.trace_id, 'Must return a trace_id');
      assert.ok(isValidTraceId(result.trace_id), 'trace_id must have valid format');
      assert.ok(result.created_at, 'Must return created_at');
    });

    it('should use a provided trace_id', () => {
      const customId = 'tg-00000000-0000-0000-0000-000000000001';
      const result = auditService.createInteraction(customId, 'Custom ID test');
      assert.equal(result.trace_id, customId);
    });
  });

  describe('getOrCreateInteraction()', () => {
    it('should return existing interaction when trace_id matches', () => {
      const first = auditService.createInteraction(null, 'First');
      const second = auditService.getOrCreateInteraction(first.trace_id);
      assert.equal(second.trace_id, first.trace_id);
      assert.equal(second.is_new, false);
    });

    it('should create a new interaction when trace_id is null', () => {
      const result = auditService.getOrCreateInteraction(null, 'New one');
      assert.ok(result.trace_id);
      assert.equal(result.is_new, true);
    });

    it('should create a new interaction when trace_id does not exist', () => {
      const result = auditService.getOrCreateInteraction('tg-nonexistent-id', 'Fallback');
      assert.ok(result.trace_id);
      assert.equal(result.is_new, true);
    });
  });

  describe('addSecurityEvent()', () => {
    it('should add an event and return an event_id', () => {
      const interaction = auditService.createInteraction(null, 'Event test');
      const eventId = auditService.addSecurityEvent({
        trace_id: interaction.trace_id,
        stage: 'prompt',
        event_type: 'threat_detected',
        threat_category: 'prompt_injection_indicator',
        severity: 'high',
        policy_decision: 'flag',
        reason: 'Test reason',
        redacted_evidence: 'Some evidence',
      });
      assert.ok(eventId, 'Must return event_id');
      assert.ok(eventId.startsWith('ev-'), 'event_id must start with ev-');
    });
  });

  describe('updateInteractionStatus()', () => {
    it('should update the status', () => {
      const interaction = auditService.createInteraction(null, 'Status test');
      auditService.updateInteractionStatus(interaction.trace_id, 'completed');
      const trace = auditService.getTrace(interaction.trace_id);
      assert.equal(trace.interaction.status, 'completed');
    });
  });

  describe('listEvents()', () => {
    it('should return events array', () => {
      const events = auditService.listEvents({});
      assert.ok(Array.isArray(events));
    });

    it('should filter by severity', () => {
      const interaction = auditService.createInteraction(null, 'Filter test');
      auditService.addSecurityEvent({
        trace_id: interaction.trace_id,
        stage: 'prompt',
        event_type: 'scan_clean',
        severity: 'info',
        policy_decision: 'allow',
      });
      auditService.addSecurityEvent({
        trace_id: interaction.trace_id,
        stage: 'output',
        event_type: 'threat_detected',
        severity: 'high',
        policy_decision: 'redact',
      });

      const highEvents = auditService.listEvents({ severity: 'high', trace_id: interaction.trace_id });
      for (const ev of highEvents) {
        assert.equal(ev.severity, 'high');
      }
    });

    it('should respect the limit parameter', () => {
      const events = auditService.listEvents({ limit: 2 });
      assert.ok(events.length <= 2);
    });
  });

  describe('getTrace()', () => {
    it('should return interaction and all events for a trace', () => {
      const interaction = auditService.createInteraction(null, 'Trace test');
      auditService.addSecurityEvent({
        trace_id: interaction.trace_id,
        stage: 'prompt',
        event_type: 'scan_clean',
        severity: 'info',
        policy_decision: 'allow',
        reason: 'Clean',
      });
      auditService.addSecurityEvent({
        trace_id: interaction.trace_id,
        stage: 'output',
        event_type: 'threat_detected',
        severity: 'high',
        policy_decision: 'redact',
        reason: 'Secret detected',
      });

      const trace = auditService.getTrace(interaction.trace_id);
      assert.ok(trace, 'Trace must not be null');
      assert.ok(trace.interaction);
      assert.equal(trace.interaction.trace_id, interaction.trace_id);
      assert.ok(Array.isArray(trace.events));
      assert.equal(trace.events.length, 2);
    });

    it('should return null for non-existent trace', () => {
      const result = auditService.getTrace('tg-does-not-exist');
      assert.equal(result, null);
    });
  });

  describe('getStats()', () => {
    it('should return aggregate statistics from real data', () => {
      const stats = auditService.getStats();
      assert.ok(typeof stats.total_events === 'number');
      assert.ok(typeof stats.total_interactions === 'number');
      assert.ok(Array.isArray(stats.by_severity));
      assert.ok(Array.isArray(stats.by_stage));
      assert.ok(Array.isArray(stats.by_decision));
      assert.ok(typeof stats.recent_24h === 'number');
      assert.ok(stats.total_events > 0, 'Should have events from earlier tests');
      assert.ok(stats.total_interactions > 0);
    });
  });
});
