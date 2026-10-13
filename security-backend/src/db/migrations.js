'use strict';

/**
 * TraceGuard Database Migrations
 *
 * Versioned, idempotent migration mechanism using schema_migrations table.
 * Preserves existing data, enforces foreign keys, and supports schema evolution.
 */

const MIGRATIONS = [
  {
    version: 1,
    name: '001_initial_schema',
    up(db) {
      db.exec(`
        CREATE TABLE IF NOT EXISTS interactions (
            trace_id        TEXT PRIMARY KEY,
            created_at      TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
            status          TEXT NOT NULL DEFAULT 'processing',
            request_summary TEXT
        );

        CREATE TABLE IF NOT EXISTS security_events (
            event_id            TEXT PRIMARY KEY,
            trace_id            TEXT NOT NULL,
            sequence_no         INTEGER NOT NULL DEFAULT 1,
            parent_event_id     TEXT,
            call_id             TEXT,
            timestamp           TEXT NOT NULL DEFAULT (datetime('now')),
            stage               TEXT NOT NULL,
            event_type          TEXT NOT NULL,
            threat_category     TEXT,
            severity            TEXT NOT NULL DEFAULT 'info',
            policy_decision     TEXT,
            rule_id             TEXT,
            rule_version        TEXT,
            policy_version      TEXT,
            reason              TEXT,
            source_id           TEXT,
            execution_outcome   TEXT,
            duration_ms         INTEGER,
            redacted_evidence   TEXT,
            metadata_json       TEXT,
            FOREIGN KEY (trace_id) REFERENCES interactions(trace_id),
            FOREIGN KEY (parent_event_id) REFERENCES security_events(event_id)
        );

        CREATE INDEX IF NOT EXISTS idx_events_trace_id   ON security_events(trace_id);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_severity   ON security_events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_stage      ON security_events(stage);
        CREATE INDEX IF NOT EXISTS idx_events_decision   ON security_events(policy_decision);
      `);
    },
  },
  {
    version: 2,
    name: '002_task2_hardening',
    up(db) {
      // 1. Ensure any missing columns on security_events are added (for upgrading v1 databases)
      const tableInfo = db.exec("PRAGMA table_info(security_events);");
      const existingColumns = new Set();
      if (tableInfo.length > 0 && tableInfo[0].values) {
        for (const row of tableInfo[0].values) {
          existingColumns.add(row[1]); // column name is index 1
        }
      }

      const columnsToAdd = [
        { name: 'sequence_no', type: 'INTEGER NOT NULL DEFAULT 1' },
        { name: 'parent_event_id', type: 'TEXT' },
        { name: 'call_id', type: 'TEXT' },
        { name: 'rule_id', type: 'TEXT' },
        { name: 'rule_version', type: 'TEXT' },
        { name: 'policy_version', type: 'TEXT' },
        { name: 'duration_ms', type: 'INTEGER' },
        { name: 'metadata_json', type: 'TEXT' },
      ];

      for (const col of columnsToAdd) {
        if (!existingColumns.has(col.name)) {
          db.exec(`ALTER TABLE security_events ADD COLUMN ${col.name} ${col.type};`);
        }
      }

      db.exec(`CREATE INDEX IF NOT EXISTS idx_events_trace_seq ON security_events(trace_id, sequence_no);`);

      // 2. Retrieval records table (B4)
      db.exec(`
        CREATE TABLE IF NOT EXISTS retrieval_records (
            retrieval_id               TEXT PRIMARY KEY,
            trace_id                   TEXT NOT NULL,
            event_id                   TEXT,
            call_id                    TEXT,
            source_id                  TEXT NOT NULL,
            source_label               TEXT NOT NULL,
            source_version             TEXT,
            source_hash                TEXT,
            chunk_id                   TEXT,
            chunk_hash                 TEXT,
            retrieval_order            INTEGER NOT NULL DEFAULT 1,
            relevance_score            REAL,
            trust_metadata             TEXT,
            included_in_model_context  INTEGER NOT NULL DEFAULT 1,
            redacted_excerpt           TEXT,
            created_at                 TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (trace_id) REFERENCES interactions(trace_id),
            FOREIGN KEY (event_id) REFERENCES security_events(event_id)
        );

        CREATE INDEX IF NOT EXISTS idx_retrieval_trace_id ON retrieval_records(trace_id);
        CREATE INDEX IF NOT EXISTS idx_retrieval_source_id ON retrieval_records(source_id);
      `);

      // 3. Dedicated tool events table (B5)
      db.exec(`
        CREATE TABLE IF NOT EXISTS tool_events (
            tool_event_id               TEXT PRIMARY KEY,
            trace_id                    TEXT NOT NULL,
            event_id                    TEXT,
            sequence_no                 INTEGER,
            parent_event_id             TEXT,
            call_id                     TEXT,
            tool_name                   TEXT NOT NULL,
            tool_server_identity        TEXT,
            sanitized_argument_summary  TEXT NOT NULL,
            argument_hash               TEXT,
            source_metadata             TEXT,
            suspicion_indicators        TEXT,
            timestamp                   TEXT NOT NULL DEFAULT (datetime('now')),
            execution_outcome           TEXT NOT NULL CHECK(execution_outcome IN ('proposed', 'started', 'succeeded', 'failed', 'denied', 'unknown')),
            redacted_result_summary     TEXT,
            FOREIGN KEY (trace_id) REFERENCES interactions(trace_id),
            FOREIGN KEY (event_id) REFERENCES security_events(event_id),
            FOREIGN KEY (parent_event_id) REFERENCES security_events(event_id)
        );

        CREATE INDEX IF NOT EXISTS idx_tool_events_trace_id ON tool_events(trace_id);
        CREATE INDEX IF NOT EXISTS idx_tool_events_tool_name ON tool_events(tool_name);
        CREATE INDEX IF NOT EXISTS idx_tool_events_outcome ON tool_events(execution_outcome);
      `);

      // 4. Attack Lab test runs and results (B6)
      db.exec(`
        CREATE TABLE IF NOT EXISTS test_runs (
            run_id              TEXT PRIMARY KEY,
            started_at          TEXT NOT NULL DEFAULT (datetime('now')),
            completed_at        TEXT,
            test_suite_version  TEXT NOT NULL,
            app_version         TEXT,
            rule_version        TEXT,
            policy_version      TEXT,
            status              TEXT NOT NULL CHECK(status IN ('running', 'passed', 'failed', 'error', 'cancelled')),
            test_case_count     INTEGER NOT NULL DEFAULT 0,
            model_metadata      TEXT
        );

        CREATE TABLE IF NOT EXISTS test_results (
            result_id               TEXT PRIMARY KEY,
            run_id                  TEXT NOT NULL,
            case_id                 TEXT NOT NULL,
            trace_id                TEXT,
            expected_classification TEXT,
            actual_findings         TEXT,
            expected_decision       TEXT,
            actual_decision         TEXT,
            pass_fail_result        TEXT NOT NULL CHECK(pass_fail_result IN ('pass', 'fail', 'error', 'skipped')),
            latency_ms              REAL,
            event_references        TEXT,
            FOREIGN KEY (run_id) REFERENCES test_runs(run_id),
            FOREIGN KEY (trace_id) REFERENCES interactions(trace_id)
        );

        CREATE INDEX IF NOT EXISTS idx_test_results_run_id ON test_results(run_id);
        CREATE INDEX IF NOT EXISTS idx_test_results_case_id ON test_results(case_id);
      `);

      // 5. Backfill sequence numbers for any legacy events without sequence_no > 1
      const traces = db.exec("SELECT DISTINCT trace_id FROM security_events;");
      if (traces.length > 0 && traces[0].values) {
        for (const [tId] of traces[0].values) {
          const events = db.exec(`SELECT event_id FROM security_events WHERE trace_id = '${tId}' ORDER BY timestamp ASC;`);
          if (events.length > 0 && events[0].values) {
            let seq = 1;
            for (const [eId] of events[0].values) {
              db.exec(`UPDATE security_events SET sequence_no = ${seq} WHERE event_id = '${eId}';`);
              seq++;
            }
          }
        }
      }
    },
  },
];

/**
 * Apply pending migrations in order.
 * @param {object} db — sql.js Database instance.
 * @returns {Array<{ version: number, name: string }>} — list of newly applied migrations.
 */
function applyMigrations(db) {
  // Ensure migration tracking table exists
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version     INTEGER PRIMARY KEY,
        name        TEXT NOT NULL,
        applied_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Query already applied versions
  const appliedResult = db.exec("SELECT version FROM schema_migrations ORDER BY version ASC;");
  const appliedVersions = new Set();
  if (appliedResult.length > 0 && appliedResult[0].values) {
    for (const row of appliedResult[0].values) {
      appliedVersions.add(row[0]);
    }
  }

  const newlyApplied = [];

  for (const migration of MIGRATIONS) {
    if (!appliedVersions.has(migration.version)) {
      db.exec('BEGIN IMMEDIATE;');
      try {
        migration.up(db);
        const now = new Date().toISOString();
        db.exec(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (${migration.version}, '${migration.name}', '${now}');`);
        db.exec('COMMIT;');
        newlyApplied.push({ version: migration.version, name: migration.name });
      } catch (err) {
        try { db.exec('ROLLBACK;'); } catch { /* ignore */ }
        throw new Error(`Migration ${migration.version} (${migration.name}) failed: ${err.message}`);
      }
    }
  }

  return newlyApplied;
}

/**
 * Get current migration status.
 * @param {object} db
 * @returns {{ current_version: number, applied: Array }}
 */
function getMigrationStatus(db) {
  const result = db.exec("SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC;");
  if (result.length === 0 || !result[0].values) {
    return { current_version: 0, applied: [] };
  }
  const applied = result[0].values.map(r => ({
    version: r[0],
    name: r[1],
    applied_at: r[2],
  }));
  const current_version = applied.length > 0 ? applied[applied.length - 1].version : 0;
  return { current_version, applied };
}

module.exports = {
  MIGRATIONS,
  applyMigrations,
  getMigrationStatus,
};
