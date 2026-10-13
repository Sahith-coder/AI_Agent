-- TraceGuard Security Backend — SQLite Schema
-- Canonical Schema (v2 - Hardened Trace, Event, Provenance, Tool, and Attack Lab contracts)

-- 1. Interactions / Traces
CREATE TABLE IF NOT EXISTS interactions (
    trace_id        TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    status          TEXT NOT NULL DEFAULT 'processing',
    request_summary TEXT
);

-- 2. Security Events (correlated to interactions, monotonic sequence ordering)
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

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_events_trace_id   ON security_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity   ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_stage      ON security_events(stage);
CREATE INDEX IF NOT EXISTS idx_events_decision   ON security_events(policy_decision);
CREATE UNIQUE INDEX IF NOT EXISTS uidx_events_trace_seq ON security_events(trace_id, sequence_no);

-- 3. Retrieval Provenance Storage (B4)
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

-- 4. Observational Tool & MCP Events Storage (B5)
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
CREATE INDEX IF NOT EXISTS idx_tool_events_call_id ON tool_events(call_id);
CREATE INDEX IF NOT EXISTS idx_tool_events_trace_call ON tool_events(trace_id, call_id);

-- 5. Attack Lab Persistence Contracts (B6)
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
CREATE INDEX IF NOT EXISTS idx_test_runs_started_at ON test_runs(started_at);
CREATE INDEX IF NOT EXISTS idx_test_results_pass_fail ON test_results(run_id, pass_fail_result);

-- 6. Clarification Sessions Persistence (Task 4)
CREATE TABLE IF NOT EXISTS clarification_sessions (
    session_id              TEXT PRIMARY KEY,
    trace_id                TEXT NOT NULL,
    query                   TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'resolved', 'stale', 'cancelled')),
    candidates_json         TEXT NOT NULL,
    selected_candidate_id   TEXT,
    clarification_prompt    TEXT,
    created_at              TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at              TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at             TEXT,
    FOREIGN KEY (trace_id) REFERENCES interactions(trace_id)
);

CREATE INDEX IF NOT EXISTS idx_clarification_trace_id ON clarification_sessions(trace_id);
CREATE INDEX IF NOT EXISTS idx_clarification_status   ON clarification_sessions(status);
