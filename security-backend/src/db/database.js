'use strict';

const fs = require('node:fs');
const path = require('node:path');
const initSqlJs = require('sql.js');
const config = require('../config');
const { applyMigrations, getMigrationStatus } = require('./migrations');

let _db = null;
let _dbPath = null;
let _isPersisting = false;

/**
 * Initialize the SQLite database using sql.js.
 * sql.js requires async initialization (WASM loading), then provides a synchronous query API.
 *
 * @param {string} [dbPath] — override path for test isolation. Use ':memory:' for in-memory.
 * @returns {Promise<object>} — the sql.js Database instance.
 */
async function initDatabase(dbPath) {
  if (_db) return _db;

  const SQL = await initSqlJs();
  const resolvedPath = dbPath !== undefined ? dbPath : config.sqlitePath;
  _dbPath = resolvedPath;

  if (resolvedPath === ':memory:') {
    _db = new SQL.Database();
  } else {
    const dir = path.dirname(resolvedPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    if (fs.existsSync(resolvedPath)) {
      const buffer = fs.readFileSync(resolvedPath);
      _db = new SQL.Database(buffer);
    } else {
      _db = new SQL.Database();
    }
  }

  // 1. Enable foreign keys
  _db.exec('PRAGMA foreign_keys = ON;');

  // 2. Run versioned migrations safely
  applyMigrations(_db);

  // 3. Persist schema immediately if file-backed
  if (_dbPath && _dbPath !== ':memory:') {
    persist();
  }

  return _db;
}

/**
 * Get the current database instance (must call initDatabase first).
 * @returns {object} — sql.js Database instance.
 * @throws if database is not initialized.
 */
function getDatabase() {
  if (!_db) {
    throw new Error('Database not initialized. Call initDatabase() first.');
  }
  return _db;
}

/**
 * Check if the database is healthy.
 * @returns {boolean}
 */
function isHealthy() {
  try {
    if (!_db) return false;
    const result = _db.exec('SELECT 1 AS ok');
    return result.length > 0 && result[0].values[0][0] === 1;
  } catch {
    return false;
  }
}

/**
 * Persist the in-memory database to disk atomically (sql.js operates in-memory).
 * Writes exported bytes to a temporary file, then renames to target.
 */
function persist() {
  if (!_db || !_dbPath || _dbPath === ':memory:') return;
  if (_isPersisting) return;

  _isPersisting = true;
  try {
    const data = _db.export();
    const buffer = Buffer.from(data);
    const dir = path.dirname(_dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Atomic write pattern: write to tmp file then atomic rename
    const tmpPath = `${_dbPath}.${Date.now()}.${Math.random().toString(36).substring(2, 8)}.tmp`;
    fs.writeFileSync(tmpPath, buffer);
    try {
      fs.renameSync(tmpPath, _dbPath);
    } catch {
      // Fallback for Windows file locks: copy and unlink
      fs.copyFileSync(tmpPath, _dbPath);
      try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
    }
  } catch (err) {
    console.error(`[ERROR] Database persistence failed: ${err.message}`);
    throw err;
  } finally {
    _isPersisting = false;
  }
}

/**
 * Close the database and persist if file-backed.
 */
function close() {
  if (_db) {
    try {
      persist();
    } catch { /* ignore */ }
    _db.close();
    _db = null;
    _dbPath = null;
  }
}

/**
 * Reset the module-level db reference (for test isolation).
 */
function _reset() {
  if (_db) {
    try { _db.close(); } catch { /* ignore */ }
  }
  _db = null;
  _dbPath = null;
}

// ---------------------------------------------------------------------------
// Helpers: parameterized query execution with automatic persistence
// ---------------------------------------------------------------------------

/**
 * Execute a parameterized write statement (INSERT, UPDATE, DELETE).
 * @param {string} sql
 * @param {Array} params
 */
function run(sql, params = []) {
  const db = getDatabase();
  db.run(sql, params);
  if (_dbPath && _dbPath !== ':memory:') {
    persist();
  }
}

/**
 * Execute raw SQL (e.g., schema commands).
 * @param {string} sql
 */
function exec(sql) {
  const db = getDatabase();
  db.exec(sql);
  if (_dbPath && _dbPath !== ':memory:') {
    persist();
  }
}

/**
 * Execute a function within a SQLite transaction.
 * @param {Function} fn
 * @returns {*}
 */
function transaction(fn) {
  const db = getDatabase();
  db.exec('BEGIN IMMEDIATE;');
  try {
    const result = fn();
    db.exec('COMMIT;');
    if (_dbPath && _dbPath !== ':memory:') {
      persist();
    }
    return result;
  } catch (err) {
    try { db.exec('ROLLBACK;'); } catch { /* ignore */ }
    throw err;
  }
}

/**
 * Execute a parameterized SELECT and return all rows as objects.
 * @param {string} sql
 * @param {Array} params
 * @returns {Array<Object>}
 */
function all(sql, params = []) {
  const db = getDatabase();
  const stmt = db.prepare(sql);
  if (params.length > 0) {
    stmt.bind(params);
  }

  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

/**
 * Execute a parameterized SELECT and return the first row as an object, or null.
 * @param {string} sql
 * @param {Array} params
 * @returns {Object|null}
 */
function get(sql, params = []) {
  const db = getDatabase();
  const stmt = db.prepare(sql);
  if (params.length > 0) {
    stmt.bind(params);
  }

  let row = null;
  if (stmt.step()) {
    row = stmt.getAsObject();
  }
  stmt.free();
  return row;
}

module.exports = {
  initDatabase,
  getDatabase,
  isHealthy,
  persist,
  close,
  _reset,
  run,
  exec,
  transaction,
  get,
  all,
  getMigrationStatus,
};
