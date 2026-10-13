'use strict';

const config = require('./config');
const db = require('./db/database');
const createApp = require('./app');

async function start() {
  // ---------------------------------------------------------------------------
  // Initialize database (async for sql.js WASM loading)
  // ---------------------------------------------------------------------------
  try {
    await db.initDatabase();
    console.log(`[INFO] Database initialized at: ${config.sqlitePath}`);
  } catch (err) {
    console.error(`[FATAL] Failed to initialize database: ${err.message}`);
    process.exit(1);
  }

  // ---------------------------------------------------------------------------
  // Start server
  // ---------------------------------------------------------------------------
  const app = createApp();

  const server = app.listen(config.port, config.host, () => {
    console.log(`[INFO] TraceGuard Security Backend running on http://${config.host}:${config.port}`);
    console.log(`[INFO] Environment: ${config.env}`);
    console.log(`[INFO] Health check: http://${config.host}:${config.port}/api/health`);
  });

  // ---------------------------------------------------------------------------
  // Graceful shutdown
  // ---------------------------------------------------------------------------
  function shutdown(signal) {
    console.log(`\n[INFO] Received ${signal}. Shutting down gracefully...`);
    server.close(() => {
      db.close();
      console.log('[INFO] Server and database closed.');
      process.exit(0);
    });

    // Force close after 5 seconds
    setTimeout(() => {
      console.error('[WARN] Forced shutdown after timeout.');
      db.close();
      process.exit(1);
    }, 5000);
  }

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  // Persist database periodically (sql.js is in-memory, writes to disk on persist)
  const persistInterval = setInterval(() => {
    try {
      db.persist();
    } catch {
      // ignore persistence errors in background
    }
  }, 30000); // every 30 seconds

  // Clear interval on shutdown
  server.on('close', () => clearInterval(persistInterval));
}

start().catch(err => {
  console.error(`[FATAL] Server startup failed: ${err.message}`);
  process.exit(1);
});
