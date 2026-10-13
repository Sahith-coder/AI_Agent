'use strict';

const { Router } = require('express');
const { AttackLabService } = require('../services/attack-lab-service');

const router = Router();
const attackLabService = new AttackLabService();

/**
 * POST /api/attack-lab/run
 *
 * Execute registered synthetic security test suite.
 * Compares expected vs actual outcomes across real TraceGuard services
 * and persists results in test_runs and test_results.
 */
router.post('/attack-lab/run', async (req, res, next) => {
  try {
    const { suite_id, case_ids } = req.body || {};

    if (case_ids !== undefined && !Array.isArray(case_ids)) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'case_ids must be an array of test case ID strings.',
      });
    }

    const report = await attackLabService.runSuite({ suite_id, case_ids });
    res.status(200).json(report);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/attack-lab/runs
 *
 * Query paginated Attack Lab run history.
 */
router.get('/attack-lab/runs', (req, res, next) => {
  try {
    const { page, limit, status } = req.query;
    const history = attackLabService.listRuns({ page, limit, status });
    res.status(200).json(history);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/attack-lab/runs/:runId
 *
 * Query individual Attack Lab run details and individual test results.
 */
router.get('/attack-lab/runs/:runId', (req, res, next) => {
  try {
    const { runId } = req.params;

    if (!runId || typeof runId !== 'string' || runId.trim().length === 0) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'runId parameter is required.',
      });
    }

    const run = attackLabService.getRun(runId.trim());
    if (!run) {
      return res.status(404).json({
        error: 'Not found',
        message: `Attack Lab run '${runId}' not found.`,
      });
    }

    res.status(200).json(run);
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/attack-lab/cases
 *
 * Retrieve catalogue of registered synthetic test cases.
 */
router.get('/attack-lab/cases', (req, res, next) => {
  try {
    const cases = attackLabService.getRegisteredTestCases();
    res.status(200).json({
      suite_id: attackLabService.suiteId,
      suite_version: attackLabService.suiteVersion,
      count: cases.length,
      cases,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
