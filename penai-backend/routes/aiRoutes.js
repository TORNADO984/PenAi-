const express = require('express');
const router = express.Router();
const {
  remediateVulnerability,
  getExecutiveSummary,
} = require('../controllers/aiController');
const { protect } = require('../middleware/authMiddleware');

// Protect all AI routes with JWT authentication
router.use(protect);

// POST /api/ai/remediate - Generate AI code fix & explanation for a vulnerability
router.post('/remediate', remediateVulnerability);

// POST /api/ai/executive-summary - Generate AI executive assessment & action plan
router.post('/executive-summary', getExecutiveSummary);

module.exports = router;
