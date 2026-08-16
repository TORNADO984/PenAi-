const express = require('express');
const router = express.Router();
const {
  createScan,
  getScans,
  getScanById,
  deleteScan,
  scanValidation,
} = require('../controllers/scanController');
const { protect } = require('../middleware/authMiddleware');

// Apply 'protect' middleware to all routes in this router
router.use(protect);

// Routes mapped to /api/scans
router.route('/')
  .get(getScans)
  .post(scanValidation, createScan);

// Routes mapped to /api/scans/:id
router.route('/:id')
  .get(getScanById)
  .delete(deleteScan);

module.exports = router;
