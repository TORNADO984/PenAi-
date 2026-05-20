const Scan = require('../models/Scan');
const { validationResult, body } = require('express-validator');

// Validation rules for POST /api/scans
const scanValidation = [
  body('targetUrl').isURL().withMessage('Please provide a valid target URL'),
  body('score').optional().isNumeric().withMessage('Score must be a number'),
  body('severity')
    .optional()
    .isIn(['Critical', 'High', 'Medium', 'Low'])
    .withMessage('Invalid severity level'),
];

// @route   POST /api/scans
// @desc    Save a new scan result
// @access  Private
const createScan = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const { targetUrl, score, severity, vulnerabilities } = req.body;

  try {
    const scan = await Scan.create({
      user: req.user.id,
      targetUrl,
      score,
      severity,
      vulnerabilities,
    });

    res.status(201).json({
      success: true,
      data: scan,
    });
  } catch (error) {
    next(error);
  }
};

// @route   GET /api/scans
// @desc    Get all scans for logged-in user
// @access  Private
const getScans = async (req, res, next) => {
  try {
    // Find scans matching the logged in user's ID, sorted by most recent first
    const scans = await Scan.find({ user: req.user.id }).sort({ scannedAt: -1 });

    res.status(200).json({
      success: true,
      count: scans.length,
      data: scans,
    });
  } catch (error) {
    next(error);
  }
};

// @route   GET /api/scans/:id
// @desc    Get single scan by ID
// @access  Private
const getScanById = async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);

    if (!scan) {
      res.status(404);
      throw new Error('Scan not found');
    }

    // Make sure user owns the scan
    if (scan.user.toString() !== req.user.id) {
      res.status(401);
      throw new Error('Not authorized to access this scan');
    }

    res.status(200).json({
      success: true,
      data: scan,
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createScan,
  getScans,
  getScanById,
  scanValidation,
};
