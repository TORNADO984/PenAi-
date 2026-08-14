const Scan = require('../models/Scan');
const { validationResult, body } = require('express-validator');
const zapService = require('../services/zapService');

// Validation rules for POST /api/scans
const scanValidation = [
  body('targetUrl').isURL().withMessage('Please provide a valid target URL'),
];

// @route   POST /api/scans
// @desc    Initiate a new scan (runs OWASP ZAP if connected, or saves directly)
// @access  Private
const createScan = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const { targetUrl, score, severity, vulnerabilities } = req.body;

  try {
    const isZapAlive = await zapService.checkConnection();

    // If client supplied pre-computed scan result (or ZAP isn't connected), handle direct save
    if (!isZapAlive && (score !== undefined || vulnerabilities !== undefined)) {
      const directScan = await Scan.create({
        user: req.user.id,
        targetUrl,
        score: score || 85,
        severity: severity || 'Low',
        vulnerabilities: vulnerabilities || [],
        status: 'complete',
        progressMessage: 'Scan complete',
        progressPct: 100,
      });

      return res.status(201).json({
        success: true,
        data: directScan,
      });
    }

    if (!isZapAlive) {
      return res.status(503).json({
        success: false,
        message:
          'OWASP ZAP daemon is not running on port 8080. Please start ZAP via Docker or local installation to run real security tests.',
      });
    }

    // ZAP is online — create pending scan record
    const scan = await Scan.create({
      user: req.user.id,
      targetUrl,
      status: 'pending',
      progressMessage: 'Scan initiated. Preparing ZAP Spider...',
      progressPct: 0,
    });

    // Respond immediately to the client
    res.status(201).json({
      success: true,
      data: scan,
    });

    // Run real ZAP scan in background
    (async () => {
      try {
        await Scan.findByIdAndUpdate(scan._id, {
          status: 'scanning',
          progressMessage: 'ZAP scan started...',
          progressPct: 5,
        });

        const result = await zapService.executeZapScan(
          targetUrl,
          async (msg, pct) => {
            await Scan.findByIdAndUpdate(scan._id, {
              progressMessage: msg,
              progressPct: pct,
            });
          }
        );

        await Scan.findByIdAndUpdate(scan._id, {
          score: result.score,
          severity: result.severity,
          vulnerabilities: result.vulnerabilities,
          scanTime: result.scanTime,
          status: 'complete',
          progressMessage: 'Scan completed successfully!',
          progressPct: 100,
        });
      } catch (err) {
        console.error('Background ZAP Scan Error:', err.message);
        await Scan.findByIdAndUpdate(scan._id, {
          status: 'failed',
          progressMessage: `Scan failed: ${err.message}`,
        });
      }
    })();
  } catch (error) {
    next(error);
  }
};

// @route   GET /api/scans
// @desc    Get all scans for logged-in user
// @access  Private
const getScans = async (req, res, next) => {
  try {
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
// @desc    Get single scan by ID (used for polling scan progress)
// @access  Private
const getScanById = async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);

    if (!scan) {
      res.status(404);
      throw new Error('Scan not found');
    }

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
