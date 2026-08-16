const Scan = require('../models/Scan');
const aiService = require('../services/aiService');

// @route   POST /api/ai/remediate
// @desc    Generate AI remediation (code fixes, explanation, verification) for a vulnerability
// @access  Private
const remediateVulnerability = async (req, res, next) => {
  try {
    const { name, description, severity, solution, url, targetUrl, scanId, vulnIndex } = req.body;

    if (!name) {
      return res.status(400).json({ success: false, message: 'Vulnerability name is required' });
    }

    const remediation = await aiService.generateVulnerabilityRemediation({
      name,
      description,
      severity: severity || 'Medium',
      solution,
      url,
      targetUrl,
    });

    // If scanId & vulnIndex provided, optionally persist to DB
    if (scanId && vulnIndex !== undefined) {
      try {
        const scan = await Scan.findOne({ _id: scanId, user: req.user.id });
        if (scan && scan.vulnerabilities && scan.vulnerabilities[vulnIndex]) {
          scan.vulnerabilities[vulnIndex].aiRemediation = remediation;
          await scan.save();
        }
      } catch (dbErr) {
        console.warn('Could not cache AI remediation to scan document:', dbErr.message);
      }
    }

    res.status(200).json({
      success: true,
      data: remediation,
    });
  } catch (error) {
    next(error);
  }
};

// @route   POST /api/ai/executive-summary
// @desc    Generate CISO-level Executive Security Assessment & Action Plan for a scan
// @access  Private
const getExecutiveSummary = async (req, res, next) => {
  try {
    const { scanId, targetUrl, score, severity, scanTime, vulnerabilities } = req.body;

    let scanData = { targetUrl, score, severity, scanTime, vulnerabilities };

    // If scanId is passed, fetch from DB to get the most accurate data
    if (scanId) {
      const scan = await Scan.findOne({ _id: scanId, user: req.user.id });
      if (scan) {
        scanData = {
          targetUrl: scan.targetUrl,
          score: scan.score,
          severity: scan.severity,
          scanTime: scan.scanTime,
          vulnerabilities: scan.vulnerabilities,
        };
      }
    }

    if (!scanData.targetUrl) {
      return res.status(400).json({ success: false, message: 'Target URL is required' });
    }

    const summary = await aiService.generateExecutiveSummary(scanData);

    // Cache summary to DB if scanId exists
    if (scanId) {
      try {
        await Scan.updateOne({ _id: scanId, user: req.user.id }, { $set: { aiSummary: summary } });
      } catch (dbErr) {
        console.warn('Could not cache executive summary to DB:', dbErr.message);
      }
    }

    res.status(200).json({
      success: true,
      data: summary,
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  remediateVulnerability,
  getExecutiveSummary,
};
