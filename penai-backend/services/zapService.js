const axios = require('axios');

const ZAP_HOST = process.env.ZAP_HOST || '127.0.0.1';
const ZAP_PORT = parseInt(process.env.ZAP_PORT, 10) || 8080;
const ZAP_API_KEY = process.env.ZAP_API_KEY || 'penai_zap_key_2026';
const ZAP_BASE_URL = `http://${ZAP_HOST}:${ZAP_PORT}`;

/**
 * Helper to call ZAP REST API endpoints directly via axios.
 */
const zapApi = async (path, params = {}) => {
  params.apikey = ZAP_API_KEY;
  const response = await axios.get(`${ZAP_BASE_URL}${path}`, {
    params,
    timeout: 30000,
  });
  return response.data;
};

/**
 * Check if the ZAP daemon is reachable and responding.
 */
const checkConnection = async () => {
  try {
    const data = await zapApi('/JSON/core/view/version/');
    return !!data.version;
  } catch (error) {
    return false;
  }
};

/**
 * Map ZAP risk levels to PenAI severities.
 */
const mapRiskToSeverity = (risk) => {
  switch (risk) {
    case 'High':
      return 'High';
    case 'Medium':
      return 'Medium';
    case 'Low':
      return 'Low';
    case 'Informational':
    default:
      return 'Info';
  }
};

/**
 * Calculate security score (0-100) based on ZAP alerts.
 */
const calculateScore = (vulnerabilities) => {
  let score = 100;
  for (const v of vulnerabilities) {
    if (v.severity === 'Critical') score -= 25;
    else if (v.severity === 'High') score -= 15;
    else if (v.severity === 'Medium') score -= 8;
    else if (v.severity === 'Low') score -= 3;
  }
  return Math.max(0, Math.min(100, score));
};

/**
 * Determine overall highest severity from vulnerabilities array.
 */
const getOverallSeverity = (vulnerabilities) => {
  const severities = vulnerabilities.map((v) => v.severity);
  if (severities.includes('Critical')) return 'Critical';
  if (severities.includes('High')) return 'High';
  if (severities.includes('Medium')) return 'Medium';
  if (severities.includes('Low')) return 'Low';
  return 'Low';
};

/**
 * Seed ZAP's sites tree by proxying a request through ZAP.
 * This ensures the target URL is in ZAP's scan tree before active scanning.
 */
const seedSiteTree = async (targetUrl) => {
  try {
    await axios.get(targetUrl, {
      proxy: { host: ZAP_HOST, port: ZAP_PORT },
      timeout: 30000,
      validateStatus: () => true, // Accept any status
    });
    return true;
  } catch (err) {
    console.warn('Proxy seed warning:', err.message);
    // Fallback: try ZAP API accessUrl
    try {
      await zapApi('/JSON/core/action/accessUrl/', { url: targetUrl, followRedirects: 'true' });
      return true;
    } catch (err2) {
      console.warn('accessUrl fallback warning:', err2.message);
      return false;
    }
  }
};

/**
 * Wait for the sites tree to contain the target URL.
 */
const waitForSiteInTree = async (targetUrl, maxWaitMs = 15000) => {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    try {
      const data = await zapApi('/JSON/core/view/sites/');
      const sites = data.sites || [];
      if (sites.some((s) => targetUrl.startsWith(s) || s.startsWith(targetUrl.replace(/\/$/, '')))) {
        return true;
      }
    } catch (e) {
      // ignore
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
};

/**
 * Run a full ZAP scan (Spider + Active Scan) and update progress callbacks.
 *
 * @param {string} targetUrl The URL to scan
 * @param {function} onProgress Callback function(message, pct)
 * @returns {object} { score, severity, vulnerabilities, scanTime }
 */
const executeZapScan = async (targetUrl, onProgress = () => {}) => {
  const startTime = Date.now();

  // 1. Check connection
  const isAlive = await checkConnection();
  if (!isAlive) {
    throw new Error(
      'OWASP ZAP daemon is not running. Please start ZAP via Docker or local installation.'
    );
  }

  // 2. Seed the site tree by proxying a request through ZAP
  onProgress('Accessing target through ZAP proxy...', 5);
  await seedSiteTree(targetUrl);

  // 3. Start Spider Scan
  onProgress('Starting ZAP Spider crawl...', 8);
  const spiderData = await zapApi('/JSON/spider/action/scan/', { url: targetUrl });
  const spiderId = spiderData.scan;

  let spiderProgress = 0;
  while (spiderProgress < 100) {
    await new Promise((r) => setTimeout(r, 2000));
    const statusData = await zapApi('/JSON/spider/view/status/', { scanId: spiderId });
    spiderProgress = parseInt(statusData.status, 10) || 0;
    const currentPct = 10 + Math.floor((spiderProgress / 100) * 35); // 10% -> 45%
    onProgress(`Spider crawling target... ${spiderProgress}%`, currentPct);
  }

  // 4. Wait for site to be populated in the tree
  onProgress('Spider complete. Preparing Active Scan...', 47);
  const inTree = await waitForSiteInTree(targetUrl);
  if (!inTree) {
    console.warn('Target URL not found in ZAP sites tree after spider. Active scan may be limited.');
  }

  // 5. Start Active Security Scan
  onProgress('Starting Active Vulnerability Scan...', 50);
  let ascanId = null;
  try {
    const ascanData = await zapApi('/JSON/ascan/action/scan/', {
      url: targetUrl,
      recurse: 'true',
    });
    ascanId = ascanData.scan;
  } catch (err) {
    console.warn('Active scan start notice:', err.response?.data || err.message);
  }

  if (ascanId) {
    let ascanProgress = 0;
    while (ascanProgress < 100) {
      await new Promise((r) => setTimeout(r, 3000));
      const statusData = await zapApi('/JSON/ascan/view/status/', { scanId: ascanId });
      ascanProgress = parseInt(statusData.status, 10) || 0;
      const currentPct = 50 + Math.floor((ascanProgress / 100) * 45); // 50% -> 95%
      onProgress(`Active Scanner running attack vectors... ${ascanProgress}%`, currentPct);
    }
  } else {
    onProgress('Active Scanner skipped — analyzing passive findings...', 90);
  }

  // 6. Fetch Alerts / Findings
  onProgress('Scanning complete. Analyzing OWASP ZAP alerts...', 97);
  const alertsData = await zapApi('/JSON/core/view/alerts/', { baseurl: targetUrl });
  const rawAlerts = alertsData.alerts || [];

  // Deduplicate alerts by name + url
  const seen = new Set();
  const uniqueAlerts = rawAlerts.filter((alert) => {
    const key = (alert.name || alert.alert) + '|' + (alert.url || '');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Map ZAP alerts to PenAI format
  const vulnerabilities = uniqueAlerts.map((alert) => ({
    name: alert.name || alert.alert || 'Security Finding',
    description: alert.description || alert.other || '',
    severity: mapRiskToSeverity(alert.risk),
    solution: alert.solution || '',
    url: alert.url || targetUrl,
  }));

  const score = calculateScore(vulnerabilities);
  const severity = getOverallSeverity(vulnerabilities);
  const scanTime = Math.round((Date.now() - startTime) / 1000);

  onProgress('Scan finished successfully!', 100);

  return {
    score,
    severity,
    vulnerabilities,
    scanTime,
  };
};

module.exports = {
  checkConnection,
  executeZapScan,
};
