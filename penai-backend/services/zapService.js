const axios = require('axios');
const https = require('https');

const ZAP_HOST = process.env.ZAP_HOST || '127.0.0.1';
const ZAP_PORT = parseInt(process.env.ZAP_PORT, 10) || 8080;
const ZAP_API_KEY = process.env.ZAP_API_KEY || 'penai_zap_key_2026';
const ZAP_BASE_URL = `http://${ZAP_HOST}:${ZAP_PORT}`;

// Realistic browser User-Agent so WAFs/CDNs don't block ZAP
const REAL_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36';

// Reusable HTTPS agent that accepts ZAP's self-signed certificate
const zapSslAgent = new https.Agent({ rejectUnauthorized: false });

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
 * Configure ZAP for optimal HTTPS scanning:
 * - Set a real browser User-Agent (WAFs block the default ZAP one)
 * - Set performance limits (spider depth, scan duration caps)
 * - Increase scan thread count for faster results
 */
const configureZapForScan = async () => {
  const settings = [
    // --- CRITICAL: Use a real browser User-Agent ---
    ['/JSON/network/action/setDefaultUserAgent/', { String: REAL_USER_AGENT }],

    // --- Spider limits ---
    ['/JSON/spider/action/setOptionMaxDepth/', { Integer: '5' }],
    ['/JSON/spider/action/setOptionMaxDuration/', { Integer: '3' }],
    // Accept all SSL certs during spider
    ['/JSON/spider/action/setOptionAcceptCookies/', { Boolean: 'true' }],

    // --- Active Scan limits ---
    ['/JSON/ascan/action/setOptionThreadPerHost/', { Integer: '10' }],
    ['/JSON/ascan/action/setOptionMaxRuleDurationInMins/', { Number: '2' }],
    ['/JSON/ascan/action/setOptionMaxScanDurationInMins/', { Number: '10' }],
  ];

  for (const [path, params] of settings) {
    try {
      await zapApi(path, params);
    } catch (err) {
      // Some options may not exist in older ZAP versions — skip gracefully
    }
  }
};

/**
 * Seed ZAP's sites tree by sending multiple requests through ZAP as a proxy.
 * This is the KEY step for HTTPS — ZAP intercepts the SSL connection and
 * adds the site + response headers to its scan tree for passive analysis.
 */
const seedSiteTree = async (targetUrl) => {
  const isHttps = targetUrl.toLowerCase().startsWith('https://');

  // Seed multiple pages through ZAP proxy to maximize passive scan coverage
  const urlsToSeed = [
    targetUrl,
    targetUrl.replace(/\/$/, '') + '/robots.txt',
    targetUrl.replace(/\/$/, '') + '/sitemap.xml',
  ];

  let seeded = false;
  for (const url of urlsToSeed) {
    try {
      await axios.get(url, {
        proxy: { host: ZAP_HOST, port: ZAP_PORT },
        timeout: 20000,
        validateStatus: () => true,
        headers: { 'User-Agent': REAL_USER_AGENT },
        ...(isHttps ? { httpsAgent: zapSslAgent } : {}),
      });
      seeded = true;
    } catch (err) {
      // Individual page seed failures are ok
    }
  }

  if (seeded) {
    console.log('Site tree seeded successfully via proxy for:', targetUrl);
    return true;
  }

  // Fallback: ZAP API accessUrl
  try {
    await zapApi('/JSON/core/action/accessUrl/', { url: targetUrl, followRedirects: 'true' });
    console.log('Site tree seeded via ZAP accessUrl for:', targetUrl);
    return true;
  } catch (err2) {
    console.warn('All seeding methods failed for:', targetUrl, err2.message);
    return false;
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
      const normalizedTarget = targetUrl.replace(/\/$/, '').toLowerCase();
      if (sites.some((s) => {
        const ns = s.replace(/\/$/, '').toLowerCase();
        return normalizedTarget.startsWith(ns) || ns.startsWith(normalizedTarget);
      })) {
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
 * Collect ALL alerts from ZAP — both passive and active.
 * Uses multiple strategies to ensure we get HTTPS passive findings.
 */
const collectAlerts = async (targetUrl) => {
  let allAlerts = [];

  // Strategy 1: Fetch alerts by baseurl
  try {
    const data = await zapApi('/JSON/core/view/alerts/', {
      baseurl: targetUrl,
      start: '0',
      count: '500',
    });
    allAlerts = data.alerts || [];
  } catch (e) {
    console.warn('Alert fetch by baseurl failed:', e.message);
  }

  // Strategy 2: If no alerts found, try fetching ALL alerts and filter
  if (allAlerts.length === 0) {
    try {
      const data = await zapApi('/JSON/core/view/alerts/', {
        start: '0',
        count: '500',
      });
      const raw = data.alerts || [];
      const targetDomain = new URL(targetUrl).hostname;
      allAlerts = raw.filter((a) => {
        try {
          return new URL(a.url).hostname.includes(targetDomain);
        } catch {
          return false;
        }
      });
    } catch (e) {
      console.warn('Alert fetch all failed:', e.message);
    }
  }

  // Strategy 3: Also check passive scan alerts specifically
  try {
    const pscanData = await zapApi('/JSON/pscan/view/recordsToScan/');
    console.log('Passive scan records remaining:', pscanData.recordsToScan);
  } catch (e) {
    // ignore
  }

  return allAlerts;
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

  // 2. Configure ZAP for optimal HTTPS scanning
  onProgress('Configuring scanner for HTTPS targets...', 3);
  await configureZapForScan();

  // 3. Seed the site tree (critical for HTTPS)
  onProgress('Accessing target through ZAP proxy...', 6);
  const seedSuccess = await seedSiteTree(targetUrl);

  // Give ZAP a moment to process passive scan rules on the seeded responses
  await new Promise((r) => setTimeout(r, 3000));

  // 4. Verify site is in ZAP's tree
  const inTree = await waitForSiteInTree(targetUrl);
  console.log('Target in ZAP sites tree:', inTree);

  // 5. Start Spider Scan
  onProgress('Starting ZAP Spider crawl...', 10);
  const spiderData = await zapApi('/JSON/spider/action/scan/', { url: targetUrl });
  const spiderId = spiderData.scan;

  let spiderProgress = 0;
  while (spiderProgress < 100) {
    await new Promise((r) => setTimeout(r, 2000));
    const statusData = await zapApi('/JSON/spider/view/status/', { scanId: spiderId });
    spiderProgress = parseInt(statusData.status, 10) || 0;
    const currentPct = 10 + Math.floor((spiderProgress / 100) * 30); // 10% -> 40%
    onProgress(`Spider crawling target... ${spiderProgress}%`, currentPct);
  }

  // Check how many URLs the spider found
  let spiderUrlCount = 0;
  try {
    const resultsData = await zapApi('/JSON/spider/view/results/', { scanId: spiderId });
    spiderUrlCount = (resultsData.results || []).length;
    console.log(`Spider found ${spiderUrlCount} URLs`);
  } catch (e) {
    // ignore
  }

  // Give ZAP time to run passive scan rules on spider results
  onProgress('Analyzing spider results with passive scanner...', 42);
  await new Promise((r) => setTimeout(r, 5000));

  // 6. Wait for passive scan to finish processing
  onProgress('Running passive security analysis...', 45);
  let pscanWaitCount = 0;
  while (pscanWaitCount < 10) {
    try {
      const pscanData = await zapApi('/JSON/pscan/view/recordsToScan/');
      const remaining = parseInt(pscanData.recordsToScan, 10) || 0;
      if (remaining === 0) break;
      onProgress(`Passive scanner processing... (${remaining} items remaining)`, 46);
    } catch (e) {
      break;
    }
    await new Promise((r) => setTimeout(r, 2000));
    pscanWaitCount++;
  }

  // 7. Start Active Security Scan
  onProgress('Starting Active Vulnerability Scan...', 50);
  let ascanId = null;
  try {
    await zapApi('/JSON/ascan/action/stopAllScans/').catch(() => {});
    await new Promise((r) => setTimeout(r, 1000));

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
    let lastProgressChange = Date.now();
    let lastProgressValue = -1;
    const STUCK_TIMEOUT_MS = 3 * 60 * 1000;
    const MAX_TOTAL_MS = 12 * 60 * 1000;
    const ascanStartTime = Date.now();

    while (ascanProgress < 100) {
      await new Promise((r) => setTimeout(r, 3000));

      const statusData = await zapApi('/JSON/ascan/view/status/', { scanId: ascanId });
      ascanProgress = parseInt(statusData.status, 10) || 0;
      const currentPct = 50 + Math.floor((ascanProgress / 100) * 45);
      onProgress(`Active Scanner running attack vectors... ${ascanProgress}%`, currentPct);

      if (ascanProgress !== lastProgressValue) {
        lastProgressValue = ascanProgress;
        lastProgressChange = Date.now();
      }

      if (ascanProgress === 0 && Date.now() - lastProgressChange > STUCK_TIMEOUT_MS) {
        console.warn('Active scan stuck at 0% — stopping and collecting passive results.');
        await zapApi('/JSON/ascan/action/stop/', { scanId: ascanId }).catch(() => {});
        onProgress('Active scan timed out — collecting passive findings...', 90);
        break;
      }

      if (Date.now() - ascanStartTime > MAX_TOTAL_MS) {
        console.warn('Active scan exceeded max duration — stopping.');
        await zapApi('/JSON/ascan/action/stop/', { scanId: ascanId }).catch(() => {});
        onProgress(`Scan time limit reached (${ascanProgress}%) — collecting results...`, 92);
        break;
      }
    }
  } else {
    onProgress('Active Scanner skipped — collecting passive findings...', 90);
  }

  // 8. Fetch ALL Alerts (passive + active)
  onProgress('Collecting security findings...', 97);
  const rawAlerts = await collectAlerts(targetUrl);

  console.log(`Total raw alerts collected: ${rawAlerts.length}`);

  // Deduplicate alerts by name (not by name+url, to reduce noise)
  const seen = new Set();
  const uniqueAlerts = rawAlerts.filter((alert) => {
    const key = (alert.name || alert.alert);
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

  console.log(`Final results: ${vulnerabilities.length} unique findings, score: ${score}, severity: ${severity}`);

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
