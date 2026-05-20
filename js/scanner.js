// PenAI - AI Scanner Engine (Simulated)

const SCAN_STAGES = [
  { msg: 'Initializing scan engine...', pct: 5 },
  { msg: 'Resolving DNS & checking SSL certificate...', pct: 12 },
  { msg: 'Crawling target site structure...', pct: 22 },
  { msg: 'Mapping entry points & forms...', pct: 32 },
  { msg: 'Running OWASP ZAP simulation...', pct: 42 },
  { msg: 'Testing for SQL Injection vectors...', pct: 50 },
  { msg: 'Checking XSS & CSRF vulnerabilities...', pct: 58 },
  { msg: 'Analyzing authentication mechanisms...', pct: 66 },
  { msg: 'Scanning for misconfigurations...', pct: 74 },
  { msg: 'Checking all 10 OWASP categories...', pct: 82 },
  { msg: 'AI analyzing injection points...', pct: 90 },
  { msg: 'Generating security report...', pct: 97 },
];

function generateReport(url) {
  const domain = url.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const hash = [...domain].reduce((a, c) => a + c.charCodeAt(0), 0);
  const score = 28 + (hash % 45); // 28-72
  const sev = s => s === 'Critical' ? 'bg-red-500/15 text-red-400 border-red-500/30'
    : s === 'High' ? 'bg-orange-500/15 text-orange-400 border-orange-500/30'
    : s === 'Medium' ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
    : 'bg-blue-500/15 text-blue-400 border-blue-500/30';

  const findings = [
    { id: 'A01', name: 'Broken Access Control', severity: 'Critical',
      desc: `Horizontal privilege escalation detected on ${domain}. API endpoints allow unauthorized access to other users\u2019 data by modifying resource IDs.`,
      poc: `GET /api/users/1042/profile returns data without proper authorization check. Changing ID to 1043 exposes another user\u2019s PII.`,
      fix: 'Implement server-side access control checks on every request. Use session-based ownership validation.',
      code: `// Express.js middleware example\napp.get('/api/users/:id/profile', auth, (req, res) => {\n  if (req.user.id !== req.params.id) {\n    return res.status(403).json({ error: 'Forbidden' });\n  }\n  // ... return profile\n});` },
    { id: 'A02', name: 'Cryptographic Failures', severity: 'High',
      desc: `Sensitive data transmitted without adequate encryption. Some API responses include PII over unencrypted channels.`,
      poc: `Set-Cookie header missing Secure and HttpOnly flags. Password reset tokens transmitted in URL query parameters.`,
      fix: 'Enforce HTTPS everywhere. Add Secure, HttpOnly, SameSite flags to all cookies. Never pass secrets in URLs.',
      code: `# Nginx HTTPS redirect\nserver {\n  listen 80;\n  return 301 https://$host$request_uri;\n}\n\n# Cookie flags\nSet-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict` },
    { id: 'A03', name: 'Injection', severity: 'Critical',
      desc: `SQL injection vulnerability found in search parameter. User input is concatenated directly into SQL queries.`,
      poc: `GET /search?q=test' OR '1'='1 returns all records, confirming unsanitized input in SQL query.`,
      fix: 'Use parameterized queries or prepared statements. Never concatenate user input into queries.',
      code: `# Python - parameterized query\ncursor.execute(\n  "SELECT * FROM products WHERE name LIKE %s",\n  (f"%{search_term}%",)\n)` },
    { id: 'A04', name: 'Insecure Design', severity: 'Medium',
      desc: `Rate limiting absent on login endpoint. No account lockout policy detected after multiple failed attempts.`,
      poc: `Automated brute-force test sent 500 login attempts in 60 seconds without throttling or CAPTCHA challenge.`,
      fix: 'Implement rate limiting, progressive delays, and CAPTCHA after failed attempts. Add account lockout policies.',
      code: `// Express rate-limit\nconst rateLimit = require('express-rate-limit');\napp.use('/login', rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 5,\n  message: 'Too many attempts'\n}));` },
    { id: 'A05', name: 'Security Misconfiguration', severity: 'High',
      desc: `Server exposes detailed error stack traces. Directory listing enabled. Default admin credentials may be active.`,
      poc: `Requesting /nonexistent returns full stack trace with framework version, file paths, and database connection strings.`,
      fix: 'Disable verbose errors in production. Remove default accounts. Disable directory listing. Set security headers.',
      code: `# Security headers (Nginx)\nadd_header X-Content-Type-Options nosniff;\nadd_header X-Frame-Options DENY;\nadd_header X-XSS-Protection "1; mode=block";\nadd_header Strict-Transport-Security "max-age=31536000";` },
    { id: 'A06', name: 'Vulnerable & Outdated Components', severity: 'High',
      desc: `jQuery 2.1.4 detected (CVE-2020-11022). Outdated Bootstrap 3.x with known XSS vectors.`,
      poc: `Page source reveals jquery-2.1.4.min.js which is vulnerable to prototype pollution and XSS via HTML parsing.`,
      fix: 'Update all client-side libraries to latest versions. Implement automated dependency scanning in CI/CD.',
      code: `# Check for outdated packages\nnpm audit\nnpm update\n\n# Or use Snyk\nnpx snyk test` },
    { id: 'A07', name: 'Auth & Identification Failures', severity: 'Medium',
      desc: `Session tokens have insufficient entropy. Password policy allows weak passwords (min 4 chars, no complexity).`,
      poc: `Session cookie value is a sequential numeric ID. Password "1234" accepted during registration.`,
      fix: 'Use cryptographically secure session generation. Enforce strong password policies. Implement MFA.',
      code: `// Secure session config (Express)\napp.use(session({\n  secret: crypto.randomBytes(64).toString('hex'),\n  resave: false,\n  saveUninitialized: false,\n  cookie: { secure: true, httpOnly: true, maxAge: 3600000 }\n}));` },
    { id: 'A08', name: 'Software & Data Integrity Failures', severity: 'Medium',
      desc: `Third-party scripts loaded without Subresource Integrity (SRI) hashes. CI/CD pipeline lacks signature verification.`,
      poc: `<script src="https://cdn.example.com/lib.js"> loaded without integrity attribute — vulnerable to supply chain attacks.`,
      fix: 'Add SRI hashes to all external scripts. Verify checksums of dependencies. Sign deployment artifacts.',
      code: `<!-- SRI example -->\n<script src="https://cdn.example.com/lib.js"\n  integrity="sha384-abc123..."\n  crossorigin="anonymous"></script>` },
    { id: 'A09', name: 'Security Logging & Monitoring Failures', severity: 'Low',
      desc: `No evidence of security event logging. Failed login attempts are not recorded. No intrusion detection observed.`,
      poc: `50 failed login attempts generated no alerts or account lockouts, suggesting absent monitoring.`,
      fix: 'Implement centralized logging for all auth events. Set up alerts for anomalous patterns. Use a SIEM solution.',
      code: `// Winston logging example\nlogger.warn('Failed login attempt', {\n  ip: req.ip,\n  email: req.body.email,\n  timestamp: new Date().toISOString(),\n  userAgent: req.headers['user-agent']\n});` },
    { id: 'A10', name: 'Server-Side Request Forgery', severity: 'Medium',
      desc: `URL parameter in image proxy endpoint allows internal network scanning. SSRF vector confirmed.`,
      poc: `GET /proxy?url=http://169.254.169.254/latest/meta-data/ returns AWS instance metadata.`,
      fix: 'Validate and whitelist allowed URLs. Block requests to internal/private IP ranges. Use URL parsing libraries.',
      code: `// SSRF prevention\nconst url = new URL(userInput);\nconst blocked = ['127.0.0.1','localhost','169.254.169.254','10.','192.168.'];\nif (blocked.some(b => url.hostname.startsWith(b))) {\n  throw new Error('Blocked: internal address');\n}` },
  ];

  // Randomize which findings are "found" based on domain hash
  const active = findings.filter((_, i) => (hash + i * 7) % 3 !== 0);
  active.forEach((f, i) => { f.found = (hash + i) % 2 === 0 || f.severity === 'Critical'; });

  return { domain, score, findings: active, sev, totalChecks: 247, scanTime: (6 + (hash % 4)) + '.' + (hash % 10), vulnerabilities: [] };
}

function renderScore(score) {
  const label = score >= 70 ? 'Secure' : score >= 45 ? 'At Risk' : 'Critical';
  const color = score >= 70 ? '#00ff9d' : score >= 45 ? '#ffaa00' : '#ff4444';
  const ringPct = (score / 100) * 283;
  return `
    <div class="score-ring-wrap">
      <svg viewBox="0 0 100 100" class="score-ring">
        <circle cx="50" cy="50" r="45" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="6"/>
        <circle cx="50" cy="50" r="45" fill="none" stroke="${color}" stroke-width="6"
          stroke-dasharray="${ringPct} 283" stroke-linecap="round"
          transform="rotate(-90 50 50)" class="score-ring-progress"/>
      </svg>
      <div class="score-ring-text">
        <span class="score-number" style="color:${color}">${score}</span>
        <span class="score-label">/100</span>
      </div>
    </div>
    <span class="score-badge" style="background:${color}20;color:${color};border:1px solid ${color}40">${label}</span>`;
}

function renderFinding(f, sev, idx) {
  const sevClass = sev(f.severity);
  const escaped = (s) => s.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `
    <div class="finding-card glass-card p-5 mb-4" data-animate>
      <div class="flex flex-wrap items-start justify-between gap-3 mb-3">
        <div class="flex items-center gap-3">
          <span class="finding-id font-mono text-xs text-gray-500">${f.id}</span>
          <h4 class="text-white font-bold text-base">${f.name}</h4>
        </div>
        <span class="text-xs font-semibold px-3 py-1 rounded-full border ${sevClass}">${f.severity}</span>
      </div>
      <p class="text-gray-400 text-sm mb-3">${f.desc}</p>
      <button onclick="this.nextElementSibling.classList.toggle('hidden')" class="text-neon-green text-xs font-semibold hover:underline cursor-pointer mb-2 flex items-center gap-1">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18l6-6-6-6"/></svg>
        View Technical Details
      </button>
      <div class="hidden mt-3 space-y-3">
        <div class="bg-black/30 rounded-lg p-3 border border-gray-800">
          <p class="text-xs text-gray-500 mb-1 font-semibold uppercase tracking-wider">Proof of Concept</p>
          <p class="text-gray-300 text-sm font-mono">${escaped(f.poc)}</p>
        </div>
        <div class="bg-black/30 rounded-lg p-3 border border-gray-800">
          <p class="text-xs text-gray-500 mb-1 font-semibold uppercase tracking-wider">Remediation</p>
          <p class="text-gray-300 text-sm">${f.fix}</p>
        </div>
        <div class="bg-black/30 rounded-lg p-3 border border-gray-800 relative">
          <p class="text-xs text-gray-500 mb-1 font-semibold uppercase tracking-wider">Code Fix</p>
          <pre class="text-green-400 text-xs overflow-x-auto"><code>${escaped(f.code)}</code></pre>
          <button onclick="navigator.clipboard.writeText(this.closest('.relative').querySelector('code').textContent);this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',1500)" class="absolute top-3 right-3 text-xs text-gray-500 hover:text-neon-green cursor-pointer">Copy</button>
        </div>
      </div>
    </div>`;
}

function renderReportUI(report, containerElement) {
  const critCount = report.findings.filter(f => f.severity === 'Critical').length;
  const highCount = report.findings.filter(f => f.severity === 'High').length;
  const medCount = report.findings.filter(f => f.severity === 'Medium').length;
  const lowCount = report.findings.filter(f => f.severity === 'Low').length;

  const totalFindings = report.findings.length;
  const critPct = totalFindings > 0 ? (critCount / totalFindings) * 100 : 0;
  const highPct = totalFindings > 0 ? (highCount / totalFindings) * 100 : 0;
  const medPct = totalFindings > 0 ? (medCount / totalFindings) * 100 : 0;
  const lowPct = totalFindings > 0 ? (lowCount / totalFindings) * 100 : 0;
  
  const scanDate = new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute:'2-digit' });

  // A nice summary text
  let summaryText = `The security assessment of <span class="text-white font-semibold">${report.domain}</span> completed successfully in ${report.scanTime}s. `;
  if (critCount > 0 || highCount > 0) {
    summaryText += `Critical vulnerabilities were detected. Immediate remediation is strongly advised to prevent exploitation.`;
  } else if (totalFindings > 0) {
    summaryText += `Several issues were identified that could improve the overall security posture.`;
  } else {
    summaryText += `No immediate vulnerabilities were found. Keep up the good work.`;
  }

  containerElement.innerHTML = `
    <div class="glass-card mb-6 sm:mb-8 glow-border relative overflow-hidden" data-animate>
      <div class="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-neon-green via-neon-blue to-neon-purple"></div>
      
      <!-- Top Header -->
      <div class="p-4 sm:p-6 md:p-8 border-b border-white/5 bg-black/20">
        <div class="flex flex-col md:flex-row justify-between items-center md:items-center gap-4 sm:gap-6">
          <div class="text-center md:text-left w-full md:w-auto">
            <div class="flex items-center justify-center md:justify-start gap-2 sm:gap-3 mb-3 flex-wrap">
              <span class="flex items-center gap-1.5 text-[10px] font-bold px-2 sm:px-2.5 py-1 rounded-md bg-neon-green/10 text-neon-green border border-neon-green/30 tracking-widest uppercase shadow-inner">
                <span class="w-1.5 h-1.5 rounded-full bg-neon-green animate-pulse"></span> Complete
              </span>
              <span class="text-[10px] sm:text-xs text-gray-400 font-mono">${scanDate}</span>
            </div>
            <h3 class="text-xl sm:text-2xl md:text-3xl font-bold text-white break-all flex items-center justify-center md:justify-start gap-2 sm:gap-3">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-gray-500 shrink-0 hidden sm:block"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
              ${report.domain}
            </h3>
          </div>
          <div class="flex-shrink-0 drop-shadow-[0_0_15px_rgba(0,255,157,0.2)] bg-black/40 p-3 sm:p-4 rounded-2xl border border-white/5 shadow-inner">
            ${renderScore(report.score)}
          </div>
        </div>
      </div>

      <!-- Stats & Summary Body -->
      <div class="p-4 sm:p-6 md:p-8">
        
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 sm:gap-8 md:gap-10">
          
          <!-- Left Col: Summary & Metadata -->
          <div class="md:col-span-1 space-y-4 sm:space-y-6">
            <div>
              <h4 class="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-2 sm:mb-3">Assessment Summary</h4>
              <p class="text-xs sm:text-sm text-gray-300 leading-relaxed bg-white/5 p-3 sm:p-4 rounded-xl border border-white/5 shadow-inner">${summaryText}</p>
            </div>
            
            <div class="grid grid-cols-2 gap-3 sm:gap-4">
              <div class="bg-black/30 p-3 sm:p-4 rounded-xl border border-white/5 shadow-inner">
                <span class="text-[10px] uppercase tracking-widest text-gray-500 font-bold block mb-1">Duration</span>
                <span class="text-lg sm:text-xl font-mono text-white flex items-center gap-1.5">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--neon-blue)" stroke-width="2" class="shrink-0"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> 
                  ${report.scanTime}s
                </span>
              </div>
              <div class="bg-black/30 p-3 sm:p-4 rounded-xl border border-white/5 shadow-inner">
                <span class="text-[10px] uppercase tracking-widest text-gray-500 font-bold block mb-1">Checks Run</span>
                <span class="text-lg sm:text-xl font-mono text-white flex items-center gap-1.5">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--neon-purple)" stroke-width="2" class="shrink-0"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> 
                  ${report.totalChecks}
                </span>
              </div>
            </div>
          </div>

          <!-- Right Col: Severity Breakdown Bars -->
          <div class="md:col-span-2">
            <h4 class="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-3 sm:mb-4">Vulnerability Breakdown</h4>
            <div class="space-y-4 sm:space-y-5 bg-black/20 p-4 sm:p-6 rounded-xl border border-white/5">
              
              <!-- Critical Bar -->
              <div>
                <div class="flex justify-between text-xs font-semibold mb-1.5 sm:mb-2">
                  <span class="text-red-400 uppercase tracking-wider">Critical</span>
                  <span class="text-white bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">${critCount}</span>
                </div>
                <div class="w-full bg-black/60 rounded-full h-2.5 sm:h-3 border border-white/5 overflow-hidden shadow-inner">
                  <div class="bg-red-500 h-full rounded-full shadow-[0_0_12px_rgba(239,68,68,0.6)] transition-all duration-1000" style="width: ${critPct}%"></div>
                </div>
              </div>
              
              <!-- High Bar -->
              <div>
                <div class="flex justify-between text-xs font-semibold mb-1.5 sm:mb-2">
                  <span class="text-orange-400 uppercase tracking-wider">High</span>
                  <span class="text-white bg-orange-500/10 px-2 py-0.5 rounded border border-orange-500/20">${highCount}</span>
                </div>
                <div class="w-full bg-black/60 rounded-full h-2.5 sm:h-3 border border-white/5 overflow-hidden shadow-inner">
                  <div class="bg-orange-500 h-full rounded-full shadow-[0_0_12px_rgba(249,115,22,0.6)] transition-all duration-1000 delay-100" style="width: ${highPct}%"></div>
                </div>
              </div>

              <!-- Medium Bar -->
              <div>
                <div class="flex justify-between text-xs font-semibold mb-1.5 sm:mb-2">
                  <span class="text-yellow-400 uppercase tracking-wider">Medium</span>
                  <span class="text-white bg-yellow-500/10 px-2 py-0.5 rounded border border-yellow-500/20">${medCount}</span>
                </div>
                <div class="w-full bg-black/60 rounded-full h-2.5 sm:h-3 border border-white/5 overflow-hidden shadow-inner">
                  <div class="bg-yellow-500 h-full rounded-full shadow-[0_0_12px_rgba(234,179,8,0.6)] transition-all duration-1000 delay-200" style="width: ${medPct}%"></div>
                </div>
              </div>

              <!-- Low Bar -->
              <div>
                <div class="flex justify-between text-xs font-semibold mb-1.5 sm:mb-2">
                  <span class="text-blue-400 uppercase tracking-wider">Low</span>
                  <span class="text-white bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">${lowCount}</span>
                </div>
                <div class="w-full bg-black/60 rounded-full h-2.5 sm:h-3 border border-white/5 overflow-hidden shadow-inner">
                  <div class="bg-blue-500 h-full rounded-full shadow-[0_0_12px_rgba(59,130,246,0.6)] transition-all duration-1000 delay-300" style="width: ${lowPct}%"></div>
                </div>
              </div>

            </div>
          </div>
          
        </div>
      </div>
    </div>

    <!-- ═══ Detected Vulnerabilities Section ═══ -->
    <div class="glass-card mb-8 overflow-hidden" data-animate>
      <div class="p-5 md:p-6 border-b border-white/5 bg-black/20 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </div>
          <div>
            <h3 class="text-base font-bold text-white">Detected Vulnerabilities</h3>
            <p class="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">${report.vulnerabilities && report.vulnerabilities.length > 0 ? report.vulnerabilities.length + ' issue' + (report.vulnerabilities.length > 1 ? 's' : '') + ' found' : 'From backend scan data'}</p>
          </div>
        </div>
        <span class="text-[10px] font-bold px-2.5 py-1 rounded-md tracking-widest uppercase shadow-inner ${
          report.vulnerabilities && report.vulnerabilities.length > 0
            ? 'bg-red-500/10 text-red-400 border border-red-500/20'
            : 'bg-neon-green/10 text-neon-green border border-neon-green/30'
        }">${report.vulnerabilities && report.vulnerabilities.length > 0 ? 'Action Required' : 'Clear'}</span>
      </div>

      <div class="p-5 md:p-6">
        ${report.vulnerabilities && report.vulnerabilities.length > 0 ? `
          <div class="max-h-[500px] overflow-y-auto pr-1 space-y-3 custom-scrollbar">
            ${report.vulnerabilities.map((v, i) => {
              const sevName = (v.severity || 'Medium').charAt(0).toUpperCase() + (v.severity || 'medium').slice(1).toLowerCase();
              const sevColors = {
                'Critical': { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20', dot: 'bg-red-500', glow: 'shadow-[0_0_8px_rgba(239,68,68,0.4)]' },
                'High':     { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20', dot: 'bg-orange-500', glow: 'shadow-[0_0_8px_rgba(249,115,22,0.4)]' },
                'Medium':   { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/20', dot: 'bg-yellow-500', glow: 'shadow-[0_0_8px_rgba(234,179,8,0.4)]' },
                'Low':      { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20', dot: 'bg-blue-500', glow: 'shadow-[0_0_8px_rgba(59,130,246,0.4)]' },
                'Info':     { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/20', dot: 'bg-gray-500', glow: '' }
              };
              const c = sevColors[sevName] || sevColors['Medium'];
              const vulnName = v.name || v.title || v.vulnerability || 'Unnamed Vulnerability';
              const vulnDesc = v.description || v.desc || '';
              return `
                <div class="flex items-start gap-4 p-4 rounded-xl bg-black/30 border ${c.border} hover:bg-white/[0.03] transition-colors group">
                  <div class="flex flex-col items-center gap-1 pt-0.5 shrink-0">
                    <span class="w-3 h-3 rounded-full ${c.dot} ${c.glow}"></span>
                    <span class="text-[9px] font-bold ${c.text} uppercase tracking-wider">${sevName}</span>
                  </div>
                  <div class="flex-1 min-w-0">
                    <div class="flex items-center justify-between gap-3 mb-1">
                      <h4 class="text-sm font-bold text-white group-hover:text-neon-green transition-colors truncate">${vulnName}</h4>
                      <span class="text-[10px] font-semibold px-2 py-0.5 rounded-full border ${c.bg} ${c.text} ${c.border} shrink-0">${sevName}</span>
                    </div>
                    ${vulnDesc ? `<p class="text-xs text-gray-400 leading-relaxed line-clamp-2">${vulnDesc}</p>` : ''}
                  </div>
                </div>`;
            }).join('')}
          </div>
        ` : `
          <div class="text-center py-12">
            <div class="w-16 h-16 rounded-full bg-neon-green/5 border border-neon-green/20 flex items-center justify-center mx-auto mb-4">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#00ff9d" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            </div>
            <h4 class="text-white font-semibold text-sm mb-1">No Vulnerabilities Detected</h4>
            <p class="text-gray-500 text-xs max-w-xs mx-auto">No backend vulnerability data is available for this scan. When the backend returns vulnerability details, they will appear here automatically.</p>
          </div>
        `}
      </div>
    </div>

    <div class="flex flex-wrap gap-3 mb-6" data-animate>
      <button onclick="alert('PDF export simulated!')" class="btn-outline text-xs px-4 py-2 cursor-pointer flex items-center gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/></svg>
        Export PDF
      </button>
      <button onclick="alert('JSON export simulated!')" class="btn-outline text-xs px-4 py-2 cursor-pointer flex items-center gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 4h2a2 2 0 012 2v14a2 2 0 01-2 2H6a2 2 0 01-2-2V6a2 2 0 012-2h2"/></svg>
        Export JSON
      </button>
      <button onclick="alert('Shared to community!')" class="btn-outline text-xs px-4 py-2 cursor-pointer flex items-center gap-2">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        Share to Community
      </button>
    </div>

    <h3 class="text-lg font-bold text-white mb-4" data-animate>Detailed Findings</h3>
    ${report.findings.map((f, i) => renderFinding(f, report.sev, i)).join('')}

    <div class="mt-6 p-4 rounded-xl bg-yellow-500/5 border border-yellow-500/15 text-yellow-400/80 text-xs" data-animate>
      ⚠️ <strong>Disclaimer:</strong> This is an AI simulation for educational purposes. For authorized professional pentesting, use licensed tools and obtain proper written authorization.
    </div>
  `;

  containerElement.classList.remove('hidden');
  if (window.revealNewElements) window.revealNewElements(containerElement);
  containerElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function initScanner() {
  const form = document.getElementById('scan-form');
  const urlInput = document.getElementById('scan-url');
  const progressWrap = document.getElementById('scan-progress');
  const progressBar = document.getElementById('scan-progress-bar');
  const progressMsg = document.getElementById('scan-progress-msg');
  const progressPct = document.getElementById('scan-progress-pct');
  const reportWrap = document.getElementById('scan-report');
  const scanBtn = document.getElementById('scan-btn');
  const advToggle = document.getElementById('adv-toggle');
  const advPanel = document.getElementById('adv-panel');

  // Tabs and History Views
  const tabNewScan = document.getElementById('tab-new-scan');
  const tabScanHistory = document.getElementById('tab-scan-history');
  const newScanView = document.getElementById('new-scan-view');
  const scanHistoryView = document.getElementById('scan-history-view');
  const historyList = document.getElementById('scan-history-list');
  const historyLoading = document.getElementById('scan-history-loading');
  const historyError = document.getElementById('scan-history-error');
  const historyEmpty = document.getElementById('scan-history-empty');
  const historyReportContainer = document.getElementById('history-report-container');
  const historyScanReport = document.getElementById('history-scan-report');
  const backToHistoryBtn = document.getElementById('back-to-history-btn');

  // Search & Filter Controls
  const historyControls = document.getElementById('scan-history-controls');
  const historySearch = document.getElementById('history-search');
  const historyFilter = document.getElementById('history-filter');

  let allScans = [];

  if (!form) return;

  // --- TAB LOGIC ---
  if (tabNewScan && tabScanHistory) {
    tabNewScan.addEventListener('click', () => {
      // Style active tab
      tabNewScan.className = 'flex-1 text-xs sm:text-sm font-semibold py-2.5 rounded-lg bg-neon-green/10 text-neon-green border border-neon-green/30 cursor-pointer transition-all shadow-[0_0_15px_rgba(0,255,157,0.1)] min-h-[40px]';
      tabScanHistory.className = 'flex-1 text-xs sm:text-sm font-semibold py-2.5 rounded-lg text-gray-400 hover:text-white border border-transparent hover:bg-white/5 cursor-pointer transition-all min-h-[40px]';
      // Switch views
      newScanView.classList.remove('hidden');
      scanHistoryView.classList.add('hidden');
    });

    tabScanHistory.addEventListener('click', () => {
      // Style active tab
      tabScanHistory.className = 'flex-1 text-xs sm:text-sm font-semibold py-2.5 rounded-lg bg-neon-green/10 text-neon-green border border-neon-green/30 cursor-pointer transition-all shadow-[0_0_15px_rgba(0,255,157,0.1)] min-h-[40px]';
      tabNewScan.className = 'flex-1 text-xs sm:text-sm font-semibold py-2.5 rounded-lg text-gray-400 hover:text-white border border-transparent hover:bg-white/5 cursor-pointer transition-all min-h-[40px]';
      // Switch views
      newScanView.classList.add('hidden');
      scanHistoryView.classList.remove('hidden');
      
      // Load history
      historyReportContainer.classList.add('hidden');
      loadScanHistory();
    });
  }

  if (backToHistoryBtn) {
    backToHistoryBtn.addEventListener('click', () => {
      historyReportContainer.classList.add('hidden');
      historyList.classList.remove('hidden');
      if (historyControls) historyControls.classList.remove('hidden');
    });
  }

  // Search and Filter Listeners
  if (historySearch) {
    historySearch.addEventListener('input', () => renderScanCards());
  }
  if (historyFilter) {
    historyFilter.addEventListener('change', () => renderScanCards());
  }

  function renderScanCards() {
    historyList.innerHTML = '';
    const query = historySearch ? historySearch.value.toLowerCase() : '';
    const filter = historyFilter ? historyFilter.value : 'All';

    const filteredScans = allScans.filter(scan => {
      const matchSearch = scan.targetUrl.toLowerCase().includes(query);
      
      let matchSeverity = true;
      if (filter !== 'All') {
        const inferredSev = scan.severity || (scan.score >= 70 ? 'Low' : scan.score >= 45 ? 'Medium' : 'Critical');
        matchSeverity = inferredSev === filter || (filter === 'High' && inferredSev === 'Medium');
      }

      return matchSearch && matchSeverity;
    });

    if (filteredScans.length === 0) {
      historyList.classList.add('hidden');
      if (allScans.length > 0) {
        historyEmpty.querySelector('p:nth-of-type(1)').textContent = 'No scans match your criteria';
        historyEmpty.querySelector('p:nth-of-type(2)').textContent = 'Try adjusting your search or filters.';
      } else {
        historyEmpty.querySelector('p:nth-of-type(1)').textContent = 'No scans found';
        historyEmpty.querySelector('p:nth-of-type(2)').textContent = 'You haven\'t run any security scans yet.';
      }
      historyEmpty.classList.remove('hidden');
      return;
    }

    historyEmpty.classList.add('hidden');
    filteredScans.forEach(scan => {
      const date = new Date(scan.scannedAt).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
      const scoreColor = scan.score >= 70 ? 'text-neon-green' : scan.score >= 45 ? 'text-yellow-400' : 'text-red-400';
      const card = document.createElement('div');
      card.className = 'glass-card p-4 sm:p-6 cursor-pointer hover:border-neon-green/40 hover:shadow-[0_8px_30px_rgba(0,255,157,0.12)] transition-all duration-300 group flex flex-col justify-between relative overflow-hidden';
      card.innerHTML = `
        <div class="absolute inset-0 bg-gradient-to-br from-neon-green/0 via-neon-green/0 to-neon-green/5 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
        <div class="relative z-10">
          <div class="flex justify-between items-start mb-4">
            <div class="flex-1 pr-4">
              <span class="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-500 font-semibold mb-1.5">
                <span class="w-1.5 h-1.5 rounded-full bg-neon-green animate-pulse"></span>
                Target Scanned
              </span>
              <h4 class="text-white font-bold text-lg group-hover:text-neon-green transition-colors break-all line-clamp-1" title="${scan.targetUrl}">${scan.targetUrl}</h4>
            </div>
            <div class="flex flex-col items-end shrink-0">
              <span class="text-[10px] uppercase tracking-wider text-gray-500 font-semibold mb-1 block">Security Score</span>
              <span class="text-3xl font-black ${scoreColor} drop-shadow-[0_0_10px_rgba(0,255,157,0.2)]">${scan.score}</span>
            </div>
          </div>
        </div>
        <div class="relative z-10 flex justify-between items-center mt-6 pt-4 border-t border-white/5">
          <span class="flex items-center gap-1.5 text-xs text-gray-400 bg-white/5 px-2.5 py-1 rounded-md border border-white/5 shadow-inner">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
            ${date}
          </span>
          <span class="flex items-center gap-1 text-sm font-semibold text-neon-green opacity-0 -translate-x-3 group-hover:opacity-100 group-hover:translate-x-0 transition-all duration-300">
            View Report <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          </span>
        </div>
      `;
      card.addEventListener('click', () => {
        historyList.classList.add('hidden');
        if (historyControls) historyControls.classList.add('hidden');
        const reportData = generateReport(scan.targetUrl);
        reportData.score = scan.score;
        // Pass backend vulnerabilities if available
        if (scan.vulnerabilities && Array.isArray(scan.vulnerabilities)) {
          reportData.vulnerabilities = scan.vulnerabilities;
        }
        renderReportUI(reportData, historyScanReport);
        historyReportContainer.classList.remove('hidden');
      });
      historyList.appendChild(card);
    });

    historyList.classList.remove('hidden');
    if (window.revealNewElements) window.revealNewElements(historyList);
  }

  async function loadScanHistory() {
    const token = localStorage.getItem('penai_token');
    if (!token) return;

    historyList.classList.add('hidden');
    historyEmpty.classList.add('hidden');
    historyError.classList.add('hidden');
    historyLoading.classList.remove('hidden');
    if (historyControls) historyControls.classList.add('hidden');

    try {
      const res = await fetch('http://localhost:5000/api/scans', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || 'Failed to fetch scan history');

      historyLoading.classList.add('hidden');

      if (!data.data || data.data.length === 0) {
        allScans = [];
        historyEmpty.classList.remove('hidden');
        return;
      }

      allScans = data.data;
      if (historyControls) historyControls.classList.remove('hidden');
      renderScanCards();

    } catch (err) {
      console.error(err);
      historyLoading.classList.add('hidden');
      historyError.textContent = err.message;
      historyError.classList.remove('hidden');
    }
  }

  // --- END TAB LOGIC ---

  advToggle?.addEventListener('click', () => {
    advPanel.classList.toggle('hidden');
    advToggle.querySelector('svg').classList.toggle('rotate-180');
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    let url = urlInput.value.trim();
    if (!url) return;
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

    const scanError = document.getElementById('scan-error');
    if (scanError) scanError.classList.add('hidden');

    const token = localStorage.getItem('penai_token');
    
    // Reset
    reportWrap.classList.add('hidden');
    reportWrap.innerHTML = '';
    progressWrap.classList.remove('hidden');
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<span class="animate-spin inline-block w-5 h-5 border-2 border-current border-t-transparent rounded-full"></span> Scanning...';

    // Run stages
    for (const stage of SCAN_STAGES) {
      progressBar.style.width = stage.pct + '%';
      progressMsg.textContent = stage.msg;
      progressPct.textContent = stage.pct + '%';
      await new Promise(r => setTimeout(r, 300 + Math.random() * 200)); // Make the fake progress slightly faster
    }

    let backendVulnerabilities = [];
    try {
      if (token) {
        // API call to backend for logged in users
        const response = await fetch('http://localhost:5000/api/scans', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({ targetUrl: url })
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.message || data.errors?.[0]?.msg || 'Failed to start scan');
        }

        // Capture backend vulnerabilities if the response includes them
        if (data.data && Array.isArray(data.data.vulnerabilities)) {
          backendVulnerabilities = data.data.vulnerabilities;
        }
      }

      progressBar.style.width = '100%';
      progressPct.textContent = '100%';
      progressMsg.innerHTML = token ? '<span class="text-neon-green font-semibold">✓ Scan complete & saved!</span>' : '<span class="text-neon-green font-semibold">✓ Scan complete!</span>';
      await new Promise(r => setTimeout(r, 800));
      progressWrap.classList.add('hidden');

      // Generate & render report (UI representation)
      const report = generateReport(url);
      // Attach backend vulnerabilities to the report
      if (backendVulnerabilities.length > 0) {
        report.vulnerabilities = backendVulnerabilities;
      }
      renderReportUI(report, reportWrap);

    } catch (error) {
      console.error('Scan Error:', error);
      if (scanError) {
        scanError.textContent = error.message || 'An error occurred while starting the scan.';
        scanError.classList.remove('hidden');
      } else {
        alert(error.message || 'An error occurred while starting the scan.');
      }
      progressWrap.classList.add('hidden');
    } finally {
      scanBtn.disabled = false;
      scanBtn.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Run AI Penetration Test';
    }
  });
}

document.addEventListener('DOMContentLoaded', initScanner);
