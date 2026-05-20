// PenAI — OWASP Complete Library Data & Renderer

const OWASP_DATA = [
  { id:'A01', name:'Broken Access Control', severity:'Critical', color:'#ff4444',
    icon:'🔓',
    risk:'Access control enforces policy so users cannot act outside their intended permissions. Failures lead to unauthorized data disclosure, modification, or destruction.',
    detect:'PenAI crawls every authenticated route, attempts horizontal/vertical privilege escalation, tests IDOR on all resource endpoints, and validates CORS policies.',
    example:'In 2023, a major SaaS platform exposed 3.1M user records because API endpoints only checked authentication — not authorization. Changing /api/users/123 to /api/users/124 returned another user\'s full profile.',
    prevention:[
      {lang:'Node.js',code:`// Middleware: ownership check\napp.get('/api/users/:id', auth, (req, res) => {\n  if (req.user.id !== parseInt(req.params.id)) {\n    return res.status(403).json({ error: 'Forbidden' });\n  }\n  // return user data\n});`},
      {lang:'Python',code:`# Flask decorator\n@app.route('/api/users/<int:uid>')\n@login_required\ndef get_user(uid):\n    if current_user.id != uid:\n        abort(403)\n    return jsonify(User.query.get(uid).to_dict())`}
    ]},
  { id:'A02', name:'Cryptographic Failures', severity:'High', color:'#ff8800',
    icon:'🔐',
    risk:'Failures related to cryptography which often lead to sensitive data exposure. Includes transmitting data in clear text, using weak algorithms, or improper key management.',
    detect:'PenAI checks TLS configuration, certificate validity, cipher suite strength, cookie flags (Secure/HttpOnly), password storage hashing, and identifies any cleartext transmission of PII.',
    example:'Equifax breach (2017): Unpatched Apache Struts vulnerability combined with unencrypted internal databases exposed 147M people\'s SSNs, birth dates, and addresses.',
    prevention:[
      {lang:'Nginx',code:`# Force HTTPS + HSTS\nserver {\n  listen 443 ssl;\n  ssl_protocols TLSv1.2 TLSv1.3;\n  ssl_ciphers HIGH:!aNULL:!MD5;\n  add_header Strict-Transport-Security\n    "max-age=63072000; includeSubDomains" always;\n}`},
      {lang:'Python',code:`# Hash passwords with bcrypt\nimport bcrypt\nhashed = bcrypt.hashpw(\n  password.encode('utf-8'),\n  bcrypt.gensalt(rounds=12)\n)`}
    ]},
  { id:'A03', name:'Injection', severity:'Critical', color:'#ff4444',
    icon:'💉',
    risk:'User-supplied data is not validated, filtered, or sanitized. SQL, NoSQL, OS command, LDAP, and XSS injection can lead to data theft, data loss, or full system compromise.',
    detect:'PenAI fuzzes all input parameters with injection payloads (SQL, XSS, command injection), tests parameterized vs concatenated queries, and detects ORM misuse patterns.',
    example:'SQL injection in a login form: entering `admin\' OR 1=1--` as the username bypasses authentication entirely, granting admin access to the attacker.',
    prevention:[
      {lang:'Node.js',code:`// Parameterized query (pg library)\nconst result = await pool.query(\n  'SELECT * FROM users WHERE email = $1 AND active = $2',\n  [email, true]\n);`},
      {lang:'Java',code:`// PreparedStatement\nString sql = "SELECT * FROM users WHERE email = ?";\nPreparedStatement ps = conn.prepareStatement(sql);\nps.setString(1, email);\nResultSet rs = ps.executeQuery();`}
    ]},
  { id:'A04', name:'Insecure Design', severity:'Medium', color:'#ffcc00',
    icon:'📐',
    risk:'Insecure design is a broad category for missing or ineffective security controls at the architectural level. It cannot be fixed by a perfect implementation alone.',
    detect:'PenAI analyzes rate limiting, account lockout policies, multi-factor authentication presence, business logic abuse vectors, and abuse-case testing coverage.',
    example:'A ticket platform allowed unlimited coupon redemptions by replaying the same API call, costing the company $2.3M before the logic flaw was patched.',
    prevention:[
      {lang:'Architecture',code:`Security Design Checklist:\n✓ Threat model for every user story\n✓ Rate limiting on all sensitive endpoints\n✓ Account lockout after N failed attempts\n✓ CAPTCHA on public-facing forms\n✓ Business logic abuse-case testing\n✓ Principle of least privilege`},
      {lang:'Express.js',code:`const rateLimit = require('express-rate-limit');\nconst loginLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000, // 15 min\n  max: 5, // 5 attempts\n  message: { error: 'Too many login attempts' }\n});\napp.post('/login', loginLimiter, loginHandler);`}
    ]},
  { id:'A05', name:'Security Misconfiguration', severity:'High', color:'#ff8800',
    icon:'⚙️',
    risk:'Missing hardening, open cloud storage, verbose error messages, unnecessary features enabled, or default accounts/passwords. The most commonly seen issue.',
    detect:'PenAI checks HTTP security headers, server banners, directory listings, error verbosity, default credentials, unnecessary HTTP methods, and CORS misconfigurations.',
    example:'An AWS S3 bucket at s3://company-backups was left publicly readable, exposing 500GB of database backups containing customer payment data.',
    prevention:[
      {lang:'Nginx',code:`# Security headers\nadd_header X-Content-Type-Options nosniff;\nadd_header X-Frame-Options DENY;\nadd_header X-XSS-Protection "1; mode=block";\nadd_header Referrer-Policy strict-origin;\nadd_header Permissions-Policy "camera=(), geolocation=()";\n\n# Hide server version\nserver_tokens off;`},
      {lang:'Express.js',code:`const helmet = require('helmet');\napp.use(helmet()); // Sets 15+ security headers\n\n// Disable X-Powered-By\napp.disable('x-powered-by');\n\n// Custom error handler (no stack traces)\napp.use((err, req, res, next) => {\n  res.status(500).json({ error: 'Internal error' });\n});`}
    ]},
  { id:'A06', name:'Vulnerable & Outdated Components', severity:'High', color:'#ff8800',
    icon:'📦',
    risk:'Using components with known vulnerabilities, unsupported frameworks, or unpatched dependencies. Automated tools can detect and exploit these at scale.',
    detect:'PenAI fingerprints all client-side libraries and frameworks, cross-references with CVE databases (NVD, Snyk), and flags any component with known exploits.',
    example:'Log4Shell (CVE-2021-44228): A critical RCE in Log4j affected millions of Java applications. Attackers could execute arbitrary code by injecting a JNDI lookup string.',
    prevention:[
      {lang:'CLI',code:`# Audit Node.js dependencies\nnpm audit --production\nnpm audit fix\n\n# Python\npip-audit\nsafety check\n\n# Use Dependabot or Renovate\n# for automated PR updates`},
      {lang:'GitHub Actions',code:`# .github/workflows/security.yml\nname: Security Audit\non: [push, pull_request]\njobs:\n  audit:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm audit --audit-level=high\n      - uses: snyk/actions/node@master`}
    ]},
  { id:'A07', name:'Identification & Authentication Failures', severity:'Medium', color:'#ffcc00',
    icon:'🪪',
    risk:'Weak authentication mechanisms: credential stuffing, brute force, weak passwords, improper session management, or missing multi-factor authentication.',
    detect:'PenAI tests password policies, session token entropy, session fixation, cookie security flags, brute-force resistance, and MFA implementation.',
    example:'A banking app used sequential 6-digit session IDs. Attackers enumerated active sessions and hijacked accounts by incrementing the session value.',
    prevention:[
      {lang:'Node.js',code:`// Secure session with high entropy\nconst session = require('express-session');\napp.use(session({\n  secret: require('crypto').randomBytes(64).toString('hex'),\n  name: '__Host-sid',\n  cookie: {\n    secure: true, httpOnly: true,\n    sameSite: 'strict', maxAge: 3600000\n  },\n  resave: false, saveUninitialized: false\n}));`},
      {lang:'Password Policy',code:`Password Requirements:\n✓ Minimum 12 characters\n✓ Check against breached password lists (HIBP API)\n✓ No common patterns (password123, qwerty)\n✓ Enforce MFA for all accounts\n✓ Implement account lockout (5 failures / 15 min)\n✓ Use Argon2id or bcrypt for hashing`}
    ]},
  { id:'A08', name:'Software & Data Integrity Failures', severity:'Medium', color:'#ffcc00',
    icon:'🔗',
    risk:'Code and infrastructure that doesn\'t protect against integrity violations: unsigned updates, insecure CI/CD pipelines, or third-party code without SRI verification.',
    detect:'PenAI checks all external script/CSS references for Subresource Integrity (SRI) hashes, analyzes update mechanisms, and scans for insecure deserialization.',
    example:'SolarWinds hack (2020): Attackers compromised the CI/CD pipeline to inject malware into signed updates, affecting 18,000+ organizations including US government agencies.',
    prevention:[
      {lang:'HTML',code:`<!-- Subresource Integrity -->\n<script\n  src="https://cdn.example.com/lib.min.js"\n  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w"\n  crossorigin="anonymous"\n></script>`},
      {lang:'CI/CD',code:`# Verify artifact signatures\nsteps:\n  - name: Verify checksum\n    run: |\n      sha256sum -c checksums.txt\n      gpg --verify release.sig release.tar.gz`}
    ]},
  { id:'A09', name:'Security Logging & Monitoring Failures', severity:'Low', color:'#4488ff',
    icon:'📊',
    risk:'Without logging and monitoring, breaches cannot be detected. Most studies show detection time is over 200 days, usually by external parties rather than internal monitoring.',
    detect:'PenAI generates deliberate anomalous traffic patterns and checks for evidence of detection, alerting, or rate-limiting responses that indicate active monitoring.',
    example:'A retailer was breached for 6 months before discovery. Had they monitored failed login spikes (10,000+/hour from the same IP range), the attack would have been caught on day one.',
    prevention:[
      {lang:'Node.js',code:`const winston = require('winston');\nconst logger = winston.createLogger({\n  transports: [\n    new winston.transports.File({\n      filename: 'security.log',\n      level: 'warn'\n    })\n  ]\n});\n\n// Log security events\nlogger.warn('Failed login', {\n  ip: req.ip, email: req.body.email,\n  timestamp: new Date().toISOString()\n});`},
      {lang:'SIEM Rule',code:`# Alert: Brute force detection\nrule:\n  name: "Brute Force Login"\n  condition: >-\n    count(failed_login) > 10\n    within 5 minutes\n    group_by source_ip\n  action:\n    - alert: security-team\n    - block_ip: temporary (30m)`}
    ]},
  { id:'A10', name:'Server-Side Request Forgery (SSRF)', severity:'Medium', color:'#ffcc00',
    icon:'🌐',
    risk:'SSRF occurs when a web app fetches a remote resource without validating the user-supplied URL, allowing attackers to access internal services, cloud metadata, or exfiltrate data.',
    detect:'PenAI tests all URL-accepting parameters with internal IP ranges (127.0.0.1, 169.254.169.254, 10.x), DNS rebinding payloads, and cloud metadata endpoint probes.',
    example:'Capital One breach (2019): An SSRF vulnerability in a WAF allowed access to AWS EC2 metadata, leading to theft of 100M+ customer records from S3 buckets.',
    prevention:[
      {lang:'Node.js',code:`// Validate & whitelist URLs\nconst { URL } = require('url');\nfunction isSafeUrl(input) {\n  const url = new URL(input);\n  const blocked = ['127.0.0.1','localhost',\n    '169.254.169.254','0.0.0.0','[::1]'];\n  if (blocked.includes(url.hostname)) return false;\n  if (/^(10|172\\.(1[6-9]|2|3[01])|192\\.168)\\./\n    .test(url.hostname)) return false;\n  return url.protocol === 'https:';\n}`},
      {lang:'AWS',code:`# Block metadata endpoint (iptables)\niptables -A OUTPUT -d 169.254.169.254 \\\n  -j DROP\n\n# Or use IMDSv2 (requires token)\naws ec2 modify-instance-metadata-options \\\n  --instance-id i-1234567890 \\\n  --http-tokens required \\\n  --http-endpoint enabled`}
    ]}
];

const OWASP_EXTRA_TABS = [
  { id:'api', name:'API Security', desc:'OWASP API Security Top 10 covers risks specific to APIs, including BOLA, broken auth, and mass assignment.' },
  { id:'mobile', name:'Mobile Security', desc:'OWASP Mobile Top 10 covers insecure data storage, insecure communication, and client-side injection in mobile apps.' },
  { id:'cloud', name:'Cloud Security', desc:'Cloud-native risks including misconfigured storage buckets, overly permissive IAM roles, and insecure serverless functions.' }
];

function renderOwaspCard(item, idx) {
  const esc = s => s.replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const sevMap = { Critical:'bg-red-500/15 text-red-400 border-red-500/30', High:'bg-orange-500/15 text-orange-400 border-orange-500/30', Medium:'bg-yellow-500/15 text-yellow-400 border-yellow-500/30', Low:'bg-blue-500/15 text-blue-400 border-blue-500/30' };
  const sevClass = sevMap[item.severity] || '';

  return `
  <div class="owasp-card glass-card p-6 fade-in-up" style="animation-delay:${idx*0.06}s; border-left: 3px solid ${item.color}" data-animate>
    <div class="flex items-start justify-between mb-3">
      <div class="flex items-center gap-3">
        <span class="text-2xl">${item.icon}</span>
        <div>
          <span class="text-[10px] font-mono text-gray-600">${item.id}:2021</span>
          <h3 class="text-white font-bold text-base leading-tight">${item.name}</h3>
        </div>
      </div>
      <span class="sev-badge text-[11px] font-semibold px-3 py-1 rounded-full border ${sevClass} whitespace-nowrap">${item.severity}</span>
    </div>

    <p class="text-gray-400 text-sm mb-4 leading-relaxed">${item.risk}</p>

    <div class="space-y-3 mb-4">
      <div class="owasp-detail-block">
        <p class="owasp-detail-label">🔍 How PenAI Detects It</p>
        <p class="text-gray-400 text-xs leading-relaxed">${item.detect}</p>
      </div>
      <div class="owasp-detail-block">
        <p class="owasp-detail-label">🌍 Real-World Example</p>
        <p class="text-gray-400 text-xs leading-relaxed">${item.example}</p>
      </div>
    </div>

    <button onclick="toggleOwaspCode(this)" class="text-neon-green text-xs font-semibold hover:underline cursor-pointer flex items-center gap-1 mb-2">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="transition-transform duration-200"><path d="M9 18l6-6-6-6"/></svg>
      Prevention Code Snippets
    </button>
    <div class="hidden mt-3 space-y-2">
      ${item.prevention.map(p => `
        <div class="bg-black/40 rounded-lg p-3 border border-gray-800/50 relative">
          <span class="text-[10px] font-mono text-neon-blue uppercase tracking-wider">${p.lang}</span>
          <pre class="text-green-400 text-xs mt-1 overflow-x-auto"><code>${esc(p.code)}</code></pre>
          <button onclick="navigator.clipboard.writeText(this.closest('.relative').querySelector('code').textContent);this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',1500)" class="absolute top-2 right-2 text-[10px] text-gray-600 hover:text-neon-green cursor-pointer transition-colors">Copy</button>
        </div>
      `).join('')}
    </div>

    <div class="mt-4 pt-3 border-t border-gray-800/50">
      <button onclick="testVulnerability('${item.id}')" class="text-xs font-semibold text-neon-blue hover:text-neon-green transition-colors cursor-pointer flex items-center gap-1.5">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        Test this vulnerability
      </button>
    </div>
  </div>`;
}

function toggleOwaspCode(btn) {
  const panel = btn.nextElementSibling;
  panel.classList.toggle('hidden');
  btn.querySelector('svg').classList.toggle('rotate-90');
}

function testVulnerability(id) {
  const scanSection = document.getElementById('scanner');
  const scanInput = document.getElementById('scan-url');
  const vuln = OWASP_DATA.find(d => d.id === id);
  if (scanSection && scanInput) {
    scanInput.value = `https://demo-vulnerable-site.com/${id.toLowerCase()}-test`;
    scanSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    // Flash highlight on scanner card
    const card = scanSection.querySelector('.scanner-card');
    if (card) {
      card.style.boxShadow = '0 0 30px rgba(0, 255, 157, 0.3)';
      setTimeout(() => { card.style.boxShadow = ''; }, 1500);
    }
    setTimeout(() => scanInput.focus(), 600);
  }
}

function initOwaspLibrary() {
  const container = document.getElementById('owasp-grid');
  const tabBtns = document.querySelectorAll('[data-owasp-tab]');
  if (!container) return;

  // Render main grid
  container.innerHTML = OWASP_DATA.map((d,i) => renderOwaspCard(d,i)).join('');

  // Tab switching
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => {
        b.classList.remove('active','border-neon-green','text-neon-green');
        b.classList.add('border-transparent','text-gray-500');
      });
      btn.classList.add('active','border-neon-green','text-neon-green');
      btn.classList.remove('border-transparent','text-gray-500');

      const tab = btn.dataset.owaspTab;
      if (tab === 'top10') {
        container.innerHTML = OWASP_DATA.map((d,i) => renderOwaspCard(d,i)).join('');
      } else {
        const extra = OWASP_EXTRA_TABS.find(t => t.id === tab);
        container.innerHTML = `
          <div class="col-span-full text-center py-16">
            <div class="text-4xl mb-4">🔒</div>
            <h3 class="text-xl font-bold text-white mb-2">OWASP ${extra.name}</h3>
            <p class="text-gray-500 max-w-md mx-auto mb-4">${extra.desc}</p>
            <span class="hero-badge">Coming Soon in PenAI v4.0</span>
          </div>`;
      }
    });
  });

  // Search filter
  const search = document.getElementById('owasp-search');
  if (search) {
    search.addEventListener('input', () => {
      const q = search.value.toLowerCase();
      const filtered = OWASP_DATA.filter(d =>
        d.name.toLowerCase().includes(q) ||
        d.id.toLowerCase().includes(q) ||
        d.risk.toLowerCase().includes(q)
      );
      container.innerHTML = filtered.length
        ? filtered.map((d,i) => renderOwaspCard(d,i)).join('')
        : '<p class="col-span-full text-center text-gray-600 py-12">No matching vulnerabilities found.</p>';
    });
  }
}

document.addEventListener('DOMContentLoaded', initOwaspLibrary);
