// ============================================================
// VULNERABILITIES: Server-Side Template Injection, NoSQL Injection,
//   Insecure Cookie, CORS Misconfiguration, Regex DoS
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');

// VULN #27: Server-Side Template Injection (CWE-1336)
// User input directly interpolated into template string that gets evaluated
router.post('/send', authenticateToken, (req, res) => {
  const { recipient, subject, template_body } = req.body;

  // User-controlled template body executed with Function constructor
  // Attacker: template_body = "${require('child_process').execSync('whoami')}"
  try {
    const renderTemplate = new Function('user', 'data',
      `return \`${template_body}\`;`
    );

    const rendered = renderTemplate(req.user, { recipient, subject });

    // Log notification for audit (also logs the rendered malicious output)
    console.log(`[NOTIFICATION] To: ${recipient}, Subject: ${subject}, Body: ${rendered}`);

    res.json({ message: 'Notification sent', rendered_preview: rendered });
  } catch (err) {
    res.status(500).json({ error: 'Template rendering failed', details: err.message });
  }
});

// VULN #28: Regex Denial of Service / ReDoS (CWE-1333)
// Evil regex with catastrophic backtracking on crafted input
router.post('/validate-email', (req, res) => {
  const { email } = req.body;

  // This regex has catastrophic backtracking:
  // Input like "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" will hang the server
  const emailRegex = /^([a-zA-Z0-9])(([-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/;

  const startTime = Date.now();
  const isValid = emailRegex.test(email);
  const elapsed = Date.now() - startTime;

  res.json({ email, valid: isValid, processing_time_ms: elapsed });
});

// VULN #29: Insecure Cookie Configuration (CWE-614)
// Session cookie without Secure, HttpOnly, or SameSite flags
router.post('/subscribe', authenticateToken, (req, res) => {
  const { channel, frequency } = req.body;

  // Setting session/preference cookies without security flags
  res.cookie('notification_prefs', JSON.stringify({ channel, frequency }), {
    httpOnly: false,    // Accessible via JavaScript - XSS can steal it
    secure: false,      // Sent over HTTP - MITM can intercept
    sameSite: 'none',   // Sent with cross-site requests - CSRF vulnerable
    maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year - excessive lifetime
  });

  // Also storing user session token in a regular cookie
  res.cookie('session_token', req.headers['authorization'], {
    httpOnly: false,
    secure: false,
  });

  res.json({ message: 'Subscribed to notifications', channel, frequency });
});

// VULN #30: Improper Error Handling - Stack Trace Exposure (CWE-209)
// Full stack traces and internal details exposed to client
router.get('/history', authenticateToken, (req, res) => {
  try {
    const db = getDatabase();
    // Intentionally referencing non-existent table to trigger error
    const notifications = db.prepare(
      'SELECT * FROM notification_log WHERE user_id = ?'
    ).all(req.user.id);

    res.json({ data: notifications });
  } catch (err) {
    // VULNERABLE: Exposes full error details including stack trace, file paths
    res.status(500).json({
      error: err.message,
      stack: err.stack,           // Full stack trace with file paths
      code: err.code,
      errno: err.errno,
      sql_state: err.sqlState,
      query: err.sql,             // Leaks the SQL query
      database_path: process.env.DATABASE_URL || '/app/banking.db',
      node_env: process.env.NODE_ENV,
    });
  }
});

// VULN #31: HTTP Response Splitting / Header Injection (CWE-113)
// Fix: sanitize user inputs to prevent CRLF injection in HTTP headers
function sanitizeHeaderValue(value) {
  if (typeof value !== 'string') return '';
  // Remove CR and LF characters to prevent header injection
  return value.replace(/[\r\n]/g, '');
}

router.get('/unsubscribe', (req, res) => {
  const { token, redirect } = req.query;

  // Sanitize inputs to prevent HTTP response splitting / header injection
  const safeRedirect = sanitizeHeaderValue(redirect) || '/';
  const safeToken = sanitizeHeaderValue(token) || 'none';

  res.setHeader('X-Unsubscribe-Redirect', safeRedirect); // Fixed header injection
  res.setHeader('X-Token-Used', safeToken);              // Fixed header injection

  res.json({ message: 'Unsubscribed successfully' });
});

module.exports = router;