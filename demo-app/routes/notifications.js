// ============================================================
// VULNERABILITIES: Server-Side Template Injection, NoSQL Injection,
//   Insecure Cookie, CORS Misconfiguration, Regex DoS
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const mustache = require('mustache');

// VULN #27: Server-Side Template Injection (CWE-1336)
// Fixed: Replaced unsafe Function constructor with safe Mustache template engine
// This prevents execution of arbitrary JS code from user input template_body
router.post('/send', authenticateToken, (req, res) => {
  const { recipient, subject, template_body } = req.body;

  try {
    // Prepare template data with controlled variables
    const data = {
      user: req.user,
      recipient: recipient,
      subject: subject
    };

    // Safely render template using mustache, which escapes inputs by default
    const rendered = mustache.render(template_body, data);

    // Log notification for audit (redacted sensitive user info)
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
  const emailRegex = /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/;

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
// User input directly in response headers
router.get('/unsubscribe', (req, res) => {
  const { token, redirect } = req.query;

  // User-controlled value in response header
  // Attacker: redirect=foo%0d%0aSet-Cookie:%20admin=true
  res.setHeader('X-Unsubscribe-Redirect', redirect || '/');
  res.setHeader('X-Token-Used', token || 'none');

  res.json({ message: 'Unsubscribed successfully' });
});

module.exports = router;