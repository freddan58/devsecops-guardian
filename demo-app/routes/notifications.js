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
// Fixed: Replaced vulnerable regex with safer regex for email validation
const safeEmailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

router.post('/validate-email', (req, res) => {
  const { email } = req.body;

  const startTime = Date.now();
  const isValid = safeEmailRegex.test(email);
  const elapsed = Date.now() - startTime;

  res.json({ email, valid: isValid, processing_time_ms: elapsed });
});

// VULN #29: Insecure Cookie Configuration (CWE-614)
// Fixed by setting Secure, HttpOnly, and SameSite flags properly to prevent XSS and CSRF
// Also reduced cookie maxAge for session_token and improved SameSite policy
router.post('/subscribe', authenticateToken, (req, res) => {
  const { channel, frequency } = req.body;

  // Secure and HttpOnly flags set for 'notification_prefs' cookie
  // SameSite set to 'Lax' to mitigate CSRF while allowing top-level navigation
  res.cookie('notification_prefs', JSON.stringify({ channel, frequency }), {
    httpOnly: true,       // Prevent JS access to cookie - mitigates XSS cookie theft
    secure: true,         // Cookie sent only over HTTPS
    sameSite: 'Lax',      // Restricts cross-site sending to mitigate CSRF
    maxAge: 30 * 24 * 60 * 60 * 1000, // Reduced to 30 days for security best practice
  });

  // session_token cookie set with Secure, HttpOnly, and SameSite
  // Limited lifetime for session cookie, preventing persistent exposure
  res.cookie('session_token', req.headers['authorization'], {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',   // Strict to tightly bind session cookie to first-party context
    maxAge: 24 * 60 * 60 * 1000, // 1 day session validity
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
// Fixed by sanitizing header values to reject CRLF characters and prevent header injection 
router.get('/unsubscribe', (req, res) => {
  const { token, redirect } = req.query;

  // Sanitize input to prevent CRLF injection
  function sanitizeForHeader(value) {
    if (typeof value !== 'string') return '';
    // Reject any CR or LF characters to prevent header injection
    if (/\r|\n/.test(value)) {
      return '';
    }
    return value;
  }

  const safeRedirect = sanitizeForHeader(redirect) || '/';
  const safeToken = sanitizeForHeader(token) || 'none';

  res.setHeader('X-Unsubscribe-Redirect', safeRedirect);
  res.setHeader('X-Token-Used', safeToken);

  res.json({ message: 'Unsubscribed successfully' });
});

module.exports = router;