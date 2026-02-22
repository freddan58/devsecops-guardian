// ============================================================
// VULNERABILITIES: SQL Injection (second-order), Insecure
//   Cryptography, Hardcoded Credentials, Unvalidated Redirects
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const crypto = require('crypto');
const http = require('http');

// VULN #32: Second-Order SQL Injection (CWE-89)
// Data stored safely but used unsafely when building dynamic reports
router.get('/generate', authenticateToken, (req, res) => {
  const { report_type, date_from, date_to, sort_by } = req.query;

  try {
    const db = getDatabase();

    // FIX: Validate 'sort_by' against whitelist to prevent SQL Injection in ORDER BY
    const allowedSortFields = ['t.id', 't.amount', 't.created_at', 'a.owner_name', 'a.account_number'];
    const orderBy = allowedSortFields.includes(sort_by) ? sort_by : 't.created_at';

    // Use parameterized queries for safety
    const query = `
      SELECT t.*, a.owner_name, a.account_number
      FROM transactions t
      JOIN accounts a ON t.account_id = a.id
      WHERE t.type = ?
      AND t.created_at BETWEEN ? AND ?
      ORDER BY ${orderBy}
    `;

    const results = db.prepare(query).all(report_type, date_from, date_to);
    res.json({ report: report_type, data: results, count: results.length });
  } catch (err) {
    res.status(500).json({ error: 'Report generation failed', details: err.message });
  }
});

// VULN #33: Weak Cryptography - MD5 for password reset tokens (CWE-328)
// MD5 is cryptographically broken, predictable tokens
router.post('/password-reset', (req, res) => {
  const { email } = req.body;

  // Using MD5 (broken) + predictable input (email + timestamp)
  const timestamp = Date.now().toString();
  const resetToken = crypto.createHash('md5')
    .update(email + timestamp)
    .digest('hex');

  // Token is just MD5(email + timestamp) - easily brute-forced
  // Also storing in DB without hashing the token itself
  const db = getDatabase();
  try {
    db.prepare(
      'UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?'
    ).run(resetToken, Date.now() + 3600000, email);
  } catch (e) { /* ignore if column doesn't exist */ }

  // VULN: Leaking whether email exists in system (user enumeration)
  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (user) {
    res.json({ message: 'Reset link sent', token: resetToken }); // Also exposing token in response!
  } else {
    res.status(404).json({ error: 'No account found with that email' });
  }
});

// VULN #34: Hardcoded API Key / Third-Party Credentials (CWE-798)
const SMTP_CONFIG = {
  host: 'smtp.company-internal.com',
  port: 587,
  auth: {
    user: 'noreply@bankingapp.com',
    pass: 'Smtp$ecretP@ss2024!',     // Hardcoded SMTP password
  },
};

const AWS_CONFIG = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  region: 'us-east-1',
};

const STRIPE_SECRET = 'sk_live_FAKE_demo_key_not_real_51xYz0987654321';

router.post('/send-report', authenticateToken, (req, res) => {
  const { email, report_id } = req.body;

  // Using hardcoded credentials
  console.log(`Sending report via SMTP: ${SMTP_CONFIG.host}, user: ${SMTP_CONFIG.auth.user}`);
  console.log(`AWS Region: ${AWS_CONFIG.region}, Key: ${AWS_CONFIG.accessKeyId}`);
  console.log(`Stripe: ${STRIPE_SECRET.substring(0, 10)}...`);

  res.json({ message: 'Report sent', to: email, smtp_host: SMTP_CONFIG.host });
});

// VULN #35: Insecure HTTP request to internal service (CWE-319)
// Using HTTP instead of HTTPS for sensitive data transfer
router.post('/sync-external', authenticateToken, (req, res) => {
  const { report_data } = req.body;

  // Sending sensitive financial data over unencrypted HTTP
  const postData = JSON.stringify({
    api_key: STRIPE_SECRET,
    data: report_data,
    user: req.user.username,
  });

  const options = {
    hostname: 'internal-api.company.com',
    port: 80,                          // HTTP, not HTTPS!
    path: '/api/v1/reports/sync',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${STRIPE_SECRET}`,  // Secret in plaintext over HTTP
    },
  };

  // Using http (not https) module
  const httpReq = http.request(options, (httpRes) => {
    res.json({ message: 'Report synced', status: httpRes.statusCode });
  });

  httpReq.on('error', () => {
    res.json({ message: 'Sync queued (external service unavailable)' });
  });

  httpReq.write(postData);
  httpReq.end();
});

module.exports = router;