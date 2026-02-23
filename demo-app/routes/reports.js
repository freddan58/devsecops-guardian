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
const https = require('https');

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

  // FIXED: Replaced MD5 with secure random token generator
  // Using crypto.randomBytes to generate cryptographically secure tokens
  const resetToken = crypto.randomBytes(32).toString('hex');

  // Token is now securely random and unpredictable
  // Also storing in DB without hashing the token itself
  const db = getDatabase();
  try {
    db.prepare(
      'UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?'
    ).run(resetToken, Date.now() + 3600000, email);
  } catch (e) { /* ignore if column doesn't exist */ }

  // FIX: Do not expose reset tokens or user existence to prevent token leakage & user enumeration
  res.json({ message: 'If an account with that email exists, a reset link has been sent.' });
});

// VULN #34: Hardcoded API Key / Third-Party Credentials (CWE-798)
// Fixed: Moved hardcoded secrets to environment variables to protect sensitive credentials
const SMTP_CONFIG = {
  host: process.env.SMTP_HOST || 'smtp.company-internal.com',
  port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 587,
  auth: {
    user: process.env.SMTP_USER || 'noreply@bankingapp.com',
    pass: process.env.SMTP_PASS || undefined, // Do not fallback to hardcoded password
  },
};

const AWS_CONFIG = {
  accessKeyId: process.env.AWS_ACCESS_KEY_ID || undefined, // Removed hardcoded key
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || undefined, // Removed hardcoded secret
  region: process.env.AWS_REGION || 'us-east-1',
};

const STRIPE_SECRET = process.env.STRIPE_SECRET || undefined; // Removed hardcoded Stripe secret

router.post('/send-report', authenticateToken, (req, res) => {
  const { email, report_id } = req.body;

  // Using environment variables for credentials now
  console.log(`Sending report via SMTP: ${SMTP_CONFIG.host}, user: ${SMTP_CONFIG.auth.user}`);
  console.log(`AWS Region: ${AWS_CONFIG.region}, Key: ${AWS_CONFIG.accessKeyId}`);
  console.log(`Stripe: ${STRIPE_SECRET ? STRIPE_SECRET.substring(0, 10) + '...' : 'Not configured'}`);

  res.json({ message: 'Report sent', to: email, smtp_host: SMTP_CONFIG.host });
});

// VULN #35: Insecure HTTP request to internal service (CWE-319)
// Using HTTPS instead of HTTP for sensitive data transfer
router.post('/sync-external', authenticateToken, (req, res) => {
  const { report_data } = req.body;

  // Sending sensitive financial data over encrypted HTTPS
  const postData = JSON.stringify({
    api_key: STRIPE_SECRET,
    data: report_data,
    user: req.user.username,
  });

  const options = {
    hostname: 'internal-api.company.com',
    port: 443,                          // Changed to HTTPS port
    path: '/api/v1/reports/sync',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${STRIPE_SECRET}`,  // Secret now sent over HTTPS connection
    },
  };

  // Use https module to ensure encrypted transport
  const httpsReq = https.request(options, (httpsRes) => {
    res.json({ message: 'Report synced', status: httpsRes.statusCode });
  });

  httpsReq.on('error', () => {
    res.json({ message: 'Sync queued (external service unavailable)' });
  });

  httpsReq.write(postData);
  httpsReq.end();
});

module.exports = router;