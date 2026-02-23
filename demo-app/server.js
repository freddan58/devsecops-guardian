// ============================================================
// DevSecOps Guardian - Vulnerable Banking API
// Purpose: Demo application with intentionally planted
//          security vulnerabilities for hackathon demonstration
//
// WARNING: This application contains INTENTIONAL vulnerabilities
//          for educational/demonstration purposes only.
//          DO NOT deploy to production.
//
// Vulnerabilities planted:
//   #1 SQL Injection (FIXED) - routes/accounts.js   (CWE-89) <- REMEDIATED
//   #2 Reflected XSS         - routes/search.js     (CWE-79)
//   #3 Hardcoded API Key     - config/database.js   (CWE-798)
//   #4 Missing Auth Check    - routes/users.js      (CWE-862)
//   #5 IDOR                  - routes/transfers.js   (CWE-639)
//   #6 SQL (parameterized)   - routes/balance.js     (FALSE POSITIVE)
//   #7 Weak Crypto (bcrypt)  - utils/auth.js         (FALSE POSITIVE)
//   #8 Logging PII           - middleware/logger.js   (CWE-532)
//   #9 Path Traversal / LFI  - routes/documents.js   (CWE-22)
//  #10 SSRF                  - routes/webhooks.js    (CWE-918)
//  #11 Prototype Pollution   - routes/settings.js    (CWE-1321)
//  #12 RCE via eval/exec     - routes/export.js      (CWE-502/CWE-78)
//  #13 Mass Assignment       - routes/admin.js       (CWE-915)
//  #14 Debug Endpoint        - routes/admin.js       (CWE-489)
//  #15 Privilege Escalation  - routes/admin.js       (CWE-269)
//  #16 Bulk Export No Auth   - routes/admin.js       (CWE-770)
//  #17 Race Condition        - routes/payments.js    (CWE-367)
//  #18 Insecure Randomness   - routes/payments.js    (CWE-330)
//  #19 Sensitive Data in URL - routes/payments.js    (CWE-598)
//  #20 No Input Validation   - routes/payments.js    (CWE-20)
//  #21 Cleartext Logging     - routes/payments.js    (CWE-312)
//  #22 Unrestricted Upload   - routes/uploads.js     (CWE-434)
//  #23 MIME Type Confusion   - routes/uploads.js     (CWE-436)
//  #24 XXE Injection         - routes/uploads.js     (CWE-611)
//  #25 Open Redirect         - routes/uploads.js     (CWE-601)
//  #26 Shell Injection       - routes/uploads.js     (CWE-78)
//  #27 Template Injection    - routes/notifications.js (CWE-1336)
//  #28 ReDoS                 - routes/notifications.js (CWE-1333)
//  #29 Insecure Cookies      - routes/notifications.js (CWE-614)
//  #30 Stack Trace Exposure  - routes/notifications.js (CWE-209)
//  #31 Header Injection      - routes/notifications.js (CWE-113)
//  #32 SQL Injection (2nd)   - routes/reports.js     (CWE-89)
//  #33 Weak Crypto MD5       - routes/reports.js     (CWE-328)
//  #34 Hardcoded Creds       - routes/reports.js     (CWE-798)
//  #35 Insecure HTTP         - routes/reports.js     (CWE-319)
//  #36 Predictable Sessions  - middleware/session.js  (CWE-330)
//  #37 Memory Exhaustion     - middleware/session.js  (CWE-400)
//  #38 Session Fixation      - middleware/session.js  (CWE-384)
//  #39 Plaintext Cookies     - middleware/session.js  (CWE-315)
//  #40 Wildcard CORS         - config/cors.js        (CWE-942)
//  #41 Missing Sec Headers   - config/cors.js        (CWE-693)
//  #42 Insecure TLS Config   - config/cors.js        (CWE-326)
//  #43 Horizontal IDOR       - routes/profile.js     (CWE-639)
//  #44 Weak Password Hash    - routes/profile.js     (CWE-916)
//  #45 Mass Data Exposure    - routes/profile.js     (CWE-200)
//  #46 NoSQL/SQL Injection   - routes/profile.js     (CWE-943)
//  #47 Unsafe Eval           - routes/profile.js     (CWE-95)
//  #48 Command Injection     - routes/diagnostics.js (CWE-78)
//  #49 XXE Injection         - routes/diagnostics.js (CWE-611)
//  #50 Log Forging           - routes/diagnostics.js (CWE-117)
//  #51 Resource Exhaustion   - routes/diagnostics.js (CWE-400)
//  #52 JWT None Algorithm    - routes/diagnostics.js (CWE-347)
// ============================================================

require('dotenv').config();
const express = require('express');
const { requestLogger } = require('./middleware/logger');
const { closeDatabase } = require('./config/database');
const { insecureHeaders } = require('./config/cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger);    // VULN #8: PII logger
app.use(insecureHeaders);  // VULN #41: Missing security headers

// Static files (for uploaded files - no auth on static!)
app.use('/uploads', express.static('public/uploads'));

// Routes - Original
app.use('/api/accounts', require('./routes/accounts'));         // VULN #1: SQL Injection
app.use('/api/search', require('./routes/search'));             // VULN #2: XSS
app.use('/api/users', require('./routes/users'));               // VULN #4: Missing auth
app.use('/api/transfers', require('./routes/transfers'));       // VULN #5: IDOR
app.use('/api/balance', require('./routes/balance'));           // FALSE POSITIVE #6
app.use('/api/documents', require('./routes/documents'));       // VULN #9: Path Traversal
app.use('/api/webhooks', require('./routes/webhooks'));         // VULN #10: SSRF
app.use('/api/settings', require('./routes/settings'));         // VULN #11: Prototype Pollution
app.use('/api/export', require('./routes/export'));             // VULN #12: RCE eval/exec

// Routes - New attack surface
app.use('/api/admin', require('./routes/admin'));               // VULN #13-16: Mass assignment, debug, privesc
app.use('/api/payments', require('./routes/payments'));         // VULN #17-21: Race condition, insecure random
app.use('/api/uploads', require('./routes/uploads'));           // VULN #22-26: File upload, XXE, shell injection
app.use('/api/notifications', require('./routes/notifications')); // VULN #27-31: SSTI, ReDoS, insecure cookies
app.use('/api/reports', require('./routes/reports'));           // VULN #32-35: SQL injection, weak crypto, creds
app.use('/api/profile', require('./routes/profile'));           // VULN #43-47: IDOR, weak hash, eval, data exposure
app.use('/api/diagnostics', require('./routes/diagnostics'));   // VULN #48-52: Command injection, XXE, JWT, log forge

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Root
app.get('/', (req, res) => {
  res.json({
    name: 'Vulnerable Banking API',
    version: '2.0.0',
    purpose: 'DevSecOps Guardian Demo - Intentionally Vulnerable',
    endpoints: [
      'GET  /api/accounts?id=',
      'GET  /api/accounts/summary',
      'GET  /api/search?q=',
      'POST /api/users/login',
      'GET  /api/users/profile',
      'DELETE /api/users/:id',
      'POST /api/transfers',
      'GET  /api/transfers/:id',
      'GET  /api/balance',
      'GET  /api/balance/history',
      'GET  /api/documents/download?file=',
      'GET  /api/documents/preview?file=',
      'POST /api/webhooks/test',
      'GET  /api/webhooks/preview?url=',
      'POST /api/settings/preferences',
      'GET  /api/settings/admin/config',
      'POST /api/export/query',
      'GET  /api/export/pdf?filename=',
      'POST /api/export/custom',
      'PUT  /api/admin/users/:id',
      'GET  /api/admin/debug',
      'POST /api/admin/promote/:id',
      'GET  /api/admin/export-all',
      'POST /api/payments/send',
      'POST /api/payments/request',
      'POST /api/payments/withdraw',
      'POST /api/payments/wire',
      'POST /api/uploads/avatar',
      'POST /api/uploads/import-xml',
      'GET  /api/uploads/callback?redirect_url=',
      'POST /api/uploads/resize',
      'POST /api/notifications/send',
      'POST /api/notifications/validate-email',
      'POST /api/notifications/subscribe',
      'GET  /api/notifications/history',
      'GET  /api/notifications/unsubscribe',
      'GET  /api/reports/generate',
      'POST /api/reports/password-reset',
      'POST /api/reports/send-report',
      'POST /api/reports/sync-external',
      'GET  /api/profile/:id',
      'POST /api/profile/change-password',
      'POST /api/profile/search',
      'POST /api/profile/calculate-bonus',
      'GET  /api/diagnostics/ping?host=',
      'POST /api/diagnostics/health-check',
      'POST /api/diagnostics/audit-log',
      'POST /api/diagnostics/import-config',
      'POST /api/diagnostics/verify-token',
      'GET  /health'
    ]
  });
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down...');
  closeDatabase();
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`Banking API running on http://localhost:${PORT}`);
  console.log('WARNING: This app contains intentional vulnerabilities for demo purposes');
});

module.exports = app;
