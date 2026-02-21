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
//   #1 SQL Injection (FIXED) - routes/accounts.js   (CWE-89) ← REMEDIATED
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
// ============================================================

require('dotenv').config();
const express = require('express');
const { requestLogger } = require('./middleware/logger');
const { closeDatabase } = require('./config/database');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger); // VULN #8: PII logger

// Routes
app.use('/api/accounts', require('./routes/accounts'));     // VULN #1: SQL Injection
app.use('/api/search', require('./routes/search'));         // VULN #2: XSS
app.use('/api/users', require('./routes/users'));           // VULN #4: Missing auth
app.use('/api/transfers', require('./routes/transfers'));   // VULN #5: IDOR
app.use('/api/balance', require('./routes/balance'));       // FALSE POSITIVE #6
app.use('/api/documents', require('./routes/documents'));   // VULN #9: Path Traversal
app.use('/api/webhooks', require('./routes/webhooks'));     // VULN #10: SSRF
app.use('/api/settings', require('./routes/settings'));     // VULN #11: Prototype Pollution
app.use('/api/export', require('./routes/export'));         // VULN #12: RCE eval/exec

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Root
app.get('/', (req, res) => {
  res.json({
    name: 'Vulnerable Banking API',
    version: '1.0.0',
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
