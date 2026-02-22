// ============================================================
// VULNERABILITIES: Mass Assignment, Privilege Escalation,
//   Insecure Direct Object Reference, Debug Endpoint Exposure
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');

// VULN #13: Mass Assignment (CWE-915)
// Accepts entire request body and merges into user record
// Attacker can set { "role": "admin" } to escalate privileges
router.put('/users/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const updates = req.body; // No field filtering!

  try {
    const db = getDatabase();
    const fields = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    const values = Object.values(updates);

    // Directly builds SQL from user-controlled field names - also SQL injection via column names
    db.prepare(`UPDATE users SET ${fields} WHERE id = ?`).run(...values, id);

    res.json({ message: 'User updated', updated_fields: Object.keys(updates) });
  } catch (err) {
    res.status(500).json({ error: 'Update failed', details: err.message });
  }
});

// VULN #14: Debug/Admin Endpoint Exposed Without Auth (CWE-489)
// Leaks full database schema, environment variables, and internal state
router.get('/debug', (req, res) => {
  const db = getDatabase();
  const tables = db.prepare(
    "SELECT name, sql FROM sqlite_master WHERE type='table'"
  ).all();

  const users = db.prepare('SELECT * FROM users').all();

  res.json({
    environment: process.env,       // Leaks ALL env vars including secrets
    database_schema: tables,
    all_users: users,               // Leaks password hashes
    node_version: process.version,
    memory_usage: process.memoryUsage(),
    uptime: process.uptime(),
    cwd: process.cwd(),
    pid: process.pid,
  });
});

// VULN #15: Privilege Escalation - No role check (CWE-269)
// Fixed: Added admin role check to prevent unauthorized privilege escalation
router.post('/promote/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  // Security fix: Only allow users with 'admin' role to promote others
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Admins only' });
  }

  try {
    const db = getDatabase();
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run('admin', id);
    res.json({ message: `User ${id} promoted to admin` });
  } catch (err) {
    res.status(500).json({ error: 'Promotion failed' });
  }
});

// VULN #16: Bulk Data Export Without Pagination or Rate Limiting (CWE-770)
// Returns ALL records - denial of service / data exfiltration
router.get('/export-all', (req, res) => {
  const db = getDatabase();
  const users = db.prepare('SELECT * FROM users').all();
  const accounts = db.prepare('SELECT * FROM accounts').all();
  const transactions = db.prepare('SELECT * FROM transactions').all();

  // No pagination, no rate limiting, no auth
  res.json({
    users: users,           // Includes password hashes
    accounts: accounts,     // Includes balances
    transactions: transactions,
    exported_at: new Date().toISOString(),
  });
});

module.exports = router;