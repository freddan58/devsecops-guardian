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
// Any authenticated user can grant admin role to any user
router.post('/promote/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  // No check if req.user.role === 'admin'

  try {
    const db = getDatabase();
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run('admin', id);
    res.json({ message: `User ${id} promoted to admin` });
  } catch (err) {
    res.status(500).json({ error: 'Promotion failed' });
  }
});

// VULN #16: Bulk Data Export Without Pagination or Rate Limiting (CWE-770)
// FIXED: Added authentication middleware to protect route
// Implemented pagination query params 'page' and 'limit' with defaults to prevent massive data exposure and DoS
router.get('/export-all', authenticateToken, (req, res) => {
  const db = getDatabase();
  const page = parseInt(req.query.page, 10) || 1;
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100); // limit max page size to 100
  const offset = (page - 1) * limit;

  try {
    // Select user fields excluding password hashes
    const users = db.prepare('SELECT id, username, email, role, created_at FROM users LIMIT ? OFFSET ?').all(limit, offset);

    // Select accounts with pagination
    const accounts = db.prepare('SELECT id, user_id, account_type, balance, created_at FROM accounts LIMIT ? OFFSET ?').all(limit, offset);

    // Select transactions with pagination
    const transactions = db.prepare('SELECT id, account_id, amount, transaction_type, created_at FROM transactions LIMIT ? OFFSET ?').all(limit, offset);

    res.json({
      users: users,           // Excludes password hashes
      accounts: accounts,     // Includes balances but only paginated
      transactions: transactions,
      page: page,
      limit: limit,
      exported_at: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: 'Data export failed' });
  }
  // Security comment: Added authentication and pagination to prevent unauthorized data exposure and DoS
});

module.exports = router;