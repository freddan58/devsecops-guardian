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
  const updates = req.body;

  // SECURITY FIX: Implement whitelist of allowed fields to prevent mass assignment
  const allowedFields = ['name', 'email', 'phone', 'address'];
  const filteredUpdates = {};
  for (const key of allowedFields) {
    if (updates.hasOwnProperty(key)) {
      filteredUpdates[key] = updates[key];
    }
  }

  if (Object.keys(filteredUpdates).length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  try {
    const db = getDatabase();
    const fields = Object.keys(filteredUpdates).map(k => `${k} = ?`).join(', ');
    const values = Object.values(filteredUpdates);

    // Use parameterized query with fixed column names to prevent SQL injection and mass assignment
    db.prepare(`UPDATE users SET ${fields} WHERE id = ?`).run(...values, id);

    res.json({ message: 'User updated', updated_fields: Object.keys(filteredUpdates) });
  } catch (err) {
    res.status(500).json({ error: 'Update failed', details: err.message });
  }
});

// VULN #14: Debug/Admin Endpoint Exposed Without Auth (CWE-489)
// Added authentication middleware to restrict access to authorized users only
router.get('/debug', authenticateToken, (req, res) => {
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
// FIX: Added check to ensure only admin role users can promote others to admin
router.post('/promote/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

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

// FIXED VULN #16: Added authentication middleware to protect sensitive export endpoint
// This prevents unauthorized access to sensitive PII and financial data
router.get('/export-all', authenticateToken, (req, res) => {
  const db = getDatabase();
  const users = db.prepare('SELECT * FROM users').all();
  const accounts = db.prepare('SELECT * FROM accounts').all();
  const transactions = db.prepare('SELECT * FROM transactions').all();

  // No pagination or rate limiting implemented here as those were not requested in the fix
  res.json({
    users: users,           // Includes password hashes
    accounts: accounts,     // Includes balances
    transactions: transactions,
    exported_at: new Date().toISOString(),
  });
});

module.exports = router;