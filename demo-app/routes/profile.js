// ============================================================
// VULNERABILITIES #43-47: User Profile Management
//   #43 Horizontal IDOR - Access any user's profile (CWE-639)
//   #44 Weak Password Hashing - MD5 without salt (CWE-916)
//   #45 Mass Data Exposure - Returns sensitive fields (CWE-200)
//   #46 NoSQL Injection via JSON query (CWE-943)
//   #47 Unsafe Eval in template rendering (CWE-95)
// ============================================================

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { getDatabase } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const { Parser } = require('expr-eval');

// VULN #43: Horizontal IDOR - No ownership check (CWE-639)
// Any authenticated user can view ANY other user's full profile
// by changing the :id parameter. No authorization check that
// req.user.id matches the requested profile ID.
router.get('/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  try {
    const db = getDatabase();
    // VULNERABLE: No check that req.user.id === id
    // Any logged-in user can access any profile
    const user = db.prepare(
      'SELECT id, username, email, role, ssn, date_of_birth, phone, address, salary, bank_account FROM users WHERE id = ?'
    ).get(id);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // VULN #45: Mass Data Exposure (CWE-200)
    // Returns SSN, salary, bank account - far more than needed
    // Should only return id, username, email for non-owner requests
    res.json({ profile: user });
  } catch (err) {
    res.status(500).json({ error: 'Profile fetch failed', details: err.message });
  }
});

// VULN #44: Weak Password Hashing - MD5 without salt (CWE-916)
// MD5 is cryptographically broken and should never be used for passwords.
// No salt means identical passwords produce identical hashes (rainbow tables).
router.post('/change-password', authenticateToken, (req, res) => {
  const { current_password, new_password } = req.body;

  try {
    const db = getDatabase();
    const user = db.prepare('SELECT id, password_hash FROM users WHERE id = ?').get(req.user.id);

    // VULNERABLE: MD5 is broken for password hashing
    const currentHash = crypto.createHash('md5').update(current_password).digest('hex');

    if (currentHash !== user.password_hash) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // VULNERABLE: Still using MD5 for the new password, no salt
    const newHash = crypto.createHash('md5').update(new_password).digest('hex');
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, req.user.id);

    // VULNERABLE: Returns the hash in the response
    res.json({
      message: 'Password updated successfully',
      password_hash: newHash,
      algorithm: 'md5',
    });
  } catch (err) {
    res.status(500).json({ error: 'Password change failed' });
  }
});

// VULN #46: NoSQL-style Injection via JSON query operators (CWE-943)
// Accepts arbitrary MongoDB-style query operators in the search body,
// allowing attackers to bypass filters or extract data they shouldn't access
router.post('/search', (req, res) => {
  const { filter } = req.body;

  if (!filter || typeof filter !== 'object') {
    return res.status(400).json({ error: 'Filter object required' });
  }

  try {
    const db = getDatabase();

    // VULNERABLE: Dynamically builds WHERE clause from user-controlled JSON
    // Attacker can send: { "filter": { "role": "admin", "1=1 OR username": "anything" } }
    const conditions = Object.entries(filter)
      .map(([key, value]) => `${key} = '${value}'`)  // SQL injection via key AND value
      .join(' AND ');

    const query = `SELECT id, username, email, role FROM users WHERE ${conditions}`;
    const users = db.prepare(query).all();

    res.json({ results: users, query_used: query });  // Also leaks the query
  } catch (err) {
    res.status(500).json({ error: 'Search failed', details: err.message });
  }
});

// VULN #47: Unsafe eval() for dynamic field computation (CWE-95)
// User-controlled expression is passed directly to eval()
// Attacker can execute arbitrary JavaScript on the server
router.post('/calculate-bonus', authenticateToken, (req, res) => {
  const { formula, base_salary } = req.body;

  try {
    const salary = Number(base_salary) || 0;
    // FIX: Use safe expression parser to evaluate formula
    // Prevents arbitrary code execution by disallowing unsafe functions
    const parser = new Parser();
    const expr = parser.parse(formula);
    const result = expr.evaluate({ salary });

    res.json({
      base_salary: salary,
      formula: formula,
      bonus: result,
      total_compensation: salary + (Number(result) || 0),
    });
  } catch (err) {
    res.status(400).json({ error: 'Formula evaluation failed', details: err.message });
  }
});

module.exports = router;