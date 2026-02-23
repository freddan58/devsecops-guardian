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

    // FIX: Validate keys against a whitelist and use parameterized queries to prevent SQL injection
    const allowedKeys = new Set(['id', 'username', 'email', 'role']);
    const conditions = [];
    const values = [];

    for (const [key, value] of Object.entries(filter)) {
      if (!allowedKeys.has(key)) {
        return res.status(400).json({ error: `Invalid filter key: ${key}` });
      }
      conditions.push(`${key} = ?`);
      values.push(value);
    }

    const whereClause = conditions.length > 0 ? conditions.join(' AND ') : '1=1';
    const query = `SELECT id, username, email, role FROM users WHERE ${whereClause}`;
    const users = db.prepare(query).all(...values);

    res.json({ results: users });  // Removed query leak to prevent info disclosure
  } catch (err) {
    res.status(500).json({ error: 'Search failed', details: err.message });
  }
});

// VULN #47: Unsafe eval() for dynamic field computation (CWE-95)
// User-controlled expression is passed directly to eval()
// Attacker can execute arbitrary JavaScript on the server
router.post('/calculate-bonus', authenticateToken, (req, res) => {
  const { formula, base_salary } = req.body;

  // VULNERABLE: eval() executes arbitrary JavaScript from user input
  // Attacker can send: { "formula": "process.exit(1)", "base_salary": 50000 }
  // Or: { "formula": "require('child_process').execSync('cat /etc/passwd').toString()" }
  try {
    const salary = Number(base_salary) || 0;
    const result = eval(`(function() { const salary = ${salary}; return ${formula}; })()`);

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