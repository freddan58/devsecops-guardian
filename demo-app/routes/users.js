// ============================================================
// VULNERABILITY #4: Missing Auth Check (CWE-862)
// Destructive endpoint without authentication middleware
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { authenticateToken, generateToken } = require('../middleware/auth');
const { hashPassword, comparePassword } = require('../utils/auth');

// POST /api/users/login - authenticate user
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const db = getDatabase();
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await comparePassword(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(user);
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Login error', details: err.message });
  }
});

// GET /api/users/profile - get current user (protected)
router.get('/profile', authenticateToken, (req, res) => {
  const db = getDatabase();
  const user = db.prepare(
    'SELECT id, username, email, role, created_at FROM users WHERE id = ?'
  ).get(req.user.id);
  res.json({ data: user });
});

// VULNERABLE: DELETE without authentication middleware!
// Any unauthenticated user can delete any user account
// Should have: router.delete('/:id', authenticateToken, ...)
router.delete('/:id', (req, res) => {
  const { id } = req.params;

  try {
    const db = getDatabase();
    const result = db.prepare('DELETE FROM users WHERE id = ?').run(id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: `User ${id} deleted successfully` });
  } catch (err) {
    res.status(500).json({ error: 'Delete error', details: err.message });
  }
});

module.exports = router;
