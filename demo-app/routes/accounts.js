// ============================================================
// VULNERABILITY #1: SQL Injection (CWE-89)
// Public endpoint with unsanitized user input in SQL query
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');

// FIXED: Use parameterized query to prevent SQL Injection
// GET /api/accounts?id=1 OR 1=1 attack prevented by parameterization
router.get('/', (req, res) => {
  const { id } = req.query;
  
  if (!id) {
    return res.status(400).json({ error: 'Account ID is required' });
  }

  try {
    const db = getDatabase();
    
    // Secure parameterized query to prevent SQL Injection
    const query = 'SELECT id, account_number, owner_name, balance, account_type FROM accounts WHERE id = ?';
    const accounts = db.prepare(query).all(id);
    
    if (accounts.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }

    res.json({ data: accounts });
  } catch (err) {
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

// GET /api/accounts/summary - list all accounts (public, no auth)
router.get('/summary', (req, res) => {
  try {
    const db = getDatabase();
    const accounts = db.prepare(
      'SELECT id, account_number, owner_name, account_type FROM accounts'
    ).all();
    res.json({ data: accounts });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

module.exports = router;