// ============================================================
// VULNERABILITY #1: SQL Injection (CWE-89)
// Public endpoint with unsanitized user input in SQL query
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');

// VULNERABLE: SQL Injection - user input concatenated directly into query
// GET /api/accounts?id=1 OR 1=1
router.get('/', (req, res) => {
  const { id } = req.query;
  
  if (!id) {
    return res.status(400).json({ error: 'Account ID is required' });
  }

  try {
    const db = getDatabase();
    
    // VULNERABLE: String concatenation in SQL query
    // An attacker can inject: ?id=1 OR 1=1 -- to dump all accounts
    const query = `SELECT id, account_number, owner_name, balance, account_type 
                   FROM accounts WHERE id = ${id}`;
    
    const accounts = db.prepare(query).all();
    
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
