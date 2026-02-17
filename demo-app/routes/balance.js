// ============================================================
// FALSE POSITIVE #6: Parameterized SQL behind JWT auth (CWE-89)
// This looks like SQL injection but is actually SAFE because:
// 1. Endpoint is behind JWT authentication
// 2. Query uses parameterized prepared statement (?)
// 3. User ID comes from verified JWT token, not user input
// A context-aware scanner should mark this as FALSE POSITIVE
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');

// GET /api/balance - get balance for authenticated user (SAFE)
router.get('/', authenticateToken, (req, res) => {
  try {
    const db = getDatabase();

    // SAFE: Parameterized query with value from verified JWT token
    const accounts = db.prepare(
      'SELECT id, account_number, account_type, balance FROM accounts WHERE user_id = ?'
    ).all(req.user.id);

    const totalBalance = accounts.reduce((sum, acc) => sum + acc.balance, 0);

    res.json({
      user: req.user.username,
      total_balance: totalBalance,
      accounts: accounts
    });
  } catch (err) {
    res.status(500).json({ error: 'Balance query error', details: err.message });
  }
});

// GET /api/balance/history - get transaction history (SAFE)
router.get('/history', authenticateToken, (req, res) => {
  try {
    const db = getDatabase();

    // SAFE: Parameterized query with authenticated user ID
    const history = db.prepare(
      `SELECT t.id, t.amount, t.description, t.created_at,
              a1.account_number as from_account, 
              a2.account_number as to_account
       FROM transfers t
       JOIN accounts a1 ON t.from_account_id = a1.id
       JOIN accounts a2 ON t.to_account_id = a2.id
       WHERE t.user_id = ?
       ORDER BY t.created_at DESC
       LIMIT 50`
    ).all(req.user.id);

    res.json({ data: history });
  } catch (err) {
    res.status(500).json({ error: 'History query error', details: err.message });
  }
});

module.exports = router;
