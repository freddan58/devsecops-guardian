// ============================================================
// VULNERABILITY #5: IDOR - Insecure Direct Object Reference (CWE-639)
// Authenticated user can access any transfer, not just their own
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');

// POST /api/transfers - create a new transfer (protected)
router.post('/', authenticateToken, (req, res) => {
  const { from_account_id, to_account_id, amount, description } = req.body;

  if (!from_account_id || !to_account_id || !amount) {
    return res.status(400).json({ error: 'from_account_id, to_account_id, and amount required' });
  }

  if (amount <= 0) {
    return res.status(400).json({ error: 'Amount must be positive' });
  }

  try {
    const db = getDatabase();

    // Verify source account belongs to user
    const sourceAccount = db.prepare(
      'SELECT * FROM accounts WHERE id = ? AND user_id = ?'
    ).get(from_account_id, req.user.id);

    if (!sourceAccount) {
      return res.status(403).json({ error: 'Source account not found or unauthorized' });
    }

    if (sourceAccount.balance < amount) {
      return res.status(400).json({ error: 'Insufficient funds' });
    }

    // Execute transfer in transaction
    const transfer = db.transaction(() => {
      db.prepare('UPDATE accounts SET balance = balance - ? WHERE id = ?')
        .run(amount, from_account_id);
      db.prepare('UPDATE accounts SET balance = balance + ? WHERE id = ?')
        .run(amount, to_account_id);
      
      const result = db.prepare(
        `INSERT INTO transfers (from_account_id, to_account_id, amount, description, user_id)
         VALUES (?, ?, ?, ?, ?)`
      ).run(from_account_id, to_account_id, amount, description || '', req.user.id);

      return result;
    })();

    res.status(201).json({ 
      message: 'Transfer completed', 
      transfer_id: transfer.lastInsertRowid 
    });
  } catch (err) {
    res.status(500).json({ error: 'Transfer error', details: err.message });
  }
});

// VULNERABLE: IDOR - No ownership check!
// Any authenticated user can view ANY transfer by ID
// Should verify: transfer.user_id === req.user.id
router.get('/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  try {
    const db = getDatabase();
    
    // VULNERABLE: Only checks if transfer exists, NOT if it belongs to the user
    const transfer = db.prepare(
      `SELECT t.*, a1.account_number as from_account, a2.account_number as to_account
       FROM transfers t
       JOIN accounts a1 ON t.from_account_id = a1.id
       JOIN accounts a2 ON t.to_account_id = a2.id
       WHERE t.id = ?`
    ).get(id);

    if (!transfer) {
      return res.status(404).json({ error: 'Transfer not found' });
    }

    // Missing: if (transfer.user_id !== req.user.id) return 403
    res.json({ data: transfer });
  } catch (err) {
    res.status(500).json({ error: 'Query error', details: err.message });
  }
});

module.exports = router;
