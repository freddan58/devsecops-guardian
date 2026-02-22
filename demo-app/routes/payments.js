// ============================================================
// VULNERABILITIES: Race Condition, Insufficient Input Validation,
//   Insecure Randomness, Cleartext Transmission of Sensitive Data
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');
const crypto = require('crypto');

// VULN #17: Race Condition / TOCTOU in Balance Check (CWE-367)
// Check-then-act pattern without locking allows double-spending
router.post('/send', authenticateToken, async (req, res) => {
  const { to_account, amount } = req.body;
  const from_user = req.user.id;

  try {
    const db = getDatabase();

    // Use a transaction to ensure atomicity and prevent race conditions
    const transaction = db.transaction(() => {
      // Step 1: Check available balance
      const sender = db.prepare('SELECT balance FROM accounts WHERE owner_id = ?').get(from_user);
      if (!sender || sender.balance < amount) {
        throw new Error('Insufficient funds');
      }

      // Step 2: Deduct funds from sender
      db.prepare('UPDATE accounts SET balance = balance - ? WHERE owner_id = ?').run(amount, from_user);

      // Step 3: Add funds to receiver
      db.prepare('UPDATE accounts SET balance = balance + ? WHERE account_number = ?').run(amount, to_account);
    });

    transaction();

    res.json({ message: 'Payment sent', amount, to: to_account });
  } catch (err) {
    if (err.message === 'Insufficient funds') {
      return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Payment failed', details: err.message });
  }
});

// VULN #18: Insecure Randomness for Transaction IDs (CWE-330)
// Math.random() is not cryptographically secure
router.post('/request', authenticateToken, (req, res) => {
  const { amount, description } = req.body;

  // Using Math.random() for security-sensitive transaction reference
  const transactionRef = 'TXN-' + Math.random().toString(36).substr(2, 9);
  const verificationCode = Math.floor(Math.random() * 9000) + 1000; // 4-digit PIN

  const db = getDatabase();
  db.prepare(
    'INSERT INTO transactions (reference, amount, description, verification_code, user_id) VALUES (?, ?, ?, ?, ?)'
  ).run(transactionRef, amount, description, verificationCode, req.user.id);

  // VULN #19: Sensitive data in URL / GET parameters (CWE-598)
  // Verification code sent in redirect URL (appears in logs, browser history, referrer headers)
  res.json({
    reference: transactionRef,
    verify_url: `/api/payments/verify?ref=${transactionRef}&code=${verificationCode}&amount=${amount}`,
    message: 'Complete payment by visiting the verify URL',
  });
});

// VULN #20: No input validation on amount (CWE-20)
// Negative amounts, zero, NaN, extremely large numbers all accepted
router.post('/withdraw', authenticateToken, (req, res) => {
  const { amount, account_number } = req.body;
  // No validation: amount could be negative (credit instead of debit),
  // NaN, Infinity, or extremely large

  const db = getDatabase();
  db.prepare('UPDATE accounts SET balance = balance - ? WHERE account_number = ?').run(amount, account_number);

  res.json({
    message: 'Withdrawal processed',
    amount: amount,
    account: account_number,
    timestamp: new Date().toISOString(),
  });
});

// VULN #21: Cleartext logging of financial transaction data (CWE-312)
router.post('/wire', authenticateToken, (req, res) => {
  const { routing_number, account_number, amount, swift_code, beneficiary_name } = req.body;

  // Logging full financial details including routing/account numbers in cleartext
  console.log(`[WIRE TRANSFER] User: ${req.user.username}, Routing: ${routing_number}, ` +
    `Account: ${account_number}, SWIFT: ${swift_code}, Amount: $${amount}, ` +
    `Beneficiary: ${beneficiary_name}, IP: ${req.ip}, ` +
    `Auth-Token: ${req.headers['authorization']}`);  // Also logs the JWT token!

  res.json({ message: 'Wire transfer initiated', reference: 'WIRE-' + Date.now() });
});

module.exports = router;