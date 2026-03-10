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

  // Secure random transaction reference using crypto.randomBytes - fixes CWE-330
  const transactionRef = 'TXN-' + crypto.randomBytes(6).toString('hex');

  // Secure 4-digit verification code generation using crypto.randomInt
  const verificationCode = crypto.randomInt(1000, 10000); // 4-digit PIN

  const db = getDatabase();
  db.prepare(
    'INSERT INTO transactions (reference, amount, description, verification_code, user_id) VALUES (?, ?, ?, ?, ?)'
  ).run(transactionRef, amount, description, verificationCode, req.user.id);

  // FIX: Do NOT send sensitive verification codes in URL params to prevent exposure in logs and browser history
  // Instead, send verificationCode and transactionRef securely in response body without embedding in a URL
  res.json({
    reference: transactionRef,
    verification_code: verificationCode, // Sending code in response body securely
    message: 'Complete payment by submitting verification code via POST to /api/payments/verify',
  });
});

// VULN #20: No input validation on amount (CWE-20)
// Fixed: Added strict validation to only allow positive numbers up to a maximum limit
router.post('/withdraw', authenticateToken, (req, res) => {
  const { amount, account_number } = req.body;

  // Validate 'amount' to ensure it is a positive number and within allowed limit
  const maxAmount = 1000000; // Maximum withdrawal limit for example
  if (
    typeof amount !== 'number' ||
    !Number.isFinite(amount) ||
    amount <= 0 ||
    amount > maxAmount
  ) {
    return res.status(400).json({ error: 'Invalid withdrawal amount' });
  }

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

  // Fixed: Removed logging of sensitive PII and authentication tokens to prevent data exposure in logs
  console.log(`[WIRE TRANSFER] User: ${req.user.username}, Amount: $${amount}, IP: ${req.ip}`);

  res.json({ message: 'Wire transfer initiated', reference: 'WIRE-' + Date.now() });
});

module.exports = router;