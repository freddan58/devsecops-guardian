// ============================================================
// FALSE POSITIVE #7: Weak Crypto - bcrypt (CWE-328)
// bcrypt IS acceptable for password hashing
// A naive scanner might flag this as "weak crypto" but bcrypt
// with cost factor 10+ is industry standard and secure.
// ============================================================

const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 10;

async function hashPassword(plainPassword) {
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  return bcrypt.hash(plainPassword, salt);
}

async function comparePassword(plainPassword, hashedPassword) {
  return bcrypt.compare(plainPassword, hashedPassword);
}

module.exports = { hashPassword, comparePassword };
