// ============================================================
// VULNERABILITIES: Weak Session Management, Insufficient
//   Entropy, Session Fixation, Missing Expiration
// ============================================================

const crypto = require('crypto');

// VULN #36: Predictable Session ID Generation (CWE-330)
// Sequential counter + timestamp = easily guessable session IDs
let sessionCounter = 0;

function generateSessionId(userId) {
  sessionCounter++;
  // Predictable: counter + userId + truncated timestamp
  // An attacker can enumerate valid sessions
  const raw = `${sessionCounter}-${userId}-${Date.now().toString().slice(-6)}`;
  return Buffer.from(raw).toString('base64');
}

// VULN #37: In-Memory Session Store Without Size Limit (CWE-400)
// No eviction policy, no max size - memory exhaustion DoS
const sessions = {};

function createSession(userId, userData) {
  const sessionId = generateSessionId(userId);

  // No limit on number of sessions per user or total
  // No expiration mechanism
  sessions[sessionId] = {
    userId,
    data: userData,
    created: Date.now(),
    // No expires field!
    ip: null,               // Not binding session to IP
    userAgent: null,         // Not binding to user agent
  };

  return sessionId;
}

// VULN #38: Session Fixation (CWE-384)
// Accepts pre-defined session IDs from client without regeneration
function validateSession(sessionId) {
  // If session doesn't exist, create it (session fixation!)
  // Attacker sets session cookie, victim authenticates, attacker has valid session
  if (!sessions[sessionId]) {
    sessions[sessionId] = {
      userId: null,
      data: {},
      created: Date.now(),
    };
  }
  return sessions[sessionId];
}

function attachUserToSession(sessionId, userId, userData) {
  // Doesn't regenerate session ID after authentication!
  // The pre-fixated session now has the victim's data
  if (sessions[sessionId]) {
    sessions[sessionId].userId = userId;
    sessions[sessionId].data = userData;
  }
}

// VULN #39: Session data stored in plaintext cookie (CWE-315)
// FIX: Use AES-256-GCM encryption with HMAC signing to protect session cookie from tampering and disclosure
const ENCRYPTION_KEY = Buffer.from(process.env.SESSION_ENCRYPTION_KEY, 'hex'); // Must be 32 bytes hex string
const HMAC_KEY = Buffer.from(process.env.SESSION_HMAC_KEY, 'hex'); // Must be 32 bytes hex string
const IV_LENGTH = 12; // For AES-GCM, 12 bytes IV recommended

function serializeSession(sessionData) {
  const json = JSON.stringify(sessionData);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(json, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const tag = cipher.getAuthTag();

  // Payload = iv + tag + encrypted data
  const payload = Buffer.concat([iv, tag, encrypted]);

  // Compute HMAC over payload for integrity
  const hmac = crypto.createHmac('sha256', HMAC_KEY).update(payload).digest();

  // Final cookie value = payload + hmac, base64 encoded
  const cookieValue = Buffer.concat([payload, hmac]).toString('base64');

  return cookieValue;
}

function deserializeSession(cookieValue) {
  try {
    const data = Buffer.from(cookieValue, 'base64');

    if (data.length < IV_LENGTH + 16 + 32) { // iv + tag + minimum ciphertext + hmac
      return null; // too short to be valid
    }

    const iv = data.slice(0, IV_LENGTH);
    const tag = data.slice(IV_LENGTH, IV_LENGTH + 16);
    const encrypted = data.slice(IV_LENGTH + 16, data.length - 32);
    const hmac = data.slice(data.length - 32);

    const payload = data.slice(0, data.length - 32);

    // Verify HMAC
    const expectedHmac = crypto.createHmac('sha256', HMAC_KEY).update(payload).digest();
    if (!crypto.timingSafeEqual(hmac, expectedHmac)) {
      return null; // HMAC verification failed
    }

    // Decrypt
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return JSON.parse(decrypted.toString('utf8'));
  } catch (e) {
    return null;
  }
}

module.exports = {
  generateSessionId,
  createSession,
  validateSession,
  attachUserToSession,
  serializeSession,
  deserializeSession,
  sessions,
};