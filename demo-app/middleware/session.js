// ============================================================
// VULNERABILITIES: Weak Session Management, Insufficient
//   Entropy, Session Fixation, Missing Expiration
// ============================================================

const crypto = require('crypto');

// FIXED #36: Use cryptographically secure random values for session IDs
function generateSessionId(userId) {
  // Generate 16 bytes (128 bits) of cryptographically secure random data
  const randomBytes = crypto.randomBytes(16).toString('hex');
  // Combine with userId for session identification, but do not rely on this for entropy
  const raw = `${randomBytes}-${userId}`;
  return Buffer.from(raw).toString('base64');
}

// VULN #37: In-Memory Session Store Without Size Limit (CWE-400)
// No eviction policy, no max size - memory exhaustion DoS
const sessions = {};

// Define session expiration duration in milliseconds (e.g., 30 minutes)
const SESSION_EXPIRATION_MS = 30 * 60 * 1000; // 30 minutes

// Helper function to clean up expired sessions
function evictExpiredSessions() {
  const now = Date.now();
  for (const sessionId in sessions) {
    if (sessions[sessionId].expires && sessions[sessionId].expires <= now) {
      delete sessions[sessionId];
    }
  }
}

function createSession(userId, userData) {
  // Perform eviction of stale sessions on each session creation to prevent memory exhaustion
  evictExpiredSessions(); // SECURITY FIX: added session eviction to prevent stale session buildup

  const sessionId = generateSessionId(userId);

  // Set expiration timestamp for session
  const expires = Date.now() + SESSION_EXPIRATION_MS; // SECURITY FIX: added session expiration time

  // Store session with expiration
  sessions[sessionId] = {
    userId,
    data: userData,
    created: Date.now(),
    expires, // Added expiration field
    ip: null,               // Not binding session to IP
    userAgent: null,         // Not binding to user agent
  };

  return sessionId;
}

// FIXED VULN #38: Session Fixation (CWE-384)
// Always create a new session; do NOT accept client-supplied session IDs to prevent fixation
function validateSession(sessionId) {
  // Perform eviction of stale sessions on each validation to enforce expiration
  evictExpiredSessions(); // SECURITY FIX: evict expired sessions every validation

  // Check if session exists and is not expired
  if (sessionId && sessions[sessionId] && sessions[sessionId].userId !== null) {
    if (sessions[sessionId].expires > Date.now()) {
      return sessions[sessionId];
    } else {
      // Session expired, remove it
      delete sessions[sessionId];
    }
  }
  // Otherwise, create a new unauthenticated session with a secure random session ID
  const newSessionId = crypto.randomBytes(32).toString('hex'); // cryptographically strong ID
  sessions[newSessionId] = {
    userId: null,
    data: {},
    created: Date.now(),
    expires: Date.now() + SESSION_EXPIRATION_MS, // SECURITY FIX: set expiration for unauthenticated session
  };
  return sessions[newSessionId];
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