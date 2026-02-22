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

// FIXED VULN #38: Session Fixation (CWE-384)
// Always create a new session; do NOT accept client-supplied session IDs to prevent fixation
function validateSession(sessionId) {
  // Do not accept pre-existing sessionId from client to avoid session fixation
  // If sessionId exists and logged in session, return it
  if (sessionId && sessions[sessionId] && sessions[sessionId].userId !== null) {
    return sessions[sessionId];
  }
  // Otherwise, create a new unauthenticated session with a secure random session ID
  const newSessionId = crypto.randomBytes(32).toString('hex'); // cryptographically strong ID
  sessions[newSessionId] = {
    userId: null,
    data: {},
    created: Date.now(),
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
function serializeSession(sessionData) {
  // Storing session data directly in cookie without encryption or signing
  // Attacker can decode base64, modify role to "admin", re-encode
  return Buffer.from(JSON.stringify(sessionData)).toString('base64');
}

function deserializeSession(cookieValue) {
  try {
    return JSON.parse(Buffer.from(cookieValue, 'base64').toString());
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