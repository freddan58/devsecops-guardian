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
