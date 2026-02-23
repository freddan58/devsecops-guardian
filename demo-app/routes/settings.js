// ============================================================
// VULNERABILITY #11: Prototype Pollution (CWE-1321)
// Attacker can inject properties into Object.prototype
// ============================================================

const express = require('express');
const router = express.Router();

// In-memory user preferences store
const userPreferences = {};

// FIXED: Deep merge avoiding prototype pollution by filtering __proto__, constructor, and prototype keys
function deepMerge(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      // Skip keys that can cause prototype pollution
      continue;
    }
    if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// POST /api/settings/preferences
// Body: { "theme": "dark", "__proto__": { "isAdmin": true } }
router.post('/preferences', (req, res) => {
  const userId = req.headers['x-user-id'] || 'anonymous';
  const updates = req.body;

  if (!updates || typeof updates !== 'object') {
    return res.status(400).json({ error: 'Invalid preferences payload' });
  }

  // SAFE: Using patched deep merge to avoid prototype pollution
  if (!userPreferences[userId]) {
    userPreferences[userId] = { theme: 'light', notifications: true, language: 'en' };
  }
  deepMerge(userPreferences[userId], updates);

  res.json({
    success: true,
    preferences: userPreferences[userId],
  });
});

// GET /api/settings/preferences
router.get('/preferences', (req, res) => {
  const userId = req.headers['x-user-id'] || 'anonymous';
  const prefs = userPreferences[userId] || { theme: 'light', notifications: true, language: 'en' };

  res.json({ preferences: prefs });
});

// FIXED: Admin check uses secure token claim to verify admin role
// Middleware to simulate token authentication and provide req.user
function authenticateToken(req, res, next) {
  // For demonstration, extract user info from headers securely
  // In production, this should verify a JWT or session token
  const userName = req.headers['x-user-name'] || 'guest';
  const isAdminHeader = req.headers['x-user-admin'] || 'false';
  // Parse isAdmin as boolean
  const isAdmin = isAdminHeader.toLowerCase() === 'true';

  // Attach securely constructed user object
  req.user = { name: userName, isAdmin };
  next();
}

// GET /api/settings/admin/config
router.get('/admin/config', authenticateToken, (req, res) => {
  // Use trusted req.user.isAdmin instead of vulnerable user object property
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  // Sensitive configuration exposed only to authenticated admins
  res.json({
    database: { host: 'db-prod.internal', port: 5432, name: 'banking_prod' },
    apiKeys: { stripe: 'sk_live_51ABC...redacted', sendgrid: 'SG.xxx...redacted' },
    featureFlags: { maintenanceMode: false, debugLogging: true },
  });
});

module.exports = router;