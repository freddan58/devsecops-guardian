// ============================================================
// VULNERABILITY #11: Prototype Pollution (CWE-1321)
// Attacker can inject properties into Object.prototype
// ============================================================

const express = require('express');
const router = express.Router();

// In-memory user preferences store
const userPreferences = {};

// FIXED: Added checks to prevent prototype pollution by disallowing __proto__, constructor, and prototype keys
function deepMerge(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      // Skip dangerous keys to prevent prototype pollution
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

  // Using safe deep merge with prototype pollution protection
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

// VULNERABLE: Admin check relies on object property that can be polluted
// GET /api/settings/admin/config
router.get('/admin/config', (req, res) => {
  const user = { name: req.headers['x-user-name'] || 'guest' };

  // VULNERABLE: After prototype pollution, user.isAdmin will be true for ANY user
  if (!user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  // Sensitive configuration exposed after prototype pollution bypass
  res.json({
    database: { host: 'db-prod.internal', port: 5432, name: 'banking_prod' },
    apiKeys: { stripe: 'sk_live_51ABC...redacted', sendgrid: 'SG.xxx...redacted' },
    featureFlags: { maintenanceMode: false, debugLogging: true },
  });
});

module.exports = router;