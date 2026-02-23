// ============================================================
// VULNERABILITY #11: Prototype Pollution (CWE-1321)
// Attacker can inject properties into Object.prototype
// ============================================================

const express = require('express');
const router = express.Router();

// In-memory user preferences store
const userPreferences = {};

// VULNERABLE: Deep merge without prototype pollution protection
function deepMerge(target, source) {
  for (const key in source) {
    // FIXED: Prevent prototype pollution by disallowing __proto__, constructor, and prototype keys
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
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

// FIXED: Admin check no longer depends on polluted user property; use explicit header token for admin auth
// Also, sensitive secrets moved to environment variables
// GET /api/settings/admin/config
router.get('/admin/config', (req, res) => {
  // Simple token-based admin authentication
  const adminToken = req.headers['x-admin-token'];
  if (!adminToken || adminToken !== process.env.ADMIN_API_TOKEN) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  // Sensitive configuration loaded from environment variables, not hardcoded
  res.json({
    database: {
      host: process.env.DB_HOST || 'db-prod.internal',
      port: parseInt(process.env.DB_PORT, 10) || 5432,
      name: process.env.DB_NAME || 'banking_prod',
    },
    apiKeys: {
      stripe: process.env.STRIPE_SECRET_KEY || '',
      sendgrid: process.env.SENDGRID_API_KEY || '',
    },
    featureFlags: {
      maintenanceMode: process.env.MAINTENANCE_MODE === 'true',
      debugLogging: process.env.DEBUG_LOGGING === 'true',
    },
  });
});

module.exports = router;