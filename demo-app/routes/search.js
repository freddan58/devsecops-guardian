// ============================================================
// VULNERABILITY #2: Reflected XSS (CWE-79)
// User input reflected in response without sanitization
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');

// Utility function to escape HTML special characters for XSS prevention
function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// FIXED: Applied HTML escaping to user input 'q' before embedding in HTML to prevent XSS
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

    const safeQ = escapeHtml(q); // Escaped user input

    const html = `
      <html>
        <head><title>Search Results</title></head>
        <body>
          <h1>Search Results for: ${safeQ}</h1>
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