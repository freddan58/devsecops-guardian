// ============================================================
// VULNERABILITY #2: Reflected XSS (CWE-79)
// User input reflected in response without sanitization
// ============================================================

const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');

// Helper function to escape HTML special characters to prevent XSS
function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// FIXED: Escape user input before reflecting in HTML to prevent XSS
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

    const safeQuery = escapeHtml(q); // Escape user input to prevent reflected XSS

    const html = `
      <html>
        <head><title>Search Results</title></head>
        <body>
          <h1>Search Results for: ${safeQuery}</h1>
          <p>Found ${results.length} results</p>
          <ul>
            ${results.map(r => `<li>${escapeHtml(r.owner_name)} - ${escapeHtml(r.account_type)}</li>`).join('')}
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