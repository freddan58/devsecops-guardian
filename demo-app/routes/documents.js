// ============================================================
// VULNERABILITY #9: Path Traversal / Local File Inclusion (CWE-22)
// Attacker can read arbitrary files from the server filesystem
// ============================================================

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const DOCS_DIR = path.join(__dirname, '..', 'uploads', 'documents');

// Helper function to prevent path traversal by ensuring resolved path is within DOCS_DIR
function safeJoin(base, target) {
  const targetPath = path.resolve(base, target);
  if (!targetPath.startsWith(base + path.sep)) {
    // Path traversal attempt detected
    return null;
  }
  return targetPath;
}

// VULNERABLE: Path Traversal - user input used directly in file path
// GET /api/documents/download?file=../../../etc/passwd
router.get('/download', (req, res) => {
  const { file } = req.query;

  if (!file) {
    return res.status(400).json({ error: 'File parameter is required' });
  }

  // FIX: Use safeJoin to prevent path traversal by validating resolved path
  const filePath = safeJoin(DOCS_DIR, file);
  if (!filePath) {
    return res.status(400).json({ error: 'Invalid file path' });
  }

  try {
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Document not found' });
    }

    // Serves only files within DOCS_DIR
    res.sendFile(filePath);
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve document' });
  }
});

// GET /api/documents/preview - renders document content as HTML (also vulnerable to XSS)
router.get('/preview', (req, res) => {
  const { file } = req.query;

  if (!file) {
    return res.status(400).json({ error: 'File parameter is required' });
  }

  // FIX: Use safeJoin to prevent path traversal by validating resolved path
  const filePath = safeJoin(DOCS_DIR, file);
  if (!filePath) {
    return res.status(400).json({ error: 'Invalid file path' });
  }

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    // VULNERABLE: Rendering file content directly as HTML without sanitization
    res.send(`<html><body><pre>${content}</pre></body></html>`);
  } catch (err) {
    res.status(404).json({ error: 'Document not found' });
  }
});

module.exports = router;