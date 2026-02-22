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
function isPathInsideBaseDir(baseDir, targetPath) {
  const relative = path.relative(baseDir, targetPath);
  return !!relative && !relative.startsWith('..') && !path.isAbsolute(relative);
}

// GET /api/documents/download?file=...
router.get('/download', (req, res) => {
  const { file } = req.query;

  if (!file) {
    return res.status(400).json({ error: 'File parameter is required' });
  }

  // Resolve the absolute path of the requested file
  const filePath = path.resolve(DOCS_DIR, file);

  // SECURITY FIX: Validate that resolved filePath is inside DOCS_DIR to prevent path traversal
  if (!isPathInsideBaseDir(DOCS_DIR, filePath)) {
    return res.status(400).json({ error: 'Invalid file path' });
  }

  try {
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Document not found' });
    }

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

  const filePath = path.resolve(DOCS_DIR, file);

  // SECURITY FIX: Validate that resolved filePath is inside DOCS_DIR to prevent path traversal
  if (!isPathInsideBaseDir(DOCS_DIR, filePath)) {
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