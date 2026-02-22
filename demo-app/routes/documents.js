// ============================================================
// VULNERABILITY #9: Path Traversal / Local File Inclusion (CWE-22)
// Attacker can read arbitrary files from the server filesystem
// ============================================================

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const DOCS_DIR = path.join(__dirname, '..', 'uploads', 'documents');

// Helper function to validate and sanitize file parameter to prevent path traversal
function sanitizeFileName(fileName) {
  // Disallow absolute paths and path traversal sequences
  if (fileName.includes('..') || path.isAbsolute(fileName)) {
    return null;
  }

  // Normalize the path and ensure it stays within DOCS_DIR
  const normalizedPath = path.normalize(path.join(DOCS_DIR, fileName));
  if (!normalizedPath.startsWith(DOCS_DIR + path.sep)) {
    return null;
  }

  return normalizedPath;
}

// GET /api/documents/download?file=filename
router.get('/download', (req, res) => {
  const { file } = req.query;

  if (!file) {
    return res.status(400).json({ error: 'File parameter is required' });
  }

  // FIX: Sanitize and validate file parameter to prevent path traversal
  const filePath = sanitizeFileName(file);
  if (!filePath) {
    return res.status(400).json({ error: 'Invalid file parameter' });
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

  const filePath = path.join(DOCS_DIR, file);

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    // VULNERABLE: Rendering file content directly as HTML without sanitization
    res.send(`<html><body><pre>${content}</pre></body></html>`);
  } catch (err) {
    res.status(404).json({ error: 'Document not found' });
  }
});

module.exports = router;