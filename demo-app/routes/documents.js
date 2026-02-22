// ============================================================
// VULNERABILITY #9: Path Traversal / Local File Inclusion (CWE-22)
// Attacker can read arbitrary files from the server filesystem
// ============================================================

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const DOCS_DIR = path.join(__dirname, '..', 'uploads', 'documents');

// Helper function to validate and sanitize file parameter
function isValidFile(file) {
  // Reject if file contains path traversal sequences or is absolute path
  if (!file || typeof file !== 'string') return false;
  if (file.includes('..') || path.isAbsolute(file)) return false;
  // Allow only filenames with safe characters (alphanumeric, dash, underscore, dot)
  // This whitelist prevents directory traversal and unexpected characters
  const safeFileNameRegex = /^[a-zA-Z0-9._-]+$/;
  return safeFileNameRegex.test(file);
}

// GET /api/documents/download?file=filename
router.get('/download', (req, res) => {
  const { file } = req.query;

  if (!file) {
    return res.status(400).json({ error: 'File parameter is required' });
  }

  if (!isValidFile(file)) {
    // Security fix: Validate and sanitize 'file' parameter to prevent path traversal
    return res.status(400).json({ error: 'Invalid file parameter' });
  }

  const filePath = path.join(DOCS_DIR, file);

  // Security fix: Ensure resolved path is within DOCS_DIR to prevent path traversal
  const resolvedPath = path.resolve(filePath);
  if (!resolvedPath.startsWith(path.resolve(DOCS_DIR) + path.sep)) {
    return res.status(400).json({ error: 'Invalid file parameter' });
  }

  try {
    if (!fs.existsSync(resolvedPath)) {
      return res.status(404).json({ error: 'Document not found' });
    }

    res.sendFile(resolvedPath);
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

  if (!isValidFile(file)) {
    // Security fix: Validate and sanitize 'file' parameter to prevent path traversal
    return res.status(400).json({ error: 'Invalid file parameter' });
  }

  const filePath = path.join(DOCS_DIR, file);
  const resolvedPath = path.resolve(filePath);
  if (!resolvedPath.startsWith(path.resolve(DOCS_DIR) + path.sep)) {
    return res.status(400).json({ error: 'Invalid file parameter' });
  }

  try {
    const content = fs.readFileSync(resolvedPath, 'utf-8');
    // VULNERABLE: Rendering file content directly as HTML without sanitization
    res.send(`<html><body><pre>${content}</pre></body></html>`);
  } catch (err) {
    res.status(404).json({ error: 'Document not found' });
  }
});

module.exports = router;