// ============================================================
// VULNERABILITY #9: Path Traversal / Local File Inclusion (CWE-22)
// Attacker can read arbitrary files from the server filesystem
// ============================================================

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const DOCS_DIR = path.join(__dirname, '..', 'uploads', 'documents');

// Utility function to validate filename - allow only alphanumeric, dash, underscore, and dot, no path separators
function isValidFilename(filename) {
  // Disallow path separators to prevent path traversal
  if (filename.includes('/') || filename.includes('\\')) {
    return false;
  }
  // Basic whitelist: letters, numbers, underscores, hyphens, dots
  return /^[a-zA-Z0-9._-]+$/.test(filename);
}

// FIXED: Validate and sanitize 'file' query parameter to prevent path traversal attacks
// GET /api/documents/download?file=filename
router.get('/download', (req, res) => {
  const { file } = req.query;

  if (!file) {
    return res.status(400).json({ error: 'File parameter is required' });
  }

  if (!isValidFilename(file)) {
    // Reject invalid filenames to prevent path traversal
    return res.status(400).json({ error: 'Invalid file name' });
  }

  const filePath = path.join(DOCS_DIR, file);

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
// Fixed stored XSS by escaping HTML special characters to prevent script injection
router.get('/preview', (req, res) => {
  const { file } = req.query;

  if (!file) {
    return res.status(400).json({ error: 'File parameter is required' });
  }

  // Apply same filename validation here (fix not requested, so no change)
  const filePath = path.join(DOCS_DIR, file);

  // Helper function to escape HTML special chars to prevent XSS
  function escapeHtml(unsafe) {
    return unsafe
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const safeContent = escapeHtml(content);
    res.send(`<html><body><pre>${safeContent}</pre></body></html>`);
  } catch (err) {
    res.status(404).json({ error: 'Document not found' });
  }
});

module.exports = router;