// ============================================================
// VULNERABILITIES: Unrestricted File Upload, XML External Entity,
//   Insecure Deserialization, Open Redirect
// ============================================================

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { authenticateToken } = require('../middleware/auth');
const { execSync } = require('child_process');

// VULN #22: Unrestricted File Upload (CWE-434)
// No file type validation, no size limit, uploads to web-accessible directory
router.post('/avatar', authenticateToken, (req, res) => {
  const filename = req.headers['x-filename'] || 'upload.bin';
  const uploadDir = path.join(__dirname, '..', 'public', 'uploads');

  // No sanitization of filename - allows path traversal in filename
  // No file type checking - could upload .js, .php, .exe
  // No file size limit - DoS via large uploads
  const filePath = path.join(uploadDir, filename);

  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }

  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const buffer = Buffer.concat(chunks);
    fs.writeFileSync(filePath, buffer);

    // VULN #23: Using file extension to determine MIME type (CWE-436)
    // Trusting user-controlled filename extension for content type detection
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes = { '.jpg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif' };

    res.json({
      message: 'File uploaded',
      path: `/uploads/${filename}`,
      size: buffer.length,
      type: mimeTypes[ext] || 'application/octet-stream',
    });
  });
});

// VULN #24: XML External Entity Injection (CWE-611)
// Parses XML without disabling external entity resolution
router.post('/import-xml', authenticateToken, (req, res) => {
  const xmlData = req.body.xml;

  // FIX: Disable external entity resolution by not processing external entities manually
  // and by not reading files based on XML entities to prevent XXE attacks
  try {
    // Extract <name> and <amount> tags safely without resolving external entities
    const nameMatch = xmlData.match(/<name>(.*?)<\/name>/);
    const amountMatch = xmlData.match(/<amount>(.*?)<\/amount>/);

    // Remove any DOCTYPE declarations to prevent external entity definitions
    const sanitizedXml = xmlData.replace(/<!DOCTYPE[^>]*>/g, '');

    // Do not process external entities manually
    const processed = sanitizedXml;

    res.json({
      parsed: { name: nameMatch?.[1], amount: amountMatch?.[1] },
      raw_processed: processed,
    });
  } catch (err) {
    res.status(400).json({ error: 'XML parsing failed', details: err.message });
  }
});

// VULN #25: Open Redirect (CWE-601)
// Redirects to user-controlled URL without validation
router.get('/callback', (req, res) => {
  const { redirect_url } = req.query;

  // No validation of redirect target
  // Attacker: /api/uploads/callback?redirect_url=https://evil.com/phishing
  if (redirect_url) {
    res.redirect(redirect_url);
  } else {
    res.redirect('/');
  }
});

// VULN #26: Shell Injection via filename in image processing (CWE-78)
// Passes user-controlled filename to shell command
router.post('/resize', authenticateToken, (req, res) => {
  const { filename, width, height } = req.body;

  try {
    // User-controlled filename passed directly to shell command
    // Attacker can inject: filename = "image.png; rm -rf / #"
    const cmd = `convert public/uploads/${filename} -resize ${width}x${height} public/uploads/resized_${filename}`;
    execSync(cmd);

    res.json({ message: 'Image resized', output: `resized_${filename}` });
  } catch (err) {
    res.status(500).json({ error: 'Resize failed', details: err.message });
  }
});

module.exports = router;