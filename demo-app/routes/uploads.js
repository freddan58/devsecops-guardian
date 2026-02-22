// ============================================================
// VULNERABILITIES: Unrestricted File Upload, XML External Entity,
//   Insecure Deserialization, Open Redirect
// ============================================================

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { authenticateToken } = require('../middleware/auth');
const { execSync, spawnSync } = require('child_process');

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

  // Directly passes user XML to parser without sanitization
  // An attacker can inject: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  try {
    // Using regex to extract data - but the XML is still processed unsafely
    // The real vulnerability is that we'd pass this to an XML parser
    const nameMatch = xmlData.match(/<name>(.*?)<\/name>/);
    const amountMatch = xmlData.match(/<amount>(.*?)<\/amount>/);

    // Simulating XML parser that resolves entities
    let processed = xmlData;
    const entityMatch = xmlData.match(/<!ENTITY\s+(\w+)\s+SYSTEM\s+"(.+?)">/);
    if (entityMatch) {
      const entityName = entityMatch[1];
      const entityPath = entityMatch[2];
      // DANGEROUS: Reading file system based on XML entity
      try {
        const content = fs.readFileSync(entityPath, 'utf-8');
        processed = processed.replace(new RegExp(`&${entityName};`, 'g'), content);
      } catch (e) { /* file not found */ }
    }

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
    // FIX: Avoid command injection by using spawnSync with argument array instead of execSync with concatenated string
    // Also sanitize filename to basename to prevent path traversal
    const safeFilename = path.basename(filename);
    const inputPath = path.join('public', 'uploads', safeFilename);
    const outputPath = path.join('public', 'uploads', `resized_${safeFilename}`);

    // Validate width and height are positive integers
    const w = parseInt(width, 10);
    const h = parseInt(height, 10);
    if (isNaN(w) || isNaN(h) || w <= 0 || h <= 0) {
      return res.status(400).json({ error: 'Invalid width or height parameters' });
    }

    const args = [inputPath, '-resize', `${w}x${h}`, outputPath];

    const result = spawnSync('convert', args, { encoding: 'utf-8' });
    if (result.error) {
      throw result.error;
    }
    if (result.status !== 0) {
      throw new Error(result.stderr);
    }

    res.json({ message: 'Image resized', output: `resized_${safeFilename}` });
  } catch (err) {
    res.status(500).json({ error: 'Resize failed', details: err.message });
  }
});

module.exports = router;