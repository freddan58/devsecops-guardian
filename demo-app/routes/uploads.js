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

// Helper function to sanitize filename and prevent path traversal
function sanitizeFilename(filename) {
  // Remove any path separators and allow only alphanumeric, dash, underscore and dot
  return filename.replace(/[^a-zA-Z0-9._-]/g, '_');
}

// Allowed file extensions for upload
const allowedExtensions = new Set(['.jpg', '.jpeg', '.png', '.gif']);

// Max file size in bytes (e.g., 5MB)
const MAX_FILE_SIZE = 5 * 1024 * 1024;

// VULN #22: Unrestricted File Upload (CWE-434)
// Fixed: sanitize filename to prevent path traversal, restrict allowed file types, impose size limit, store outside web root
router.post('/avatar', authenticateToken, (req, res) => {
  const rawFilename = req.headers['x-filename'] || 'upload.bin';
  const sanitizedFilename = sanitizeFilename(rawFilename);
  const ext = path.extname(sanitizedFilename).toLowerCase();

  // Validate file extension
  if (!allowedExtensions.has(ext)) {
    return res.status(400).json({ error: 'Invalid file type' });
  }

  // Store uploads outside web root for security
  const uploadDir = path.join(__dirname, '..', 'uploads');

  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }

  const chunks = [];
  let totalSize = 0;

  req.on('data', chunk => {
    totalSize += chunk.length;
    if (totalSize > MAX_FILE_SIZE) {
      // Abort request if file too large
      req.destroy();
    } else {
      chunks.push(chunk);
    }
  });

  req.on('end', () => {
    if (totalSize > MAX_FILE_SIZE) {
      return res.status(413).json({ error: 'File too large' });
    }

    const buffer = Buffer.concat(chunks);
    const filePath = path.join(uploadDir, sanitizedFilename);

    // Write file safely
    try {
      fs.writeFileSync(filePath, buffer);
    } catch (err) {
      return res.status(500).json({ error: 'Failed to save file' });
    }

    const mimeTypes = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif' };

    res.json({
      message: 'File uploaded',
      path: `/uploads/${sanitizedFilename}`,
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