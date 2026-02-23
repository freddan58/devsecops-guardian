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

// Helper: sanitize filename to prevent path traversal and allow only safe chars and extensions
function sanitizeFilename(filename) {
  // Remove any directory path (basename)
  const baseName = path.basename(filename);

  // Allow only alphanumeric, dash, underscore, dot
  // Replace other chars with underscore
  const safeName = baseName.replace(/[^a-zA-Z0-9._-]/g, '_');

  // Limit file name length
  return safeName.substring(0, 100);
}

// Helper: validate allowed extensions
const allowedExtensions = new Set(['.jpg', '.jpeg', '.png', '.gif']);

// Helper: max allowed upload size in bytes (5 MB)
const MAX_UPLOAD_SIZE = 5 * 1024 * 1024;

// VULN #22: Unrestricted File Upload (CWE-434) - FIXED
// Implemented strict filename sanitization, file type check, and size limit
// Store files in non-public directory to avoid direct web access
router.post('/avatar', authenticateToken, (req, res) => {
  const rawFilename = req.headers['x-filename'] || 'upload.bin';
  const sanitizedFilename = sanitizeFilename(rawFilename);
  const ext = path.extname(sanitizedFilename).toLowerCase();

  // Validate file extension
  if (!allowedExtensions.has(ext)) {
    return res.status(400).json({ error: 'Invalid file type' });
  }

  const uploadDir = path.join(__dirname, '..', 'uploads', 'avatars'); // outside 'public' directory

  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }

  const chunks = [];
  let uploadedSize = 0;

  req.on('data', chunk => {
    uploadedSize += chunk.length;
    if (uploadedSize > MAX_UPLOAD_SIZE) {
      // Abort connection to prevent large upload DoS
      req.destroy();
    } else {
      chunks.push(chunk);
    }
  });

  req.on('error', () => {
    return res.status(400).json({ error: 'Upload interrupted or failed' });
  });

  req.on('end', () => {
    if (uploadedSize > MAX_UPLOAD_SIZE) {
      // Request was aborted because file too big
      return; // Response was already terminated by destroy(); no response needed here
    }

    const buffer = Buffer.concat(chunks);

    const filePath = path.join(uploadDir, sanitizedFilename);

    // Write the file synchronously to avoid partial upload risks
    try {
      fs.writeFileSync(filePath, buffer, { flag: 'wx' }); // flag 'wx' to fail if file exists to avoid overwrite
    } catch (err) {
      return res.status(500).json({ error: 'File write failed' });
    }

    const mimeTypes = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif' };

    res.json({
      message: 'File uploaded',
      path: `/uploads/avatars/${sanitizedFilename}`, // Note: this path not served publicly directly
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