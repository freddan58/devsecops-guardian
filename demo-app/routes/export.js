// ============================================================
// VULNERABILITY #12: Insecure Deserialization + Command Injection (CWE-502 / CWE-78)
// Attacker can execute arbitrary commands through unsafe eval/deserialization
// ============================================================

const express = require('express');
const router = express.Router();
const { execSync } = require('child_process');

// VULNERABLE: Using eval() for "flexible" query parsing
// POST /api/export/query
// Body: { "filter": "({amount: {$gt: 1000}})" }
// Exploit: { "filter": "(require('child_process').execSync('cat /etc/passwd').toString())" }
router.post('/query', (req, res) => {
  const { filter, format } = req.body;

  if (!filter) {
    return res.status(400).json({ error: 'Filter expression is required' });
  }

  try {
    // VULNERABLE: eval() on user input - Remote Code Execution
    // "We need eval for flexible query expressions" - famous last words
    const parsedFilter = eval(filter);

    // Simulate filtered data export
    const mockData = [
      { id: 1, account: 'ACC-001', amount: 5000, date: '2026-01-15' },
      { id: 2, account: 'ACC-002', amount: 12000, date: '2026-01-20' },
      { id: 3, account: 'ACC-003', amount: 800, date: '2026-02-01' },
    ];

    res.json({
      format: format || 'json',
      results: mockData,
      filter_applied: String(parsedFilter),
    });
  } catch (err) {
    res.status(400).json({ error: `Invalid filter expression: ${err.message}` });
  }
});

// FIXED: Removed command injection by avoiding shell command execution with user input
// Instead, simulate PDF generation logic safely without execSync
router.get('/pdf', (req, res) => {
  const { filename } = req.query;
  const reportName = filename || 'transaction-report';

  try {
    // SECURITY FIX: Avoided command injection by not using execSync with user input
    // Simulate PDF generation process safely
    const output = `Generating PDF: ${reportName}\n${new Date().toString()}`;

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