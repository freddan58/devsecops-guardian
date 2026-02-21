// ============================================================
// VULNERABILITY #10: Server-Side Request Forgery - SSRF (CWE-918)
// Attacker can make the server request internal/cloud metadata URLs
// ============================================================

const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const { URL } = require('url');

// Define an allowlist of trusted domains for SSRF protection
const ALLOWED_DOMAINS = [
  'example.com',
  'api.example.com',
  'hooks.example.com'
];

function isUrlAllowed(inputUrl) {
  try {
    const parsedUrl = new URL(inputUrl);
    // Only allow http or https protocols
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false;
    }
    // Check if hostname is in allowlist
    return ALLOWED_DOMAINS.some(domain => {
      // Exact match or subdomain match
      return parsedUrl.hostname === domain || parsedUrl.hostname.endsWith(`.${domain}`);
    });
  } catch (e) {
    return false;
  }
}

// POST /api/webhooks/test
// Body: { "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
router.post('/test', async (req, res) => {
  const { url, payload } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'Webhook URL is required' });
  }

  // FIXED: Validate URL against allowlist to prevent SSRF attacks
  if (!isUrlAllowed(url)) {
    return res.status(400).json({ error: 'URL is not allowed' });
  }

  try {
    const protocol = url.startsWith('https') ? https : http;

    const response = await new Promise((resolve, reject) => {
      const request = protocol.get(url, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', () => resolve({ status: resp.statusCode, body: data }));
      });
      request.on('error', reject);
      request.setTimeout(5000, () => { request.destroy(); reject(new Error('Timeout')); });
    });

    res.json({
      success: true,
      webhook_response: {
        status: response.status,
        body: response.body.substring(0, 1000),
      }
    });
  } catch (err) {
    res.status(502).json({
      success: false,
      error: `Webhook delivery failed: ${err.message}`
    });
  }
});

// GET /api/webhooks/preview?url=http://internal-service:8080/admin
router.get('/preview', (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter required' });
  }

  // FIXED: Validate URL against allowlist to prevent SSRF attacks
  if (!isUrlAllowed(url)) {
    return res.status(400).json({ error: 'URL is not allowed' });
  }

  const protocol = url.startsWith('https') ? https : http;

  protocol.get(url, (resp) => {
    let data = '';
    resp.on('data', chunk => data += chunk);
    resp.on('end', () => {
      // Extract title for "preview"
      const titleMatch = data.match(/<title>(.*?)<\/title>/i);
      res.json({
        url: url,
        title: titleMatch ? titleMatch[1] : 'No title',
        status: resp.statusCode,
        // FIXED: Removed leaking internal response headers to attacker
      });
    });
  }).on('error', (err) => {
    res.status(502).json({ error: err.message });
  });
});

module.exports = router;