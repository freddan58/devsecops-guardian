// ============================================================
// VULNERABILITY #10: Server-Side Request Forgery - SSRF (CWE-918)
// Attacker can make the server request internal/cloud metadata URLs
// ============================================================

const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const urlModule = require('url');

// VULNERABLE: SSRF - user-supplied URL is fetched by the server
// POST /api/webhooks/test
// Body: { "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
router.post('/test', async (req, res) => {
  const { url, payload } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'Webhook URL is required' });
  }

  // VULNERABLE: No URL validation - attacker can target internal services
  // Can access cloud metadata: http://169.254.169.254/latest/meta-data/
  // Can scan internal network: http://10.0.0.1:8080/admin
  // Can access localhost services: http://127.0.0.1:6379/ (Redis)
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

    // VULNERABLE: Returning internal service response to the attacker
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

// FIXED: Added URL validation to restrict to trusted domains and removed leaking internal headers
// GET /api/webhooks/preview?url=http://internal-service:8080/admin
router.get('/preview', (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter required' });
  }

  // Parse and validate URL to allow only trusted domains
  let parsedUrl;
  try {
    parsedUrl = new urlModule.URL(url);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  // Define allowed hostnames for SSRF protection
  const allowedHosts = ['example.com', 'www.example.com', 'trustedsite.com'];

  if (!allowedHosts.includes(parsedUrl.hostname)) {
    return res.status(403).json({ error: 'URL domain is not allowed' });
  }

  const protocol = parsedUrl.protocol === 'https:' ? https : http;

  protocol.get(url, (resp) => {
    let data = '';
    resp.on('data', chunk => data += chunk);
    resp.on('end', () => {
      // Extract title for "preview"
      const titleMatch = data.match(/<title>(.*?)<\/title>/i);
      res.json({
        url: url,
        title: titleMatch ? titleMatch[1] : 'No title',
        status: resp.statusCode
        // Removed headers from response to prevent leaking internal information
      });
    });
  }).on('error', (err) => {
    res.status(502).json({ error: err.message });
  });
});

module.exports = router;