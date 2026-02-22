// ============================================================
// VULNERABILITY #10: Server-Side Request Forgery - SSRF (CWE-918)
// Attacker can make the server request internal/cloud metadata URLs
// ============================================================

const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const { URL } = require('url');

// Helper function to check if IP is private or loopback
const net = require('net');
const dns = require('dns').promises;

function isPrivateIP(ip) {
  // Check for IPv4 private ranges
  const parts = ip.split('.').map(Number);
  if (parts.length === 4) {
    if (parts[0] === 10) return true; // 10.0.0.0/8
    if (parts[0] === 127) return true; // 127.0.0.0/8 loopback
    if (parts[0] === 169 && parts[1] === 254) return true; // link-local
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16
  }
  // IPv6 loopback and unique local addresses
  if (ip === '::1') return true;
  if (ip.startsWith('fc') || ip.startsWith('fd')) return true; // Unique local address
  return false;
}

// VULNERABLE: SSRF - user-supplied URL is fetched by the server
// POST /api/webhooks/test
// Body: { "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
router.post('/test', async (req, res) => {
  const { url, payload } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'Webhook URL is required' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  // SECURITY FIX: Validate URL hostname and IP to prevent SSRF
  // 1. Resolve hostname to IP
  // 2. Block private IP ranges and cloud metadata IPs
  // 3. Allow only http or https protocols

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return res.status(400).json({ error: 'Only HTTP and HTTPS protocols are allowed' });
  }

  try {
    // Resolve DNS to IP addresses
    const addresses = await dns.lookup(parsedUrl.hostname, { all: true });

    for (const addr of addresses) {
      if (isPrivateIP(addr.address)) {
        return res.status(403).json({ error: 'Access to private or restricted IP addresses is forbidden' });
      }
      // Block cloud metadata IP specifically
      if (addr.address === '169.254.169.254') {
        return res.status(403).json({ error: 'Access to cloud metadata IP is forbidden' });
      }
    }
  } catch (err) {
    // DNS resolution failed
    return res.status(400).json({ error: 'Unable to resolve hostname' });
  }

  try {
    const protocol = parsedUrl.protocol === 'https:' ? https : http;

    const response = await new Promise((resolve, reject) => {
      const request = protocol.get(url, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', () => resolve({ status: resp.statusCode, body: data }));
      });
      request.on('error', reject);
      request.setTimeout(5000, () => { request.destroy(); reject(new Error('Timeout')); });
    });

    // SECURITY FIX: Limit response body length and do not expose headers
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

// FIXED: Added URL validation to allow only trusted domains and removed response headers from output
// GET /api/webhooks/preview?url=http://internal-service:8080/admin
router.get('/preview', (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter required' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  // Allowlist of trusted domains for SSRF protection
  const allowedHosts = ['example.com', 'www.example.com', 'trustedpartner.com'];

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
        // Removed headers to prevent leaking internal response headers
      });
    });
  }).on('error', (err) => {
    res.status(502).json({ error: err.message });
  });
});

module.exports = router;