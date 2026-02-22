// ============================================================
// VULNERABILITY #10: Server-Side Request Forgery - SSRF (CWE-918)
// Attacker can make the server request internal/cloud metadata URLs
// ============================================================

const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const net = require('net');

// Helper function to check if IP is private or loopback
function isPrivateIp(ip) {
  // IPv4 private ranges
  const privateRanges = [
    ['10.0.0.0', '10.255.255.255'],
    ['172.16.0.0', '172.31.255.255'],
    ['192.168.0.0', '192.168.255.255'],
    ['127.0.0.0', '127.255.255.255'], // loopback
    ['169.254.0.0', '169.254.255.255'], // link-local
  ];

  const ipNum = ipToNumber(ip);
  for (const [start, end] of privateRanges) {
    if (ipNum >= ipToNumber(start) && ipNum <= ipToNumber(end)) {
      return true;
    }
  }
  return false;
}

function ipToNumber(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

// Allowlist of trusted domains (example)
const allowedDomains = [
  'example.com',
  'api.example.com',
  'trusted-webhook.com'
];

// Validate URL and enforce allowlist and block internal IPs
async function validateUrl(userUrl) {
  let parsedUrl;
  try {
    parsedUrl = new URL(userUrl);
  } catch (e) {
    throw new Error('Invalid URL format');
  }

  // Enforce protocol
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new Error('Only HTTP and HTTPS protocols are allowed');
  }

  // Check domain against allowlist
  const hostname = parsedUrl.hostname.toLowerCase();
  const domainAllowed = allowedDomains.some(domain => {
    return hostname === domain || hostname.endsWith('.' + domain);
  });
  if (!domainAllowed) {
    throw new Error('Domain is not in the allowlist');
  }

  // Resolve DNS to IPs and check for private IPs
  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch (err) {
    throw new Error('DNS lookup failed');
  }

  for (const addr of addresses) {
    if (net.isIP(addr.address)) {
      if (isPrivateIp(addr.address)) {
        throw new Error('IP address is in a private or restricted range');
      }
    } else {
      throw new Error('Resolved address is not a valid IP');
    }
  }

  return parsedUrl.toString();
}

// POST /api/webhooks/test
// Body: { "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
router.post('/test', async (req, res) => {
  const { url, payload } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'Webhook URL is required' });
  }

  try {
    // SECURITY FIX: Validate URL against allowlist and block internal IPs to prevent SSRF
    const safeUrl = await validateUrl(url);

    const protocol = safeUrl.startsWith('https') ? https : http;

    const response = await new Promise((resolve, reject) => {
      const request = protocol.get(safeUrl, (resp) => {
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

// VULNERABLE: URL fetcher for "link preview" feature
// GET /api/webhooks/preview?url=http://internal-service:8080/admin
router.get('/preview', (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ error: 'URL parameter required' });
  }

  // VULNERABLE: Fetching arbitrary URLs without blocklist validation
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
        // VULNERABLE: Leaking internal response headers
        headers: resp.headers,
      });
    });
  }).on('error', (err) => {
    res.status(502).json({ error: err.message });
  });
});

module.exports = router;