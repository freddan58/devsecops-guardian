// ============================================================
// VULNERABILITIES: Overly Permissive CORS, Missing Security
//   Headers, Insecure TLS Configuration
// ============================================================

// VULN #40: Wildcard CORS - Allows any origin (CWE-942)
// Combined with credentials: true, this is a critical misconfiguration
const corsOptions = {
  origin: '*',                    // Allows ANY domain to make requests
  credentials: true,              // Sends cookies with cross-origin requests
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['*'],          // Allows any header
  exposedHeaders: ['Set-Cookie', 'Authorization', 'X-Session-Token'],
  maxAge: 86400 * 30,             // Cache preflight for 30 days
};

// VULN #41: Missing Security Headers (CWE-693)
// No CSP, no X-Frame-Options, no HSTS
function insecureHeaders(req, res, next) {
  // Deliberately NOT setting important security headers:
  // - Content-Security-Policy (CSP)
  // - X-Frame-Options (clickjacking protection)
  // - Strict-Transport-Security (HSTS)
  // - X-Content-Type-Options
  // - Referrer-Policy
  // - Permissions-Policy

  // Actually setting DANGEROUS headers
  res.setHeader('X-Powered-By', 'Express 4.18.2');  // Server fingerprinting
  res.setHeader('Server', 'NodeJS/18.19.0');          // Version disclosure
  res.setHeader('X-Debug-Mode', 'enabled');           // Debug info exposure
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  next();
}

// VULN #42: Insecure TLS/SSL Configuration (CWE-326)
// Fixed: Enforce TLS 1.2 or higher, remove weak ciphers, enable cert validation, enforce server cipher order
const tlsOptions = {
  minVersion: 'TLSv1.2',         // Enforce TLS 1.2 or higher to prevent downgrade attacks
  ciphers: [
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305'
  ].join(':'),                    // Use strong AEAD ciphers only
  rejectUnauthorized: true,      // Enforce certificate validation to prevent MITM
  honorCipherOrder: true,        // Server chooses cipher to enforce strong ciphers
};

module.exports = { corsOptions, insecureHeaders, tlsOptions };