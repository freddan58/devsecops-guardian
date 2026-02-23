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
// Fixed to disallow TLS 1.0, remove weak ciphers, enforce cert validation,
// and enforce server cipher order to enhance security against MITM and downgrade attacks
const tlsOptions = {
  minVersion: 'TLSv1.2',           // Enforce minimum TLS 1.2 version (deprecated TLS disabled)
  ciphers: [
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'DHE-RSA-AES128-GCM-SHA256',
    'DHE-RSA-AES256-GCM-SHA384'
  ].join(':'),
  rejectUnauthorized: true,      // Enforce valid and trusted certificates to prevent MITM
  honorCipherOrder: true,        // Server chooses cipher preference preventing client weak cipher downgrade
};

module.exports = { corsOptions, insecureHeaders, tlsOptions };