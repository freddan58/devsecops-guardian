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
// Added critical security headers and removed dangerous server info headers
function insecureHeaders(req, res, next) {
  // Set strict Content-Security-Policy header to mitigate XSS
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self';");

  // Prevent clickjacking by denying framing
  res.setHeader('X-Frame-Options', 'DENY');

  // Enforce HTTPS with long max-age and subdomains included
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');

  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Restrict referrer information
  res.setHeader('Referrer-Policy', 'no-referrer');

  // Disable features to reduce attack surface
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), fullscreen=()');

  // Remove dangerous headers that disclose internal implementation details
  // Do NOT set 'X-Powered-By', 'Server', 'X-Debug-Mode'

  // Preserve CORS headers as in original implementation
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  next();
}

// VULN #42: Insecure TLS/SSL Configuration (CWE-326)
// If this were used for HTTPS server setup
const tlsOptions = {
  minVersion: 'TLSv1',           // TLS 1.0 is deprecated and insecure
  ciphers: [
    'RC4-SHA',                    // RC4 is broken
    'DES-CBC3-SHA',               // 3DES is deprecated
    'AES128-SHA',                 // CBC mode without AEAD
    'NULL-SHA',                   // No encryption at all!
  ].join(':'),
  rejectUnauthorized: false,      // Accepts invalid/self-signed certificates
  honorCipherOrder: false,        // Client chooses cipher (may pick weakest)
};

module.exports = { corsOptions, insecureHeaders, tlsOptions };