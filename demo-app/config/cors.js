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
// Added critical security headers to mitigate XSS, clickjacking, downgrade attacks, MIME sniffing, and privacy leaks
function insecureHeaders(req, res, next) {
  // Remove dangerous headers that disclose server info and debug data
  // Set recommended security headers
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  res.removeHeader('X-Debug-Mode');

  // Content-Security-Policy to restrict sources of scripts, styles, and other resources
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';");

  // Clickjacking protection
  res.setHeader('X-Frame-Options', 'DENY');

  // Enforce HTTPS for 1 year including subdomains
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

  // Prevent MIME sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Control referrer information sent
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Limit browser features to reduce attack surface
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  // Preserve CORS headers as originally set
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