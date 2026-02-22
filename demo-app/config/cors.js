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
// Fixed by setting strict security headers and removing information disclosure headers
function insecureHeaders(req, res, next) {
  // Set Content-Security-Policy to restrict resource loading and mitigate XSS
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';");
  // Prevent clickjacking by denying framing
  res.setHeader('X-Frame-Options', 'DENY');
  // Enforce HTTPS connections for 6 months
  res.setHeader('Strict-Transport-Security', 'max-age=15768000; includeSubDomains; preload');
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Control information sent in Referer header
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Disable browser features that could cause security or privacy issues
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  // Remove headers that leak server software/version and debug info to reduce attack surface
  // Do NOT set 'X-Powered-By', 'Server', or 'X-Debug-Mode'
  
  // Preserve CORS headers per original code
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