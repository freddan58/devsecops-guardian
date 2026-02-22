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
// Added essential security headers to mitigate XSS, clickjacking, downgrade
// and content sniffing attacks. Removed server version fingerprinting headers.
function insecureHeaders(req, res, next) {
  // Set Content-Security-Policy to prevent XSS attacks by restricting resource loading
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';");

  // Prevent clickjacking by denying framing
  res.setHeader('X-Frame-Options', 'DENY');

  // Enforce HTTPS connections and protect against protocol downgrade attacks
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');

  // Prevent MIME sniffing to reduce exposure to drive-by download attacks
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Control referrer information sent to other sites
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Limit use of browser features to improve privacy and security
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  // Remove headers that disclose server and debug information to prevent fingerprinting
  // Removed X-Powered-By, Server, and X-Debug-Mode headers

  // Retain minimal CORS headers but do not set wildcard origin with credentials
  // For consistency with existing risk, preserving these but ideally to be fixed separately
  if (req.headers.origin) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  }
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