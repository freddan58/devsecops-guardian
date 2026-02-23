// ============================================================
// VULNERABILITIES: Overly Permissive CORS, Missing Security
//   Headers, Insecure TLS Configuration
// ============================================================

// VULN #40: Wildcard CORS - Allows any origin (CWE-942)
// Combined with credentials: true, this is a critical misconfiguration
// FIX: Restrict CORS origins to a whitelist; do not allow wildcard with credentials
const allowedOrigins = [
  'https://trusted.bankdomain.com',
  'https://app.bankdomain.com'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
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