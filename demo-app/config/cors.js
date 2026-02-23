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

  // SECURITY FIX: Removed unsafe dynamic setting of Access-Control-Allow-Origin and credentials
  // This should be handled only by the dedicated CORS middleware with strict origin validation

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