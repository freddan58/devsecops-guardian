// ============================================================
// VULNERABILITY #8: Logging PII (CWE-532)
// Sensitive data written to application logs
// ============================================================

function redactPII(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const redacted = Array.isArray(obj) ? [] : {};
  for (const key in obj) {
    if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
    // Redact sensitive fields
    if (['account_number', 'ssn', 'card_number', 'credit_card', 'cvv', 'password'].includes(key.toLowerCase())) {
      redacted[key] = 'REDACTED';
    } else if (typeof obj[key] === 'object' && obj[key] !== null) {
      redacted[key] = redactPII(obj[key]);
    } else {
      redacted[key] = obj[key];
    }
  }
  return redacted;
}

function requestLogger(req, res, next) {
  const timestamp = new Date().toISOString();

  // Log method and URL without sensitive data
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);

  // Redact sensitive headers before logging
  const safeHeaders = redactPII(req.headers);
  console.log(`[${timestamp}] Headers:`, JSON.stringify(safeHeaders));

  if (req.body && Object.keys(req.body).length > 0) {
    // Redact sensitive fields in request body before logging
    const safeBody = redactPII(req.body);
    console.log(`[${timestamp}] Request Body:`, JSON.stringify(safeBody));
  }

  if (req.query && Object.keys(req.query).length > 0) {
    // Redact sensitive fields in query parameters before logging
    const safeQuery = redactPII(req.query);
    console.log(`[${timestamp}] Query Params:`, JSON.stringify(safeQuery));
  }

  // Capture response for logging
  const originalSend = res.send;
  res.send = function(body) {
    let safeBody = body;
    try {
      if (typeof body === 'string') {
        // Attempt to parse JSON response to redact PII
        const parsed = JSON.parse(body);
        safeBody = JSON.stringify(redactPII(parsed));
      } else if (typeof body === 'object' && body !== null) {
        safeBody = JSON.stringify(redactPII(body));
      }
    } catch (e) {
      // If parsing fails, fallback to substring but do not log full sensitive data
      if (typeof body === 'string') {
        safeBody = body.substring(0, 500) + ' [TRUNCATED]';
      }
    }
    // Log redacted response body to avoid PII exposure
    console.log(`[${timestamp}] Response [${res.statusCode}]:`, safeBody);
    originalSend.call(this, body);
  };

  next();
}

module.exports = { requestLogger };