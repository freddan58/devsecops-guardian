// ============================================================
// VULNERABILITY #8: Logging PII (CWE-532)
// Sensitive data written to application logs
// ============================================================

function redactSensitiveData(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const sensitiveFields = ['account_number', 'ssn', 'card_number', 'credit_card', 'cvv', 'password'];
  const redacted = Array.isArray(obj) ? [] : {};
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      if (sensitiveFields.includes(key.toLowerCase())) {
        redacted[key] = 'REDACTED'; // Redact sensitive PII fields
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        redacted[key] = redactSensitiveData(obj[key]);
      } else {
        redacted[key] = obj[key];
      }
    }
  }
  return redacted;
}

function requestLogger(req, res, next) {
  const timestamp = new Date().toISOString();

  // Log method and URL
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);
  // Log headers without redaction (assuming no PII in headers)
  console.log(`[${timestamp}] Headers:`, JSON.stringify(req.headers));

  if (req.body && Object.keys(req.body).length > 0) {
    // Redact sensitive fields in request body before logging
    const safeBody = redactSensitiveData(req.body);
    console.log(`[${timestamp}] Request Body:`, JSON.stringify(safeBody));
  }

  if (req.query && Object.keys(req.query).length > 0) {
    // Redact sensitive fields in query parameters before logging
    const safeQuery = redactSensitiveData(req.query);
    console.log(`[${timestamp}] Query Params:`, JSON.stringify(safeQuery));
  }

  // Capture response for logging
  const originalSend = res.send;
  res.send = function(body) {
    let logBody = body;
    try {
      if (typeof body === 'string') {
        // Attempt to parse JSON string to redact sensitive data
        const parsed = JSON.parse(body);
        const safeResponse = redactSensitiveData(parsed);
        logBody = JSON.stringify(safeResponse).substring(0, 500);
      } else if (typeof body === 'object' && body !== null) {
        const safeResponse = redactSensitiveData(body);
        logBody = JSON.stringify(safeResponse).substring(0, 500);
      } else {
        logBody = typeof body === 'string' ? body.substring(0, 500) : body;
      }
    } catch (e) {
      // If parsing fails, fallback to substring of original body
      logBody = typeof body === 'string' ? body.substring(0, 500) : body;
    }

    // Log response body with sensitive data redacted
    console.log(`[${timestamp}] Response [${res.statusCode}]:`, logBody);
    originalSend.call(this, body);
  };

  next();
}

module.exports = { requestLogger };