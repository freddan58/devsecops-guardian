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

  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);

  // Security fix: Redact sensitive headers before logging to prevent PII exposure
  const redactedHeaders = redactSensitiveData(req.headers);
  console.log(`[${timestamp}] Headers:`, JSON.stringify(redactedHeaders));

  if (req.body && Object.keys(req.body).length > 0) {
    // Security fix: Redact sensitive fields in request body before logging
    const redactedBody = redactSensitiveData(req.body);
    console.log(`[${timestamp}] Request Body:`, JSON.stringify(redactedBody));
  }

  if (req.query && Object.keys(req.query).length > 0) {
    // Security fix: Redact sensitive fields in query parameters before logging
    const redactedQuery = redactSensitiveData(req.query);
    console.log(`[${timestamp}] Query Params:`, JSON.stringify(redactedQuery));
  }

  const originalSend = res.send;
  res.send = function(body) {
    // Security fix: Attempt to parse and redact sensitive data in response body before logging
    let loggedBody = body;
    if (typeof body === 'string') {
      try {
        const parsed = JSON.parse(body);
        const redactedResponse = redactSensitiveData(parsed);
        loggedBody = JSON.stringify(redactedResponse).substring(0, 500);
      } catch (e) {
        // If not JSON, log only first 500 chars without redaction
        loggedBody = body.substring(0, 500);
      }
    } else if (typeof body === 'object' && body !== null) {
      const redactedResponse = redactSensitiveData(body);
      loggedBody = JSON.stringify(redactedResponse).substring(0, 500);
    }
    console.log(`[${timestamp}] Response [${res.statusCode}]:`, loggedBody);
    originalSend.call(this, body);
  };

  next();
}

module.exports = { requestLogger };