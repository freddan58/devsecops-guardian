// ============================================================
// VULNERABILITY #8: Logging PII (CWE-532)
// Sensitive data written to application logs
// ============================================================

function redactSensitiveData(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const redactedObj = Array.isArray(obj) ? [] : {};
  const sensitiveFields = ['account_number', 'ssn', 'card_number', 'credit_card', 'cardNumber', 'ssnNumber'];

  for (const key in obj) {
    if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
    if (sensitiveFields.includes(key.toLowerCase())) {
      redactedObj[key] = 'REDACTED'; // Redact sensitive PII fields
    } else if (typeof obj[key] === 'object' && obj[key] !== null) {
      redactedObj[key] = redactSensitiveData(obj[key]); // Recursively redact nested objects
    } else {
      redactedObj[key] = obj[key];
    }
  }
  return redactedObj;
}

function requestLogger(req, res, next) {
  const timestamp = new Date().toISOString();

  // Log method and URL without sensitive data
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);

  // Redact sensitive headers before logging
  const redactedHeaders = redactSensitiveData(req.headers);
  console.log(`[${timestamp}] Headers:`, JSON.stringify(redactedHeaders));

  if (req.body && Object.keys(req.body).length > 0) {
    // Redact sensitive fields in request body before logging
    const redactedBody = redactSensitiveData(req.body);
    console.log(`[${timestamp}] Request Body:`, JSON.stringify(redactedBody));
  }

  if (req.query && Object.keys(req.query).length > 0) {
    // Redact sensitive fields in query parameters before logging
    const redactedQuery = redactSensitiveData(req.query);
    console.log(`[${timestamp}] Query Params:`, JSON.stringify(redactedQuery));
  }

  // Capture response for logging
  const originalSend = res.send;
  res.send = function(body) {
    // Redact sensitive fields in response body before logging if JSON
    let logBody = body;
    if (typeof body === 'string') {
      try {
        const parsed = JSON.parse(body);
        const redacted = redactSensitiveData(parsed);
        logBody = JSON.stringify(redacted).substring(0, 500);
      } catch (e) {
        // If not JSON, log truncated string
        logBody = body.substring(0, 500);
      }
    } else if (typeof body === 'object' && body !== null) {
      const redacted = redactSensitiveData(body);
      logBody = JSON.stringify(redacted).substring(0, 500);
    }

    console.log(`[${timestamp}] Response [${res.statusCode}]:`, logBody);
    originalSend.call(this, body);
  };

  next();
}

module.exports = { requestLogger };