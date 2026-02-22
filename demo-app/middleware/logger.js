// ============================================================
// VULNERABILITY #8: Logging PII (CWE-532)
// Sensitive data written to application logs
// ============================================================

function redactSensitiveData(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const redacted = Array.isArray(obj) ? [] : {};
  const sensitiveFields = ['account_number', 'ssn', 'card_number', 'credit_card', 'token', 'authorization', 'password'];

  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      if (sensitiveFields.includes(key.toLowerCase())) {
        redacted[key] = 'REDACTED'; // Redact sensitive fields to prevent PII exposure in logs
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

  // Redact sensitive headers before logging
  const safeHeaders = redactSensitiveData(req.headers);
  console.log(`[${timestamp}] Headers:`, JSON.stringify(safeHeaders));

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

  const originalSend = res.send;
  res.send = function(body) {
    // Avoid logging full response bodies containing sensitive data
    // Log only status code and truncated body length
    let logBody = '';
    if (typeof body === 'string') {
      logBody = body.length > 500 ? body.substring(0, 500) + '...[truncated]' : body;
    } else if (typeof body === 'object' && body !== null) {
      // Redact sensitive fields in response body before logging
      const safeBody = redactSensitiveData(body);
      logBody = JSON.stringify(safeBody).substring(0, 500);
      if (JSON.stringify(safeBody).length > 500) {
        logBody += '...[truncated]';
      }
    } else {
      logBody = String(body);
    }
    console.log(`[${timestamp}] Response [${res.statusCode}]:`, logBody);
    originalSend.call(this, body);
  };

  next();
}

module.exports = { requestLogger };