// ============================================================
// VULNERABILITY #8: Logging PII (CWE-532)
// Sensitive data written to application logs
// ============================================================

function redactSensitiveData(obj) {
  const sensitiveFields = ['account_number', 'ssn', 'card_number', 'credit_card', 'password'];
  if (obj && typeof obj === 'object') {
    const redactedObj = Array.isArray(obj) ? [] : {};
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        if (sensitiveFields.includes(key.toLowerCase())) {
          redactedObj[key] = '[REDACTED]';
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          redactedObj[key] = redactSensitiveData(obj[key]);
        } else {
          redactedObj[key] = obj[key];
        }
      }
    }
    return redactedObj;
  }
  return obj;
}

function requestLogger(req, res, next) {
  const timestamp = new Date().toISOString();

  // Fixed: Avoid logging full request body with sensitive PII by redacting sensitive fields
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);
  console.log(`[${timestamp}] Headers:`, JSON.stringify(req.headers));

  if (req.body && Object.keys(req.body).length > 0) {
    const sanitizedBody = redactSensitiveData(req.body);
    console.log(`[${timestamp}] Request Body (redacted):`, JSON.stringify(sanitizedBody));
  }

  // Fixed: Avoid logging full query params with possible sensitive PII by redacting sensitive fields
  if (req.query && Object.keys(req.query).length > 0) {
    const sanitizedQuery = redactSensitiveData(req.query);
    console.log(`[${timestamp}] Query Params (redacted):`, JSON.stringify(sanitizedQuery));
  }

  // Capture response for logging
  const originalSend = res.send;
  res.send = function(body) {
    /* Fixed: Do not log full response with potential sensitive information
       Instead log only minimal info like response status code and body size if string */
    if (typeof body === 'string') {
      console.log(`[${timestamp}] Response [${res.statusCode}] (body preview):`, body.substring(0, 500));
    } else {
      console.log(`[${timestamp}] Response [${res.statusCode}] (response body omitted for sensitive data)`);
    }
    originalSend.call(this, body);
  };

  next();
}

module.exports = { requestLogger };