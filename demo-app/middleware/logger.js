// ============================================================
// VULNERABILITY #8: Logging PII (CWE-532)
// Sensitive data written to application logs
// ============================================================

function requestLogger(req, res, next) {
  const timestamp = new Date().toISOString();
  
  // VULNERABLE: Logging full request bodies which may contain PII
  // Account numbers, SSN, credit card numbers end up in log files
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);
  console.log(`[${timestamp}] Headers:`, JSON.stringify(req.headers));
  
  if (req.body && Object.keys(req.body).length > 0) {
    // VULNERABLE: Logs sensitive fields like account_number, ssn, card_number
    console.log(`[${timestamp}] Request Body:`, JSON.stringify(req.body));
  }

  // VULNERABLE: Log query parameters which may contain account IDs
  if (req.query && Object.keys(req.query).length > 0) {
    console.log(`[${timestamp}] Query Params:`, JSON.stringify(req.query));
  }

  // Capture response for logging
  const originalSend = res.send;
  res.send = function(body) {
    // VULNERABLE: Logging full response bodies with account balances, PII
    console.log(`[${timestamp}] Response [${res.statusCode}]:`, 
      typeof body === 'string' ? body.substring(0, 500) : body);
    originalSend.call(this, body);
  };

  next();
}

module.exports = { requestLogger };
