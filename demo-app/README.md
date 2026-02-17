# Vulnerable Banking API

> ⚠️ **WARNING**: This application contains **intentional security vulnerabilities** for demonstration purposes. DO NOT deploy to production.

## Purpose

This is a demo banking API used by DevSecOps Guardian to demonstrate AI-powered security scanning. It contains 8 planted vulnerabilities (6 confirmed + 2 false positives) that the 4-agent pipeline detects, analyzes, fixes, and reports on.

## Planted Vulnerabilities

| # | Vulnerability | Location | CWE | Expected Result |
|---|--------------|----------|-----|----------------|
| 1 | SQL Injection | `routes/accounts.js` | CWE-89 | ✅ CONFIRMED |
| 2 | Reflected XSS | `routes/search.js` | CWE-79 | ✅ CONFIRMED |
| 3 | Hardcoded API Key | `config/database.js` | CWE-798 | ✅ CONFIRMED |
| 4 | Missing Auth Check | `routes/users.js` | CWE-862 | ✅ CONFIRMED |
| 5 | IDOR | `routes/transfers.js` | CWE-639 | ✅ CONFIRMED |
| 6 | SQL Query (parameterized) | `routes/balance.js` | CWE-89 | ❌ FALSE POSITIVE |
| 7 | Weak Crypto (bcrypt) | `utils/auth.js` | CWE-328 | ❌ FALSE POSITIVE |
| 8 | Logging PII | `middleware/logger.js` | CWE-532 | ✅ CONFIRMED |

## Setup

```bash
npm install
npm run seed    # Create database with sample data
npm start       # Start server on port 3000
```

## API Endpoints

- `GET /` - API info and endpoint listing
- `GET /health` - Health check
- `GET /api/accounts?id=` - Account lookup (VULN: SQL injection)
- `GET /api/search?q=` - Search accounts (VULN: XSS)
- `POST /api/users/login` - Authenticate user
- `GET /api/users/profile` - Get profile (requires JWT)
- `DELETE /api/users/:id` - Delete user (VULN: no auth)
- `POST /api/transfers` - Create transfer (requires JWT)
- `GET /api/transfers/:id` - View transfer (VULN: IDOR)
- `GET /api/balance` - View balance (requires JWT, SAFE)
- `GET /api/balance/history` - Transaction history (requires JWT, SAFE)

## Test Users

| Username | Password | Role |
|----------|----------|------|
| jdoe | password123 | customer |
| admin | admin456 | admin |
| msmith | customer789 | customer |
