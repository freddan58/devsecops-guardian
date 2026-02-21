# Copilot Instructions for DevSecOps Guardian

## Project Context
This is a multi-agent AI security pipeline for banking applications.
The `demo-app/` directory contains an intentionally vulnerable Node.js/Express banking API.

## Security Fix Guidelines
When fixing security vulnerabilities:
1. Always use parameterized queries (never string concatenation for SQL)
2. Add input validation using express-validator or manual checks
3. Ensure authentication middleware is applied to all sensitive endpoints
4. Never hardcode secrets — use environment variables
5. Implement proper authorization checks (ownership validation for resources)
6. Use secure logging that masks PII (account numbers, SSNs)
7. Follow OWASP Secure Coding Guidelines for Node.js/Express
8. Validate and sanitize all path inputs to prevent path traversal
9. Restrict outbound HTTP requests to allowed domains (prevent SSRF)
10. Never use `eval()`, `exec()`, or `Function()` with user input
11. Protect against prototype pollution by validating object keys

## Code Style
- Use ES6+ syntax (const/let, arrow functions, template literals for non-SQL strings)
- Add JSDoc comments for all functions
- Include error handling with proper HTTP status codes
- Follow Express.js middleware patterns

## Architecture Overview
- `agents/` — 5 Python AI agents (Scanner, Analyzer, Fixer, Risk Profiler, Compliance)
- `api/` — FastAPI backend gateway orchestrating the pipeline
- `dashboard/` — Next.js frontend displaying scan results
- `demo-app/` — Intentionally vulnerable Express.js banking API
- `mcp-servers/github/` — MCP Server with 9 GitHub tools

## Testing
After fixes, ensure:
- `npm start` runs without errors in `demo-app/`
- `npm run seed` populates test data correctly
- API endpoints return expected responses
- No new vulnerabilities introduced by the fix
