# DevSecOps Guardian - Project Status & Context

## 🎯 Hackathon Info
- **Hackathon**: Microsoft AI Dev Days 2026
- **Track**: Agentic DevOps ($20K Grand Prize)
- **Team**: Soluciones Etech Corp (Freddy Urbano - furbano@soluetech.com)
- **Deadline**: March 15, 2026
- **Repo**: https://github.com/freddan58/devsecops-guardian

---

## 📋 What Is DevSecOps Guardian?

A **multi-agent AI security pipeline** for banking applications. Four specialized AI agents replace traditional SAST tools (SonarQube, Checkmarx, Fortify):

1. **Scanner Agent** - LLM-based code security scanner (detects vulns using AI reasoning, not regex)
2. **Analyzer Agent** - False positive eliminator (contextual analysis: is this actually exploitable?)
3. **Fixer Agent** - Auto-generates draft PRs with code fixes
4. **Compliance Agent** - Generates audit-ready reports mapped to PCI-DSS 4.0

**Key differentiator**: Multi-agent architecture on Microsoft Foundry + compliance reporting (no competitor has this).

---

## ✅ What's Been Built (as of Feb 17, 2026)

### 1. Demo App (COMPLETE) ✅
**Location**: `demo-app/`
- Node.js/Express banking API with **8 intentionally planted vulnerabilities**
- SQLite database with sample data (users, accounts, transfers)
- Tested and working: `npm run seed && npm start` on port 3000
- SQL injection confirmed exploitable: `GET /api/accounts?id=1%20OR%201=1` dumps all accounts

**Planted Vulnerabilities:**

| # | Vulnerability | File | CWE | Expected Result |
|---|--------------|------|-----|-----------------|
| 1 | SQL Injection | routes/accounts.js | CWE-89 | CONFIRMED - public endpoint, string concat |
| 2 | Reflected XSS | routes/search.js | CWE-79 | CONFIRMED - user input in HTML |
| 3 | Hardcoded API Key | config/database.js | CWE-798 | CONFIRMED - secrets in source |
| 4 | Missing Auth | routes/users.js (DELETE) | CWE-862 | CONFIRMED - no auth on destructive endpoint |
| 5 | IDOR | routes/transfers.js | CWE-639 | CONFIRMED - no ownership check |
| 6 | SQL Query (parameterized) | routes/balance.js | CWE-89 | FALSE POSITIVE - behind JWT + prepared stmt |
| 7 | Weak Crypto (bcrypt) | utils/auth.js | CWE-328 | FALSE POSITIVE - bcrypt is acceptable |
| 8 | Logging PII | middleware/logger.js | CWE-532 | CONFIRMED - logs account numbers/SSN |

### 2. GitHub MCP Server (COMPLETE) ✅
**Location**: `mcp-servers/github/`
- Python MCP server with **9 tools** for GitHub API interaction
- All agents use this to read/write to the repo
- **Tests passing**: 2/2 (list files + read file content)

**Tools:**
| Tool | Type | Used By |
|------|------|---------|
| `github_read_file` | Read | Scanner, Analyzer |
| `github_list_files` | Read | Scanner |
| `github_read_pr_diff` | Read | Scanner |
| `github_list_pr_files` | Read | Scanner |
| `github_get_pr` | Read | Compliance |
| `github_create_branch` | Write | Fixer |
| `github_create_or_update_file` | Write | Fixer |
| `github_create_pr` | Write | Fixer |
| `github_post_pr_comment` | Write | Fixer |

### 3. Scanner Agent (COMPLETE) ✅
**Location**: `agents/scanner/`
- Reads files from GitHub via MCP tools
- Sends to Azure OpenAI (gpt-4.1-mini) for security analysis
- **Last test**: Detected 6 of 8 vulnerabilities (correctly excludes the 2 false positives - Analyzer handles those)
- Smart scan bug (escaped braces) **FIXED AND VERIFIED**

**Files:**
| File | Purpose | Status |
|------|---------|--------|
| `config.py` | Configuration from .env | ✅ |
| `prompts.py` | LLM system prompt + templates | ✅ |
| `github_client.py` | Reads files via GitHub MCP tools | ✅ |
| `llm_engine.py` | Calls Azure OpenAI for analysis | ✅ |
| `scanner.py` | Main orchestrator + CLI | ✅ |
| `smart_scan.py` | Smart scan strategy for large repos | ✅ |

### 4. Analyzer Agent (COMPLETE) ✅
**Location**: `agents/analyzer/`
- Takes Scanner findings + full source code from GitHub
- For each finding, reasons about exploitability via LLM:
  - Is this endpoint public or behind auth?
  - Is input sanitized upstream?
  - Is the data sensitive (PCI, PII)?
- Outputs: confirmed/false_positive verdict, exploitability score (0-100)
- **Last test**: All 6 scanner findings correctly analyzed as CONFIRMED with scores 80-95

**Files:**
| File | Purpose | Status |
|------|---------|--------|
| `config.py` | Configuration from .env | ✅ |
| `prompts.py` | LLM system prompt + analysis templates | ✅ |
| `github_client.py` | Reads source files via GitHub MCP | ✅ |
| `llm_engine.py` | Calls Azure OpenAI for contextual analysis | ✅ |
| `analyzer.py` | Main orchestrator + CLI | ✅ |

### 5. Fixer Agent (COMPLETE) ✅
**Location**: `agents/fixer/`
- Takes confirmed findings from Analyzer
- For each finding: reads source file, generates LLM fix, creates security/ branch, commits fix, creates draft PR
- Human-in-the-loop: developer reviews and merges (all PRs are drafts)
- Uses GitHub MCP write tools (create_branch, create_or_update_file, create_pr)
- **Last test**: 6/6 confirmed findings fixed, 6 draft PRs created (PRs #1-#6)
- Supports `--dry-run` mode for testing without GitHub writes

**Files:**
| File | Purpose | Status |
|------|---------|--------|
| `config.py` | Configuration from .env | ✅ |
| `prompts.py` | LLM system prompt + fix generation templates | ✅ |
| `github_client.py` | Read + Write ops via GitHub MCP (branch, commit, PR) | ✅ |
| `llm_engine.py` | Calls Azure OpenAI for fix code generation | ✅ |
| `fixer.py` | Main orchestrator + CLI | ✅ |

**Draft PRs Created:**
| PR# | Finding | Branch |
|-----|---------|--------|
| #1 | SQL Injection (CWE-89) | `security/fix-sql-injection-accounts` |
| #2 | XSS (CWE-79) | `security/fix-reflected-cross-site-scripting-xss-search` |
| #3 | Hardcoded Secrets (CWE-798) | `security/fix-hardcoded-secrets-database` |
| #4 | PII Logging (CWE-532) | `security/fix-information-exposure-in-logs-logger` |
| #5 | IDOR (CWE-639) | `security/fix-missing-authorization-idor-transfers` |
| #6 | Missing Auth (CWE-862) | `security/fix-missing-authentication-users` |

### 6. Compliance Agent
**Location**: `agents/compliance/` (empty)
- Takes full pipeline results (Scanner → Analyzer → Fixer)
- Maps findings to PCI-DSS 4.0 controls (Req 6.2.4, 6.3.1, 8.3)
- Generates Markdown/PDF report with evidence trail
- **KILLER DIFFERENTIATOR** - no competitor has this

### 7. Azure DevOps Pipeline
- Triggers the 4-agent pipeline on PR creation
- NOT using GitHub Actions (billing concerns - previously charged $5K)
- Azure Pipelines strengthens "Best Azure Integration" category

### 8. Demo Video (2 min)
- Record the full pipeline: PR → Scanner → Analyzer → Fixer → Compliance Report

---

## 🔧 Technical Details

### Azure OpenAI (Foundry)
- **Endpoint**: `https://devsecops-guardian-hackaton-etec.services.ai.azure.com/`
- **API Key**: In `agents/scanner/.env`, `agents/analyzer/.env`, `agents/fixer/.env` (DO NOT COMMIT)
- **Project**: `devsecops-guardian-hackaton-etech`
- **Deployed models**: `gpt-4.1-mini` (practice, cheap), `o4-mini` (final video, better quality)
- **API Version**: `2024-12-01-preview`

### GitHub Token
- **Token**: Fine-grained PAT in `mcp-servers/github/.env` and `agents/scanner/.env`
- **Scopes**: Contents (R/W), Pull Requests (R/W), Metadata (Read)
- **Name**: `devsecops-guardian-hackathon`

### Environment Files (.env) - ALL in .gitignore
- `mcp-servers/github/.env` - GITHUB_TOKEN
- `agents/scanner/.env` - AZURE_OPENAI_* + GITHUB_TOKEN
- `agents/analyzer/.env` - AZURE_OPENAI_* + GITHUB_TOKEN
- `agents/fixer/.env` - AZURE_OPENAI_* + GITHUB_TOKEN
- (future) `agents/compliance/.env`

### Key Dependencies
- **Python 3.12** (installed on machine)
- **Node.js** (for demo-app)
- `httpx` - async HTTP client for GitHub + Azure OpenAI APIs
- `python-dotenv` - .env loading
- `mcp[cli]` - MCP server framework (FastMCP)
- `pydantic` - input validation

---

## 📁 Repository Structure
```
devsecops-guardian/
├── demo-app/                    # ✅ Vulnerable banking API (Node.js)
│   ├── config/database.js       # VULN #3: Hardcoded secrets
│   ├── middleware/auth.js       # JWT authentication
│   ├── middleware/logger.js     # VULN #8: PII logging
│   ├── routes/accounts.js      # VULN #1: SQL Injection
│   ├── routes/balance.js       # FALSE POSITIVE #6: Safe parameterized SQL
│   ├── routes/search.js        # VULN #2: XSS
│   ├── routes/transfers.js     # VULN #5: IDOR
│   ├── routes/users.js         # VULN #4: Missing auth
│   ├── utils/auth.js           # FALSE POSITIVE #7: bcrypt (safe)
│   ├── seed.js                 # Database seeder
│   ├── server.js               # Express app
│   └── package.json
├── mcp-servers/
│   └── github/                  # ✅ GitHub MCP Server (9 tools)
│       ├── server.py
│       ├── test_tools.py
│       ├── pyproject.toml
│       └── README.md
├── agents/
│   └── scanner/                 # ✅ Scanner Agent
│       ├── config.py
│       ├── prompts.py
│       ├── github_client.py
│       ├── llm_engine.py
│       ├── scanner.py
│       ├── smart_scan.py
│       ├── requirements.txt
│       └── .env.example
│   ├── analyzer/                # ✅ Analyzer Agent
│       ├── config.py
│       ├── prompts.py
│       ├── github_client.py
│       ├── llm_engine.py
│       ├── analyzer.py
│       ├── requirements.txt
│       └── .env.example
│   ├── fixer/                   # ✅ Fixer Agent
│       ├── config.py
│       ├── prompts.py
│       ├── github_client.py
│       ├── llm_engine.py
│       ├── fixer.py
│       ├── requirements.txt
│       └── .env.example
│   └── compliance/              # ❌ Not built
├── docs/                        # Empty - architecture diagrams later
├── reports/                     # Scanner output goes here
├── .gitignore                   # Includes .env, __pycache__, *.db, Python
└── PROJECT_STATUS.md            # ← THIS FILE
```

---

## 🏗️ Build Priority Order

1. ~~GitHub MCP Server~~ ✅
2. ~~Scanner Agent~~ ✅
3. ~~Analyzer Agent~~ ✅
4. ~~Fixer Agent~~ ✅
5. **Compliance Agent** <- NEXT
6. Azure DevOps Pipeline (last - just trigger/glue)
7. Demo Video

---

## 💡 Architecture Decisions

1. **Python over TypeScript** for agents - Foundry SDK is Python-first
2. **Azure DevOps Pipelines over GitHub Actions** - billing concerns ($5K incident), Azure integration points
3. **gpt-4.1-mini for practice, o4-mini for final** - cost optimization
4. **Smart scan strategy** for large repos: Context Map → Grouped Scan → Deduplicate
5. **MCP Server as shared layer** - all agents use same GitHub MCP tools
6. **Draft PRs always** - human-in-the-loop for compliance (regulators need to see human approval)

---

## 📝 Blueprint Document
Full hackathon blueprint is at: `/mnt/project/DevSecOps_Guardian_Hackathon_Blueprint.docx`
Contains: problem statement, architecture, demo flow, competitive analysis, build plan, costs.

---

*Last updated: February 17, 2026 ~5:15 PM EST*
