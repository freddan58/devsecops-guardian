# DevSecOps Guardian - Project Status & Context

## Hackathon Info
- **Hackathon**: Microsoft AI Dev Days 2026
- **Track**: Agentic DevOps (Grand Prize: $5K/person + Microsoft Build 2026 tickets)
- **Category Prizes**: Best Multi-Agent System, Best Enterprise Solution, Best Azure Integration
- **Team**: Soluciones Etech Corp (Freddy Urbano - furbano@soluetech.com)
- **Deadline**: March 15, 2026 (11:59 PM PT)
- **Judging**: March 16-22, 2026 | Winners: ~March 25, 2026
- **Repo**: https://github.com/freddan58/devsecops-guardian

### Submission Requirements
| # | Deliverable | Status |
|---|-------------|--------|
| 1 | Public GitHub repo with source code | Done |
| 2 | Demo video < 2 min (YouTube/Vimeo public URL) | PENDING |
| 3 | Project pitch/description (what, which Azure tech, what problem) | PENDING |
| 4 | Working demo link for judges to test | PENDING |
| 5 | All materials in English | Done |

### Judging Criteria (each 20%)
| Criterion | What judges evaluate | Our strength |
|-----------|---------------------|--------------|
| Technological Implementation | Code quality, use of Foundry/Agent Framework/Azure MCP/GitHub Copilot | Strong |
| Agentic Design & Innovation | Creative agent patterns, orchestration, multi-agent collaboration | Very strong |
| Real-World Impact | Problem significance, production potential, business impact | Very strong |
| User Experience & Presentation | Intuitive design, demo clarity, frontend/backend balance | Strong (Dashboard built) |
| Category Adherence | Compliance with Agentic DevOps track requirements | Strong |

---

## What Is DevSecOps Guardian?

An **enterprise-grade multi-agent AI security platform** for banking and regulated industries. Five specialized AI agents work as a pipeline to replace traditional SAST tools (SonarQube, Checkmarx, Fortify) with LLM-powered reasoning:

1. **Scanner Agent** - LLM-based code security scanner (AI reasoning, not regex rules)
2. **Analyzer Agent** - False positive eliminator (contextual exploitability analysis)
3. **Fixer Agent** - Auto-generates draft PRs with security fixes (human-in-the-loop)
4. **Risk Profiler Agent** - Generates risk profile per service/API with OWASP scoring
5. **Compliance Agent** - Audit-ready reports mapped to PCI-DSS 4.0, SOX, SWIFT CSP

**Dashboard**: React/Next.js web application for visualizing pipeline results, managing scans, and reviewing compliance reports.

### Competitive Differentiation vs GitHub Copilot Security / Dependabot

| Capability | GitHub CodeQL/Copilot Autofix | Dependabot | **DevSecOps Guardian** |
|-----------|-------------------------------|------------|------------------------|
| Detection method | Predefined CodeQL rules | CVE database for deps | **LLM reasoning over code context** |
| False positive handling | Manual tuning of rules | N/A | **Dedicated AI agent with exploitability scoring** |
| Auto-fix | Copilot Autofix (limited languages) | Version bumps only | **Full code rewrites as draft PRs** |
| Risk profiling | NO | NO | **OWASP-based risk score per service** |
| Compliance reporting | NO | NO | **PCI-DSS 4.0 audit-ready reports** |
| Multi-agent orchestration | Single tool | Single bot | **5 specialized agents in pipeline** |
| Business logic understanding | Limited (pattern matching) | None | **LLM understands domain context** |
| Customizable per industry | CodeQL queries (limited) | No | **Prompts editable per domain** |

**Key differentiators no competitor has:**
1. **Analyzer Agent** - AI-powered false positive elimination with exploitability score (0-100)
2. **Risk Profiler Agent** - Per-service risk assessment with OWASP Top 10 breakdown
3. **Compliance Agent** - Automated CWE-to-PCI-DSS 4.0 mapping with evidence chain
4. **End-to-end pipeline** - From detection to fix PR to audit report, fully automated

---

## Architecture Overview

```
                    +------------------------------------------+
                    |          Dashboard (Next.js)              |
                    |  React frontend on Azure Container Apps   |
                    +----+-------------+-----------+-----------+
                         |             |           |
                    +----v-------------v-----------v-----------+
                    |          API Gateway (FastAPI)            |
                    |  Python backend on Azure Container Apps   |
                    +----+----+----+----+----+-----------------+
                         |    |    |    |    |
              +----------+    |    |    |    +----------+
              |               |    |    |               |
        +-----v-----+  +-----v--+ | +--v------+ +------v------+
        |  Scanner   |  |Analyzer| | | Fixer   | | Compliance  |
        |  Agent     |  | Agent  | | | Agent   | | Agent       |
        +-----+------+  +---+----+ | +----+----+ +------+------+
              |              |     |      |              |
              |              |  +--v---+  |              |
              |              |  | Risk |  |              |
              |              |  |Profiler| |              |
              |              |  +------+  |              |
              +--------------+-----+------+--------------+
                                   |
                    +--------------v--------------+
                    |     Azure OpenAI (Foundry)   |
                    |     gpt-4.1-mini / o4-mini   |
                    +------------------------------+
```

### Deployment Architecture (Azure Container Apps)
```
Azure Container Apps Environment
├── dashboard-app          # Next.js frontend (port 3000)
├── api-gateway            # FastAPI backend (port 8000)
├── scanner-agent          # Python agent (internal)
├── analyzer-agent         # Python agent (internal)
├── fixer-agent            # Python agent (internal)
├── risk-profiler-agent    # Python agent (internal)
└── compliance-agent       # Python agent (internal)

Azure Services
├── Azure OpenAI (Foundry) # LLM inference
├── Azure Key Vault        # Secrets (API keys, tokens)
├── Azure Container Registry # Docker images
└── Azure DevOps Pipelines # CI/CD trigger
```

---

## Build Status

### PHASE 1: Core Agents (COMPLETE)

#### 1. Demo App (COMPLETE)
**Location**: `demo-app/`
- Node.js/Express banking API with **8 intentionally planted vulnerabilities**
- SQLite database with sample data (users, accounts, transfers)
- Tested and working: `npm run seed && npm start` on port 3000

**Planted Vulnerabilities:**

| # | Vulnerability | File | CWE | Expected Result |
|---|--------------|------|-----|-----------------|
| 1 | SQL Injection | routes/accounts.js | CWE-89 | CONFIRMED |
| 2 | Reflected XSS | routes/search.js | CWE-79 | CONFIRMED |
| 3 | Hardcoded API Key | config/database.js | CWE-798 | CONFIRMED |
| 4 | Missing Auth | routes/users.js (DELETE) | CWE-862 | CONFIRMED |
| 5 | IDOR | routes/transfers.js | CWE-639 | CONFIRMED |
| 6 | SQL Query (parameterized) | routes/balance.js | CWE-89 | FALSE POSITIVE |
| 7 | Weak Crypto (bcrypt) | utils/auth.js | CWE-328 | FALSE POSITIVE |
| 8 | Logging PII | middleware/logger.js | CWE-532 | CONFIRMED |

#### 2. GitHub MCP Server (COMPLETE)
**Location**: `mcp-servers/github/`
- Python MCP server with **9 tools** for GitHub API interaction
- Tests passing: 2/2

#### 3. Scanner Agent (COMPLETE)
**Location**: `agents/scanner/`
- Reads files from GitHub via MCP tools, sends to Azure OpenAI for security analysis
- Last test: Detected 6 of 8 vulnerabilities correctly

#### 4. Analyzer Agent (COMPLETE)
**Location**: `agents/analyzer/`
- Takes Scanner findings + source code, reasons about exploitability
- Outputs: confirmed/false_positive verdict, exploitability score (0-100)
- Last test: All 6 findings correctly analyzed as CONFIRMED (scores 80-95)

#### 5. Fixer Agent (COMPLETE)
**Location**: `agents/fixer/`
- For each confirmed finding: reads source, generates LLM fix, creates branch, commits, creates draft PR
- Last test: 6/6 fixed, 6 draft PRs created (#1-#6)

#### 6. Compliance Agent (COMPLETE)
**Location**: `agents/compliance/`
- Maps findings to PCI-DSS 4.0 controls, generates JSON + Markdown reports
- Last test: 6 findings mapped to 15 PCI-DSS requirements, risk: CRITICAL

#### 7. Azure DevOps Pipeline (COMPLETE)
**Location**: `azure-pipelines.yml` + `run_pipeline.py`
- 5-stage pipeline: Setup -> Scanner -> Analyzer -> Fixer -> Compliance
- Local orchestrator: `python run_pipeline.py`

---

### PHASE 2: Product-Grade Platform (COMPLETE)

#### 8. API Gateway (COMPLETE)
**Location**: `api/`
- **Tech**: FastAPI (Python), async subprocess agent orchestration
- **Endpoints**: 7 REST endpoints (POST/GET scans, findings, compliance, risk-profile, health)
- **Pattern**: BackgroundTasks runs pipeline, in-memory ScanStore, per-scan report dirs
- **Tested**: All endpoints verified with real pipeline execution

#### 9. Dashboard (COMPLETE)
**Location**: `dashboard/`
- **Tech**: Next.js 16 (React, TypeScript, Tailwind CSS, Recharts)
- **Pages**: Scan list, scan detail, findings table, risk profile, compliance report
- **Design**: Dark theme (#0a0a0f), enterprise-grade, data-dense (Snyk/Datadog style)
- **Features**: Real-time polling (3s), pipeline status visualization, severity/verdict filters
- **Build**: TypeScript compiles clean, standalone output for Docker

#### 10. Risk Profiler Agent (COMPLETE)
**Location**: `agents/risk-profiler/`
- **Input**: Scanner + Analyzer + Fixer outputs
- **Output**: Risk score (0-100), OWASP Top 10 breakdown, attack surface analysis
- **Same pattern as other agents**: config.py, prompts.py, llm_engine.py, risk_profiler.py

#### 11. Docker Configuration (COMPLETE)
- `api/Dockerfile` - Python 3.12-slim, all agent deps, uvicorn
- `dashboard/Dockerfile` - Node 20-alpine, multi-stage build, standalone output
- `docker-compose.yml` - API (8000) + Dashboard (3000), healthcheck, shared volumes

#### 12. README (PENDING)
- Professional README.md with architecture diagram, screenshots, quick start

#### 13. Demo Video (PENDING)
- 2 minutes max on YouTube/Vimeo
- Shows: Dashboard triggering scan -> pipeline running -> findings -> fixes -> compliance report

---

## Build Priority Order

| # | Component | Status | Judge Impact | Effort |
|---|-----------|--------|-------------|--------|
| 1 | ~~GitHub MCP Server~~ | DONE | - | - |
| 2 | ~~Scanner Agent~~ | DONE | - | - |
| 3 | ~~Analyzer Agent~~ | DONE | - | - |
| 4 | ~~Fixer Agent~~ | DONE | - | - |
| 5 | ~~Compliance Agent~~ | DONE | - | - |
| 6 | ~~Azure DevOps Pipeline~~ | DONE | - | - |
| **7** | ~~API Gateway (FastAPI)~~ | DONE | High | - |
| **8** | ~~Dashboard (Next.js)~~ | DONE | Very High (20% UX) | - |
| **9** | ~~Risk Profiler Agent~~ | DONE | Medium (innovation) | - |
| **10** | **Container Apps Deploy** | PENDING | High (Azure Integration) | ~3h |
| **11** | **README** | PENDING | High (first impression) | ~1h |
| **12** | **Demo Video** | PENDING | Critical (required) | ~2h |

---

## Technical Details

### Azure OpenAI (Foundry)
- **Endpoint**: `https://devsecops-guardian-hackaton-etec.services.ai.azure.com/`
- **API Key**: In agents/*/.env (DO NOT COMMIT)
- **Project**: `devsecops-guardian-hackaton-etech`
- **Deployed models**: `gpt-4.1-mini` (practice, cheap), `o4-mini` (final video, better quality)
- **API Version**: `2024-12-01-preview`

### GitHub Token
- **Token**: Fine-grained PAT in .env files
- **Scopes**: Contents (R/W), Pull Requests (R/W), Metadata (Read)
- **Name**: `devsecops-guardian-hackathon`

### Environment Files (.env) - ALL in .gitignore
- `mcp-servers/github/.env` - GITHUB_TOKEN
- `agents/scanner/.env` - AZURE_OPENAI_* + GITHUB_TOKEN
- `agents/analyzer/.env` - AZURE_OPENAI_* + GITHUB_TOKEN
- `agents/fixer/.env` - AZURE_OPENAI_* + GITHUB_TOKEN
- `agents/compliance/.env` - AZURE_OPENAI_* + GITHUB_TOKEN
- `agents/risk-profiler/.env` - AZURE_OPENAI_* + GITHUB_TOKEN
- `api/.env` - AZURE_OPENAI_* + GITHUB_TOKEN
- `dashboard/.env.local` - NEXT_PUBLIC_API_URL

### Key Dependencies
- **Python 3.12** (installed on machine)
- **Node.js 20+** (for demo-app and dashboard)
- `httpx` - async HTTP client for GitHub + Azure OpenAI APIs
- `python-dotenv` - .env loading
- `mcp[cli]` - MCP server framework (FastMCP)
- `pydantic` - input validation
- `fastapi` + `uvicorn` - API gateway (Phase 2)
- `next` + `react` + `tailwindcss` - Dashboard (Phase 2)

---

## Repository Structure
```
devsecops-guardian/
├── demo-app/                    # Vulnerable banking API (Node.js)
│   ├── config/database.js       # VULN: Hardcoded secrets
│   ├── middleware/               # auth.js, logger.js (PII logging)
│   ├── routes/                  # accounts, search, transfers, users, balance
│   ├── utils/auth.js            # bcrypt (false positive)
│   ├── seed.js, server.js, package.json
│
├── mcp-servers/
│   └── github/                  # GitHub MCP Server (9 tools)
│       ├── server.py, test_tools.py, pyproject.toml
│
├── agents/
│   ├── scanner/                 # Scanner Agent
│   ├── analyzer/                # Analyzer Agent
│   ├── fixer/                   # Fixer Agent
│   ├── compliance/              # Compliance Agent
│   └── risk-profiler/           # Risk Profiler Agent (COMPLETE)
│
├── api/                         # FastAPI backend (COMPLETE)
│   ├── main.py                  # FastAPI app + routes
│   ├── config.py, schemas.py    # Config + Pydantic models
│   ├── models.py, pipeline.py   # ScanStore + agent orchestration
│   ├── routers/                 # health, scans, findings, compliance, risk_profile
│   ├── requirements.txt
│   └── Dockerfile
│
├── dashboard/                   # Next.js frontend (COMPLETE)
│   ├── app/                     # Next.js App Router pages
│   ├── components/              # React components (layout, scans, findings, risk)
│   ├── lib/                     # API client, utils, types
│   ├── package.json
│   └── Dockerfile
│
├── infra/                       # Azure deployment (PENDING)
│   ├── main.bicep               # Azure Container Apps infra
│   └── deploy.sh                # Deployment script
│
├── azure-pipelines.yml          # Azure DevOps pipeline (5 stages)
├── run_pipeline.py              # Local pipeline orchestrator
├── .gitignore
├── README.md                    # Professional README (PENDING)
└── PROJECT_STATUS.md            # THIS FILE
```

---

## Architecture Decisions

1. **Python for agents, TypeScript for dashboard** - Each in its best language
2. **FastAPI as API Gateway** - Agents are Python, FastAPI is natural fit + fast
3. **Next.js for dashboard** - React ecosystem, SSR, what hackathon winners use
4. **Azure Container Apps** - Simpler than AKS, perfect for microservices, strong Azure integration
5. **Azure DevOps Pipelines over GitHub Actions** - billing concerns ($5K incident), Azure integration points
6. **gpt-4.1-mini for practice, o4-mini for final** - cost optimization
7. **Smart scan strategy** for large repos: Context Map -> Grouped Scan -> Deduplicate
8. **MCP Server as shared layer** - all agents use same GitHub MCP tools
9. **Draft PRs always** - human-in-the-loop for compliance (regulators need human approval)
10. **Monorepo** - single repo, separate deployments per container (hackathon rules: one repo URL)
11. **API-first architecture** - dashboard calls API, agents behind API, like a real product

---

## Blueprint Document
Full hackathon blueprint is at: `/mnt/project/DevSecOps_Guardian_Hackathon_Blueprint.docx`
Contains: problem statement, architecture, demo flow, competitive analysis, build plan, costs.

---

*Last updated: February 17, 2026 ~11:30 PM EST*
