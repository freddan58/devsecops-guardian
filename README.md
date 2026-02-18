<p align="center">
  <img src="https://img.shields.io/badge/Microsoft%20AI%20Dev%20Days-2026-blue?style=for-the-badge&logo=microsoft" alt="Microsoft AI Dev Days 2026"/>
  <img src="https://img.shields.io/badge/Track-Agentic%20DevOps-purple?style=for-the-badge" alt="Agentic DevOps"/>
  <img src="https://img.shields.io/badge/Azure%20OpenAI-Foundry-orange?style=for-the-badge&logo=microsoftazure" alt="Azure OpenAI"/>
</p>

# DevSecOps Guardian

**Enterprise-grade multi-agent AI security platform for banking and regulated industries.**

Five specialized AI agents replace traditional SAST tools (SonarQube, Checkmarx, Fortify) with LLM-powered reasoning — from vulnerability detection through auto-fix PRs to PCI-DSS 4.0 compliance reports, fully automated.

<p align="center">
  <a href="https://ca-dashboard.agreeablesand-6566841b.eastus.azurecontainerapps.io">Live Demo</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#agents">Agents</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#demo-video">Demo Video</a>
</p>

---

## The Problem

Banks and financial institutions face a critical gap in application security:

- **Traditional SAST tools** rely on regex/pattern matching — they generate 60-80% false positives
- **No contextual reasoning** — tools flag `bcrypt` hashing as "weak crypto" without understanding it's the right choice
- **No compliance automation** — security teams manually map CWEs to PCI-DSS controls for every audit
- **No integrated fix generation** — developers receive findings but must research and implement fixes themselves
- **Fragmented toolchain** — separate tools for scanning, analysis, fixing, and compliance with no pipeline

## The Solution

DevSecOps Guardian is a **multi-agent AI pipeline** where each agent specializes in one security task, passing structured outputs to the next:

```
Code Push → Scanner → Analyzer → Fixer → Risk Profiler → Compliance
             │           │          │          │              │
             │           │          │          │              └── PCI-DSS 4.0 audit report
             │           │          │          └── OWASP Top 10 risk score
             │           │          └── Draft PRs with security fixes
             │           └── False positive elimination (exploitability 0-100)
             └── AI-detected vulnerabilities (CWE-classified)
```

---

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │        Dashboard (Next.js / React)       │
                    │   https://ca-dashboard.....azurecontainerapps.io  │
                    └────────────────────┬─────────────────────┘
                                         │ REST API
                    ┌────────────────────▼─────────────────────┐
                    │        API Gateway (FastAPI / Python)     │
                    │   https://ca-api-gateway.....azurecontainerapps.io│
                    └──┬─────┬─────┬─────┬─────┬───────────────┘
                       │     │     │     │     │
              ┌────────┘     │     │     │     └────────┐
              ▼              ▼     │     ▼              ▼
        ┌──────────┐  ┌──────────┐ │ ┌──────────┐ ┌──────────┐
        │ Scanner  │  │ Analyzer │ │ │  Fixer   │ │Compliance│
        │  Agent   │  │  Agent   │ │ │  Agent   │ │  Agent   │
        └────┬─────┘  └────┬─────┘ │ └────┬─────┘ └────┬─────┘
             │              │       │      │             │
             │              │  ┌────▼────┐ │             │
             │              │  │  Risk   │ │             │
             │              │  │Profiler │ │             │
             │              │  └─────────┘ │             │
             └──────────────┴──────┬───────┴─────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │    Azure OpenAI (Foundry)    │
                    │     gpt-4.1-mini / o4-mini   │
                    └──────────────────────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │   GitHub MCP Server (9 tools)│
                    │   Read files, create PRs     │
                    └──────────────────────────────┘
```

### Azure Services Used

| Service | Purpose |
|---------|---------|
| **Azure OpenAI (Foundry)** | LLM inference for all 5 agents (gpt-4.1-mini, o4-mini) |
| **Azure Container Apps** | Serverless hosting for API + Dashboard (scale-to-zero) |
| **Azure Container Registry** | Docker image storage |
| **Azure DevOps Pipelines** | CI/CD with 8-stage pipeline (agents + build + deploy) |
| **Log Analytics Workspace** | Container monitoring and diagnostics |

---

## Agents

### Agent 1: Scanner
Reads source code from GitHub via MCP tools and performs LLM-based security analysis. Unlike regex scanners, it understands code semantics — detecting business logic flaws, not just pattern matches.

**Output**: List of findings with CWE classification, severity, affected file/line, and evidence.

### Agent 2: Analyzer
Takes Scanner findings plus full source code context to determine exploitability. Eliminates false positives with contextual reasoning — understands that `bcrypt` is secure hashing, parameterized queries prevent SQLi, etc.

**Output**: Confirmed/false-positive verdict per finding with exploitability score (0-100).

### Agent 3: Fixer
For each confirmed vulnerability: reads the vulnerable code, generates an LLM-powered fix, creates a feature branch, commits the fix, and opens a draft PR on GitHub. Human-in-the-loop by design — draft PRs require manual review.

**Output**: Draft pull requests with security fixes on GitHub.

### Agent 4: Risk Profiler
Aggregates all pipeline outputs to generate a risk profile per service/API. Maps findings to OWASP Top 10 categories, calculates attack surface exposure, and produces an overall risk score (0-100).

**Output**: OWASP Top 10 breakdown, risk score, attack surface analysis.

### Agent 5: Compliance
Maps confirmed vulnerabilities to PCI-DSS 4.0 controls using CWE-to-requirement mapping. Generates audit-ready reports with evidence chains linking each finding to specific compliance requirements.

**Output**: PCI-DSS 4.0 compliance report (JSON + Markdown) with control gap analysis.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check + agent availability status |
| `POST` | `/api/scans` | Trigger new security scan (async, returns 202) |
| `GET` | `/api/scans` | List all scans with status |
| `GET` | `/api/scans/{id}` | Full scan detail with all agent outputs |
| `GET` | `/api/scans/{id}/findings` | Merged findings (analyzer verdicts + fixer status) |
| `GET` | `/api/scans/{id}/compliance` | PCI-DSS 4.0 compliance assessment |
| `GET` | `/api/scans/{id}/risk-profile` | OWASP Top 10 risk profile |

---

## Quick Start

### Prerequisites
- Python 3.12+
- Node.js 20+
- Docker & Docker Compose
- Azure OpenAI API key
- GitHub PAT (Contents R/W, Pull Requests R/W)

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/freddan58/devsecops-guardian.git
cd devsecops-guardian

# Set environment variables
export AZURE_OPENAI_ENDPOINT="your-endpoint"
export AZURE_OPENAI_API_KEY="your-key"
export GITHUB_TOKEN="your-github-pat"

# Start all services
docker compose up --build

# Dashboard: http://localhost:3000
# API:       http://localhost:8000/api/health
```

### Option 2: Local Development

```bash
# 1. Start the API Gateway
cd api
pip install -r requirements.txt
cp .env.example .env  # Fill in your credentials
uvicorn main:app --reload --port 8000

# 2. Start the Dashboard (separate terminal)
cd dashboard
npm install
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local
npm run dev

# Dashboard: http://localhost:3000
```

### Option 3: Run Agents Standalone

```bash
# Run the full pipeline locally
python run_pipeline.py

# Or run individual agents
cd agents/scanner && python scanner.py --path demo-app
cd agents/analyzer && python analyzer.py --input ../scanner/reports/scanner-output.json
cd agents/fixer && python fixer.py --input ../analyzer/reports/analyzer-output.json
cd agents/risk-profiler && python risk_profiler.py --scanner ... --analyzer ... --fixer ...
cd agents/compliance && python compliance.py --scanner ... --analyzer ... --fixer ...
```

---

## Demo App

A vulnerable Node.js/Express banking API is included for testing (`demo-app/`). It contains **8 intentionally planted vulnerabilities**:

| # | Vulnerability | CWE | Expected Verdict |
|---|--------------|-----|------------------|
| 1 | SQL Injection in account lookup | CWE-89 | CONFIRMED |
| 2 | Reflected XSS in search | CWE-79 | CONFIRMED |
| 3 | Hardcoded API key in config | CWE-798 | CONFIRMED |
| 4 | Missing auth on user deletion | CWE-862 | CONFIRMED |
| 5 | IDOR in transfer endpoint | CWE-639 | CONFIRMED |
| 6 | SQL query (parameterized) | CWE-89 | FALSE POSITIVE |
| 7 | Bcrypt hashing (secure) | CWE-328 | FALSE POSITIVE |
| 8 | PII in server logs | CWE-532 | CONFIRMED |

The Analyzer agent correctly identifies items 6 and 7 as false positives through contextual reasoning.

---

## CI/CD Pipeline (Azure DevOps)

The pipeline (`azure-pipelines.yml`) has **8 stages** split into two tracks:

**Security Scan Track** (triggers on `demo-app/` changes):
1. **Setup** — Install Python dependencies
2. **Scanner** — AI-powered code security scan
3. **Analyzer** — False positive elimination
4. **Fixer** — Auto-generate security fix PRs
5. **Risk Profiler** — OWASP Top 10 risk assessment
6. **Compliance** — PCI-DSS 4.0 audit report

**CI/CD Deploy Track** (triggers on `api/`, `dashboard/`, `agents/` changes):
7. **Build** — Docker build + push to Azure Container Registry
8. **Deploy** — Update Azure Container Apps

All 8 stages produce downloadable artifacts in the Azure DevOps Artifacts tab.

---

## Competitive Differentiation

| Capability | GitHub CodeQL | Dependabot | **DevSecOps Guardian** |
|-----------|---------------|------------|------------------------|
| Detection method | Predefined rules | CVE database | **LLM reasoning over code context** |
| False positive handling | Manual tuning | N/A | **Dedicated AI agent (exploitability 0-100)** |
| Auto-fix | Limited languages | Version bumps | **Full code rewrites as draft PRs** |
| Risk profiling | No | No | **OWASP Top 10 risk score per service** |
| Compliance reporting | No | No | **PCI-DSS 4.0 audit-ready reports** |
| Multi-agent orchestration | Single tool | Single bot | **5 specialized agents in pipeline** |
| Business logic understanding | Pattern matching | None | **LLM understands domain context** |

---

## Project Structure

```
devsecops-guardian/
├── agents/
│   ├── scanner/          # Agent 1: LLM-based code scanner
│   ├── analyzer/         # Agent 2: False positive eliminator
│   ├── fixer/            # Agent 3: Auto-fix PR generator
│   ├── risk-profiler/    # Agent 4: OWASP risk profiler
│   └── compliance/       # Agent 5: PCI-DSS compliance auditor
├── api/                  # FastAPI backend (gateway + orchestrator)
├── dashboard/            # Next.js frontend (React, TypeScript, Tailwind)
├── demo-app/             # Vulnerable banking API for testing
├── mcp-servers/
│   └── github/           # GitHub MCP Server (9 tools)
├── infra/                # Azure deployment scripts
├── azure-pipelines.yml   # 8-stage CI/CD pipeline
├── docker-compose.yml    # Local development setup
└── run_pipeline.py       # Standalone pipeline orchestrator
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **LLM** | Azure OpenAI Foundry (gpt-4.1-mini, o4-mini) |
| **Agents** | Python 3.12, httpx, MCP (Model Context Protocol) |
| **API** | FastAPI, uvicorn, Pydantic |
| **Dashboard** | Next.js 16, React, TypeScript, Tailwind CSS, Recharts |
| **Infrastructure** | Azure Container Apps, Azure Container Registry |
| **CI/CD** | Azure DevOps Pipelines (YAML) |
| **Code Integration** | GitHub MCP Server (9 tools for file read, PR creation) |

---

## Live Demo

- **Dashboard**: [https://ca-dashboard.agreeablesand-6566841b.eastus.azurecontainerapps.io](https://ca-dashboard.agreeablesand-6566841b.eastus.azurecontainerapps.io)
- **API Health**: [https://ca-api-gateway.agreeablesand-6566841b.eastus.azurecontainerapps.io/api/health](https://ca-api-gateway.agreeablesand-6566841b.eastus.azurecontainerapps.io/api/health)

---

## Team

**Soluciones Etech Corp** — Freddy Urbano (furbano@soluetech.com)

---

## License

MIT

---

<p align="center">
  Built for <strong>Microsoft AI Dev Days Hackathon 2026</strong> &mdash; Agentic DevOps Track
</p>
