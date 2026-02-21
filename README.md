<p align="center">
  <img src="https://img.shields.io/badge/Microsoft%20AI%20Dev%20Days-2026-blue?style=for-the-badge&logo=microsoft" alt="Microsoft AI Dev Days 2026"/>
  <img src="https://img.shields.io/badge/Track-Agentic%20DevOps-purple?style=for-the-badge" alt="Agentic DevOps"/>
  <img src="https://img.shields.io/badge/Azure%20OpenAI-Foundry-orange?style=for-the-badge&logo=microsoftazure" alt="Azure OpenAI"/>
  <img src="https://img.shields.io/badge/Agent%20Framework-Orchestration-green?style=for-the-badge" alt="Agent Framework"/>
</p>

# DevSecOps Guardian

**Enterprise-grade multi-agent AI security platform for banking and regulated industries.**

Five specialized AI agents replace traditional SAST tools (SonarQube, Checkmarx, Fortify) with LLM-powered reasoning — from vulnerability detection through auto-fix PRs to PCI-DSS 4.0 compliance reports, fully automated.

<p align="center">
  <a href="https://ca-dashboard.agreeablesand-6566841b.eastus.azurecontainerapps.io">Live Demo</a> &bull;
  <a href="#hero-technologies">Hero Technologies</a> &bull;
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
Code Push --> Scanner --> Analyzer --> Fixer --> Risk Profiler --> Compliance
               |            |           |            |               |
               |            |           |            |               +-- PCI-DSS 4.0 audit report
               |            |           |            +-- OWASP Top 10 risk score
               |            |           +-- Draft PRs with security fixes
               |            +-- False positive elimination (exploitability 0-100)
               +-- AI-detected vulnerabilities (CWE-classified)
```

---

## Hero Technologies

| Technology | How We Use It | Implementation |
|-----------|---------------|----------------|
| **Microsoft Foundry Agent Service** | All 5 agents registered via Responses API (`azure-ai-projects` v2 SDK) — visible in main Agents section | `agents/foundry_client.py`, `agents/register_all_agents.py` |
| **Microsoft Agent Framework** | Sequential multi-agent orchestration pipeline with `Agent` + `WorkflowBuilder` from `agent-framework` SDK | `agents/orchestrator.py` |
| **Azure MCP Server** | Custom GitHub MCP Server (9 tools) registered as native `MCPTool` in Foundry for agent-tool integration | `mcp-servers/github/server.py`, `mcp-servers/github/foundry_adapter.py` |
| **GitHub Copilot Agent Mode** | Remediation Accelerator: auto-creates GitHub Issues for Copilot Coding Agent + custom instructions | `agents/fixer/issue_creator.py`, `.github/copilot-instructions.md` |

---

## Microsoft Foundry Integration

All 5 agents are registered in Microsoft Foundry Agent Service using the **Responses API** (`azure-ai-projects` v2 SDK, `PromptAgentDefinition`). Agents appear in the main **Agents** section of the Azure AI Foundry portal (not Classic Agents):

| Agent | Kind | Model | Description |
|-------|------|-------|-------------|
| **SecurityScanner** | `prompt` | `gpt-4.1-mini` | LLM-based code vulnerability detection |
| **VulnerabilityAnalyzer** | `prompt` | `gpt-4.1-mini` | Contextual false positive elimination |
| **SecurityFixer** | `prompt` | `gpt-4.1-mini` | Automated remediation + native MCP tools |
| **RiskProfiler** | `prompt` | `gpt-4.1-mini` | OWASP Top 10 risk assessment |
| **ComplianceReporter** | `prompt` | `gpt-4.1-mini` | PCI-DSS 4.0 audit report generation |

**Foundry Endpoint**: `https://devsecops-guardian-hackaton-etec.services.ai.azure.com`

```python
# agents/foundry_client.py — Responses API (v2)
from azure.ai.projects import AIProjectClient
from azure.ai.projects.models import PromptAgentDefinition
from azure.identity import DefaultAzureCredential

client = AIProjectClient(endpoint=FOUNDRY_ENDPOINT, credential=DefaultAzureCredential())
agent = client.agents.create(
    name="SecurityScanner",
    definition=PromptAgentDefinition(model="gpt-4.1-mini", instructions="..."),
)

# Execute via Responses API
openai_client = client.get_openai_client()
response = openai_client.responses.create(...)
```

---

## Microsoft Agent Framework

Pipeline orchestration uses the **Microsoft Agent Framework** (`agent-framework` SDK) with `AzureAIClient` and `WorkflowBuilder`:

- **5 Agent instances**: Each connects to a Foundry-registered agent via `AzureAIClient` (Responses API)
- **Sequential workflow chain**: Scanner --> Analyzer --> Fixer --> Risk Profiler --> Compliance
- **State management**: Findings state passed between agents with full context
- **Native MCP tool integration**: SecurityFixer agent has GitHub MCP tools registered as native `MCPTool`
- **Human-in-the-loop**: Fixer creates Draft PRs requiring human approval before merge

```python
# agents/orchestrator.py — Microsoft Agent Framework
from agent_framework import Agent, WorkflowBuilder
from agent_framework_azure_ai import AzureAIClient

client = AzureAIClient(project_endpoint=FOUNDRY_ENDPOINT, agent_name="SecurityScanner", ...)
scanner = Agent(client=client, name="SecurityScanner")

workflow = WorkflowBuilder(start_executor=scanner, output_executors=[compliance])
workflow.add_chain([scanner, analyzer, fixer, profiler, compliance])
result = await workflow.build().run(message="Scan for vulnerabilities")
```

---

## Azure MCP Integration

Custom GitHub MCP Server with **9 tools** registered in Foundry Agent Service as a **native `MCPTool`** (Responses API):

**Read Tools** (used by Scanner + Analyzer):
- `github_read_file` — Read source code files from repositories
- `github_list_files` — Discover files to scan in repository directories
- `github_read_pr_diff` — Read PR diffs for security analysis
- `github_list_pr_files` — List files changed in Pull Requests
- `github_get_pr` — Get PR details for evidence trails

**Write Tools** (used by Fixer):
- `github_create_branch` — Create security fix branches
- `github_create_or_update_file` — Commit code fixes
- `github_create_pr` — Create draft Pull Requests with fixes
- `github_post_pr_comment` — Add vulnerability details to PRs

The MCP Server is built with **FastMCP** and exposed via HTTP adapter for Foundry integration.

---

## GitHub Copilot Agent Mode Integration

DevSecOps Guardian integrates with GitHub Copilot in two ways:

### 1. Development with Copilot Agent Mode
This project was developed using GitHub Copilot Agent Mode in VS Code, which autonomously planned, wrote, tested, and refined code across the entire codebase. Custom instructions in `.github/copilot-instructions.md` guided Copilot's security-aware coding.

### 2. Remediation Accelerator
When the Analyzer Agent confirms vulnerabilities, the system automatically:
1. Creates formatted GitHub Issues with full vulnerability context
2. Labels issues with `security`, severity level, and `copilot-fix`
3. Copilot Coding Agent picks up issues and generates enhanced fix Pull Requests
4. Human developers review and merge — maintaining human-in-the-loop compliance

This creates a powerful **Agentic DevOps loop**:
```
Scanner --> Analyzer --> Fixer (fix code) --> Issue Creator --> Copilot Agent --> PR --> Human Review --> Merge
```

---

## Architecture

```
                    +----------------------------------------------+
                    |        Dashboard (Next.js / React)            |
                    |   ca-dashboard.....azurecontainerapps.io      |
                    +---------------------+------------------------+
                                          | REST API
                    +---------------------v------------------------+
                    |        API Gateway (FastAPI / Python)          |
                    |   ca-api-gateway.....azurecontainerapps.io     |
                    +--+-----+-----+-----+-----+------------------+
                       |     |     |     |     |
              +--------+     |     |     |     +--------+
              v              v     |     v              v
        +----------+  +----------+ | +----------+ +----------+
        | Scanner  |  | Analyzer | | |  Fixer   | |Compliance|
        |  Agent   |  |  Agent   | | |  Agent   | |  Agent   |
        +----+-----+  +----+-----+ | +----+-----+ +----+-----+
             |              |       |      |             |
             |              |  +----v----+ |             |
             |              |  |  Risk   | |             |
             |              |  |Profiler | |             |
             |              |  +---------+ |             |
             +--------------+------+-------+-------------+
                                   |
                    +--------------v--------------+
                    | Microsoft Foundry Agent Svc  |
                    | (azure-ai-projects SDK)      |
                    +-----+--------------+--------+
                          |              |
              +-----------v---+  +-------v-----------+
              | Azure OpenAI  |  | GitHub MCP Server  |
              | gpt-4.1-mini  |  | (9 tools, FastMCP) |
              +---------------+  +-------------------+
```

### Azure Services Used

| Service | Purpose |
|---------|---------|
| **Azure AI Foundry** | Agent registration, management, and LLM inference |
| **Azure OpenAI** | gpt-4.1-mini for all 5 agents |
| **Azure Container Apps** | Serverless hosting for API + Dashboard (scale-to-zero) |
| **Azure Container Registry** | Docker image storage and cloud builds |
| **Azure DevOps Pipelines** | CI/CD with 8-stage pipeline (agents + build + deploy) |
| **Azure Table Storage** | Persistent scan data storage |
| **Log Analytics Workspace** | Container monitoring and diagnostics |

---

## Agents

### Agent 1: SecurityScanner
Reads source code from GitHub via MCP tools and performs LLM-based security analysis. Unlike regex scanners, it understands code semantics — detecting business logic flaws, not just pattern matches.

**Output**: List of findings with CWE classification, severity, affected file/line, and evidence.

### Agent 2: VulnerabilityAnalyzer
Takes Scanner findings plus full source code context to determine exploitability. Eliminates false positives with contextual reasoning — understands that `bcrypt` is secure hashing, parameterized queries prevent SQLi, etc.

**Output**: Confirmed/false-positive verdict per finding with exploitability score (0-100).

### Agent 3: SecurityFixer
For each confirmed vulnerability: reads the vulnerable code, generates an LLM-powered fix, creates a feature branch, commits the fix, and opens a draft PR on GitHub. Also creates GitHub Issues for Copilot Coding Agent. Human-in-the-loop by design.

**Output**: Draft pull requests with security fixes + GitHub Issues for Copilot.

### Agent 4: RiskProfiler
Aggregates all pipeline outputs to generate a risk profile per service/API. Maps findings to OWASP Top 10 categories, calculates attack surface exposure, and produces an overall risk score (0-100).

**Output**: OWASP Top 10 breakdown, risk score, attack surface analysis.

### Agent 5: ComplianceReporter
Maps confirmed vulnerabilities to PCI-DSS 4.0 controls using CWE-to-requirement mapping. Generates audit-ready reports with evidence chains linking each finding to specific compliance requirements.

**Output**: PCI-DSS 4.0 compliance report (JSON + Markdown) with control gap analysis.

---

## Results

| Metric | Value |
|--------|-------|
| **Vulnerabilities planted** | 12 (10 real + 2 false positives) |
| **Detected by Scanner** | 12/12 (100% detection rate) |
| **False positives identified** | 2/2 correctly eliminated by Analyzer |
| **Noise reduction** | 25% through contextual analysis |
| **Fix PRs generated** | Automated draft PRs for confirmed findings |
| **Compliance report** | PCI-DSS 4.0 audit-ready in seconds (vs. 2-3 weeks manual) |
| **Full evidence trail** | Detection --> Analysis --> Fix PR --> Merge --> Verification |

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
| `GET` | `/api/scans/{id}/practices` | Best practices analysis |

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

### Register Agents in Foundry

```bash
# Install SDK
pip install "azure-ai-projects>=2.0.0b3" azure-identity "agent-framework[azure-ai]"

# Register all 5 agents
cd agents
python register_all_agents.py
```

---

## Demo App

A vulnerable Node.js/Express banking API is included for testing (`demo-app/`). It contains **12 intentionally planted vulnerabilities** (10 real + 2 false positives):

| # | Vulnerability | CWE | Expected Verdict |
|---|--------------|-----|------------------|
| 1 | SQL Injection in account lookup (FIXED) | CWE-89 | CONFIRMED |
| 2 | Reflected XSS in search | CWE-79 | CONFIRMED |
| 3 | Hardcoded API key in config | CWE-798 | CONFIRMED |
| 4 | Missing auth on user deletion | CWE-862 | CONFIRMED |
| 5 | IDOR in transfer endpoint | CWE-639 | CONFIRMED |
| 6 | SQL query (parameterized) | CWE-89 | FALSE POSITIVE |
| 7 | Bcrypt hashing (secure) | CWE-328 | FALSE POSITIVE |
| 8 | PII in server logs | CWE-532 | CONFIRMED |
| 9 | Path Traversal / LFI | CWE-22 | CONFIRMED |
| 10 | SSRF in webhooks | CWE-918 | CONFIRMED |
| 11 | Prototype Pollution | CWE-1321 | CONFIRMED |
| 12 | RCE via eval/exec | CWE-502 | CONFIRMED |

The Analyzer agent correctly identifies items 6 and 7 as false positives through contextual reasoning.

---

## CI/CD Pipeline (Azure DevOps)

The pipeline (`azure-pipelines.yml`) has **8 stages** split into two tracks:

**Security Scan Track** (triggers on `demo-app/` changes):
1. **Setup** -- Install Python dependencies
2. **Scanner** -- AI-powered code security scan
3. **Analyzer** -- False positive elimination
4. **Fixer** -- Auto-generate security fix PRs
5. **Risk Profiler** -- OWASP Top 10 risk assessment
6. **Compliance** -- PCI-DSS 4.0 audit report

**CI/CD Deploy Track** (triggers on `api/`, `dashboard/`, `agents/` changes):
7. **Build** -- Docker build + push to Azure Container Registry
8. **Deploy** -- Update Azure Container Apps

---

## Competitive Differentiation

| Capability | GitHub CodeQL | Dependabot | **DevSecOps Guardian** |
|-----------|---------------|------------|------------------------|
| Detection method | Predefined rules | CVE database | **LLM reasoning over code context** |
| False positive handling | Manual tuning | N/A | **Dedicated AI agent (exploitability 0-100)** |
| Auto-fix | Limited languages | Version bumps | **Full code rewrites as draft PRs** |
| Risk profiling | No | No | **OWASP Top 10 risk score per service** |
| Compliance reporting | No | No | **PCI-DSS 4.0 audit-ready reports** |
| Multi-agent orchestration | Single tool | Single bot | **5 agents via Foundry + Agent Framework** |
| Business logic understanding | Pattern matching | None | **LLM understands domain context** |
| Copilot integration | N/A | N/A | **Auto-creates Issues for Copilot Agent** |

---

## Project Structure

```
devsecops-guardian/
|-- agents/
|   |-- scanner/              # Agent 1: LLM-based code scanner
|   |-- analyzer/             # Agent 2: False positive eliminator
|   |-- fixer/                # Agent 3: Auto-fix PR generator
|   |   +-- issue_creator.py  # Copilot Coding Agent issue creator
|   |-- risk-profiler/        # Agent 4: OWASP risk profiler
|   |-- compliance/           # Agent 5: PCI-DSS compliance auditor
|   |-- foundry_client.py     # Foundry Agent Service SDK wrapper
|   |-- register_all_agents.py # Register agents in Foundry
|   +-- orchestrator.py       # Agent Framework orchestration pipeline
|-- api/                      # FastAPI backend (gateway + pipeline runner)
|-- dashboard/                # Next.js frontend (React, TypeScript, Tailwind)
|-- demo-app/                 # Vulnerable banking API (12 planted vulns)
|-- mcp-servers/
|   +-- github/               # GitHub MCP Server (9 tools, FastMCP)
|       +-- foundry_adapter.py # HTTP adapter for Foundry integration
|-- .github/
|   +-- copilot-instructions.md # Custom instructions for Copilot Agent
|-- infra/                    # Azure deployment scripts
|-- azure-pipelines.yml       # 8-stage CI/CD pipeline
|-- docker-compose.yml        # Local development setup
+-- run_pipeline.py           # Standalone pipeline orchestrator
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Agent Service** | Microsoft Foundry Agent Service (`azure-ai-projects` v2, Responses API) |
| **Agent Framework** | Microsoft Agent Framework (`Agent`, `WorkflowBuilder`, `AzureAIClient`) |
| **LLM** | Azure OpenAI (gpt-4.1-mini) via Foundry |
| **MCP** | Custom GitHub MCP Server (FastMCP, 9 tools, registered in Foundry) |
| **Copilot** | GitHub Copilot Agent Mode (issue creator + custom instructions) |
| **API** | FastAPI, uvicorn, Pydantic |
| **Dashboard** | Next.js 16, React, TypeScript, Tailwind CSS, Recharts |
| **Infrastructure** | Azure Container Apps, Azure Container Registry, Azure Table Storage |
| **CI/CD** | Azure DevOps Pipelines (YAML, 8 stages) |

---

## Live Demo

- **Dashboard**: [https://ca-dashboard.agreeablesand-6566841b.eastus.azurecontainerapps.io](https://ca-dashboard.agreeablesand-6566841b.eastus.azurecontainerapps.io)
- **API Health**: [https://ca-api-gateway.agreeablesand-6566841b.eastus.azurecontainerapps.io/api/health](https://ca-api-gateway.agreeablesand-6566841b.eastus.azurecontainerapps.io/api/health)
- **Repository**: [https://github.com/freddan58/devsecops-guardian](https://github.com/freddan58/devsecops-guardian)

---

## Demo Video

*Coming soon*

---

## Team

**Soluciones Etech Corp** -- Freddy Urbano (furbano@soluetech.com)

---

## License

MIT

---

<p align="center">
  Built for <strong>Microsoft AI Dev Days Hackathon 2026</strong> &mdash; Agentic DevOps Track
</p>
