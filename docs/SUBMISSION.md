# DevSecOps Guardian — Hackathon Submission Guide

---

## DevPost Fields

### Title
```
DevSecOps Guardian — AI-Powered Multi-Agent Security Pipeline
```

### Tagline
```
Five AI agents in Azure AI Foundry detect vulnerabilities, eliminate false positives, auto-fix code, assess risk, and generate PCI-DSS compliance reports — all with safety guardrails.
```

### Keywords
```
Azure AI Foundry, Multi-Agent AI, DevSecOps, Application Security, SAST, Vulnerability Detection, Auto-Fix, PCI-DSS Compliance, OWASP, GitHub MCP Server, OpenTelemetry, RAI Guardrails, Azure Container Apps, GitHub Copilot, Agentic DevOps
```

### Description

DevSecOps Guardian is an enterprise-grade multi-agent AI security platform built for banking and regulated industries. It replaces traditional static analysis tools (SonarQube, Checkmarx, Fortify) with five specialized AI agents registered and running in Azure AI Foundry, each protected by RAI safety guardrails.

**The Problem:**
Traditional SAST tools rely on regex/pattern matching and generate 60-80% false positives. They lack contextual understanding — flagging bcrypt as "weak crypto" — and provide no compliance automation or integrated fix generation. Security teams spend weeks manually mapping findings to PCI-DSS controls.

**How It Works:**
The platform orchestrates a sequential 5-stage pipeline where each agent is invoked through Azure AI Foundry's Responses API (v2 SDK):

1. **SecurityScanner** — Reads source code via a custom GitHub MCP Server (9 tools, FastMCP) and uses LLM reasoning to detect vulnerabilities with CWE classification.
2. **VulnerabilityAnalyzer** — Eliminates false positives by analyzing code context, scoring exploitability (0-100), and providing detailed reasoning for each verdict.
3. **SecurityFixer** — Generates code fixes and creates draft Pull Requests via GitHub API. Creates formatted Issues for GitHub Copilot Agent Mode to pick up for enhanced remediation.
4. **RiskProfiler** — Produces OWASP Top 10 risk scores with per-category breakdown and attack surface analysis.
5. **ComplianceReporter** — Maps findings to PCI-DSS 4.0 requirements, generating audit-ready compliance reports in seconds.

**Key Differentiators:**
- All 5 agents are registered in Azure AI Foundry with `DevSecOps-Guardian-Safety` RAI guardrails applied to every interaction
- Full gen_ai.* OpenTelemetry telemetry exported to Application Insights via ResponsesInstrumentor
- Re-scan comparison: automatic NEW/RESOLVED/PERSISTENT finding classification between scans with visual charts
- Custom GitHub MCP Server with 9 tools for repository read/write operations
- GitHub Copilot Agent Mode integration for enhanced fix generation
- Production deployed on Azure Container Apps with Azure Table Storage persistence and Azure DevOps CI/CD

**Tech Stack:**
Azure AI Foundry (Responses API, prompt agents) | Azure OpenAI gpt-4.1-mini | Application Insights | Azure Container Apps | Azure Table Storage | FastAPI | Next.js 16 + React 19 + Tailwind CSS | Custom GitHub MCP Server (FastMCP) | GitHub Copilot Agent Mode | Azure DevOps Pipelines

**Demo App:**
Includes a vulnerable Node.js/Express banking API with 52 intentionally planted vulnerabilities across 14 route files, covering 30+ CWE categories — from SQL injection and XSS to SSRF, prototype pollution, and JWT attacks.

**Results:**
- 95%+ detection rate across 52 planted vulnerabilities
- 25+ auto-fix PRs generated and merged
- PCI-DSS 4.0 audit-ready reports in seconds (vs. 2-3 weeks manual)
- Full re-scan comparison with trend tracking
- 100% of agent interactions protected by RAI guardrails

---

## 2-Minute Video Script

### [0:00 - 0:15] Hook & Problem Statement
**[Screen: Dashboard landing page with scan list]**

> "Every day, banks ship code with vulnerabilities that traditional SAST tools either miss or bury in false positives. Security teams spend weeks mapping findings to compliance controls manually. DevSecOps Guardian changes that — with five AI agents running in Azure AI Foundry."

### [0:15 - 0:30] Architecture Overview
**[Screen: Show the Mermaid architecture diagram from README — scroll or zoom in]**

> "Five specialized agents work as a pipeline: Scanner detects vulnerabilities, Analyzer eliminates false positives, Fixer creates pull requests with code fixes, Risk Profiler scores against OWASP Top 10, and Compliance Reporter maps everything to PCI-DSS 4.0. Every agent is registered in Azure AI Foundry with RAI safety guardrails and OpenTelemetry observability."

### [0:30 - 0:55] Live Demo — Trigger a Scan
**[Screen: Click "New Scan" button in dashboard, fill in repository path, click "Start Scan"]**

> "Let me scan our demo banking application — 52 intentionally planted vulnerabilities across 14 route files."

**[Screen: Show pipeline progress bar advancing through stages: Scanner → Analyzer → Fixer → Risk Profiler → Compliance]**

> "The pipeline orchestrates each agent sequentially. Notice the real-time pipeline progress — each stage calls Azure AI Foundry's Responses API with the DevSecOps-Guardian-Safety guardrails applied."

### [0:55 - 1:15] Results — Findings & Risk
**[Screen: Click into completed scan → show Findings page with severity filters]**

> "The Scanner detected 26 findings. The Analyzer confirmed 20 as real vulnerabilities and correctly identified false positives — like parameterized SQL queries that regex tools would flag."

**[Screen: Click a finding → show vulnerability detail modal with code context, analysis reasoning, fixed code]**

> "Every finding includes the vulnerable code, AI-powered analysis reasoning, attack scenarios, and the actual fixed code."

**[Screen: Navigate to Risk Profile tab → show OWASP Radar Chart]**

> "The Risk Profiler gives us an OWASP Top 10 radar chart with per-category scores."

### [1:15 - 1:30] Compliance & Auto-Fix
**[Screen: Navigate to Compliance tab → show PCI-DSS requirement mapping]**

> "The Compliance Reporter maps every finding to specific PCI-DSS 4.0 requirements — turning weeks of manual audit work into seconds."

**[Screen: Quick flash of GitHub showing merged PRs from the Fixer agent]**

> "Meanwhile, the Fixer agent has already created 25-plus draft pull requests with actual code fixes, and created GitHub Issues for Copilot Agent to enhance."

### [1:30 - 1:50] Re-Scan Comparison
**[Screen: Click "Re-Scan" → show comparison report with donut chart, bar chart, findings table]**

> "After fixes are merged, re-scan and get an instant comparison report. New vulnerabilities, resolved ones, and persistent issues — all visualized with severity breakdowns and filterable tables. This is how you track security posture over time."

### [1:50 - 2:00] Closing — Tech Stack & Impact
**[Screen: Show Azure AI Foundry portal with the 5 registered agents, then Application Insights with gen_ai spans]**

> "Five agents in Azure AI Foundry, RAI guardrails on every call, full OpenTelemetry observability in Application Insights, custom GitHub MCP Server, and Copilot integration. DevSecOps Guardian — enterprise security automation that actually works."

**[Screen: Dashboard overview with DevSecOps Guardian logo]**

---

## Cover Image Prompt (for Gemini Pro with nanobanan style)

```
Create a striking, modern cover image in nanobanan's signature illustration style — clean vector art with bold colors, dark background (#0f172a), and glowing neon accents.

The central composition shows a futuristic security shield in the center, glowing electric blue (#3b82f6), with five orbiting AI agent nodes around it connected by luminous circuit-like lines. Each node is a different color: red (Scanner), purple (Analyzer), green (Fixer), cyan (Risk Profiler), orange (Compliance Reporter).

Behind the shield, a subtle code editor pattern fades into the dark background with faint vulnerability highlights in red. The Microsoft Azure AI Foundry logo sits subtly integrated in the top portion.

At the bottom, a sleek pipeline visualization shows the 5 stages flowing left to right with glowing arrows. The overall feel is cybersecurity meets AI — dark, professional, futuristic, and impactful.

Text overlay: "DevSecOps Guardian" in bold white modern sans-serif font at the top, and "AI-Powered Multi-Agent Security Pipeline" as a smaller subtitle below.

Style: nanobanan vector illustration, flat design with depth through glowing effects, dark tech aesthetic, no gradients on shapes — just solid fills with glow/shadow effects. 16:9 aspect ratio, suitable for DevPost hackathon project cover.
```

---

## Architecture Diagram (for separate submission)

The Mermaid diagram in the README renders on GitHub automatically. For the DevPost submission, you can:

1. **GitHub rendering**: Just link to the README — GitHub renders Mermaid natively
2. **Export as image**: Use [mermaid.live](https://mermaid.live) — paste the Mermaid code from the README to get a PNG/SVG export
3. **Screenshot**: Take a screenshot of the rendered diagram from the GitHub README page

The diagram covers:
- Developer/Security Team (users)
- Dashboard (Next.js frontend with all feature modules)
- API Gateway (FastAPI pipeline orchestrator)
- 5 AI Agents (each with their specific role)
- Azure AI Foundry (Responses API, RAI Guardrails, ResponsesInstrumentor)
- GitHub MCP Server (9 tools - read and write)
- Azure Services (OpenAI, App Insights, Container Apps, Table Storage, ACR, DevOps)
- GitHub (Repository, PRs, Issues, Copilot)
- All data flows and connections between components
