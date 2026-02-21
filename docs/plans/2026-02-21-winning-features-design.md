# DevSecOps Guardian — Winning Features Design

## Date: 2026-02-21
## Timeline: 24-48 hours
## Scope: Features 1-4 (Full Blueprint Implementation)

---

## 1. Overview

Transform DevSecOps Guardian from a functional pipeline into a hackathon-winning product by implementing 4 features across 3 layers: Agent modifications, API Gateway enrichment, and Dashboard frontend components.

### Features in Scope
| # | Feature | Impact | Layer |
|---|---------|--------|-------|
| 1 | Vulnerability Detail Modal (slide-over with 6 tabs) | CRITICAL — surfaces LLM reasoning | All 3 layers |
| 2 | Fix Status Resolution (granular states + fix code display) | HIGH — fixes "everything is FAILED" | API + Frontend |
| 3 | Re-Scan with History (parent_scan_id + comparison + timeline) | HIGH — shows closed-loop remediation | All 3 layers |
| 4 | Best Practices Analysis (per-finding + consolidated page) | MEDIUM — differentiator vs competitors | All 3 layers |

---

## 2. Layer 1: Agent Modifications

### 2.1 Scanner Agent (`agents/scanner/scanner.py` + `smart_scan.py`)

**Current state**: Outputs `evidence` (short snippet), `file`, `line`, `description`, `recommendation`.

**Changes**:
- Modify LLM prompt to output a `code_context` object per finding
- Store 30-line window around each vulnerability
- Include related file snippets (imports, middleware, config referenced in code)

**New output fields per finding**:
```json
{
  "code_context": {
    "file_content_snippet": "// 30 lines around the vulnerability...",
    "start_line": 5,
    "end_line": 35,
    "highlight_lines": [14, 15],
    "related_files": [
      {
        "file": "middleware/auth.js",
        "relevance": "authentication middleware",
        "snippet": "// relevant auth check code..."
      }
    ]
  }
}
```

**Implementation approach**: The Scanner already reads full file contents via `file_reader.py`. After the LLM identifies a finding at line N, extract lines max(1, N-15) to min(EOF, N+15). For related files, the LLM prompt should identify imports and middleware referenced in the finding's code context.

### 2.2 Analyzer Agent (`agents/analyzer/analyzer.py`)

**Current state**: Outputs `verdict`, `exploitability_score`, `attack_scenario`, `auth_context`, `data_sensitivity`, `confirmed_evidence`, `false_positive_reason`.

**Changes**:
- Add `analysis_reasoning` field — narrative paragraph explaining the full verdict reasoning chain
- Add `best_practices_analysis` object — root cause, violated standards, recommended patterns

**New output fields per finding**:
```json
{
  "analysis_reasoning": "The Analyzer Agent evaluated 5 contextual factors: (1) Endpoint Exposure: PUBLIC — Route /api/accounts has no authentication middleware... (2) Input Sanitization: NONE — req.query.id is used directly... [full narrative]",

  "best_practices_analysis": {
    "root_cause_pattern": "String concatenation in SQL query construction",
    "violated_standards": [
      {
        "standard": "OWASP Secure Coding Guidelines",
        "section": "Input Validation",
        "rule": "Never construct SQL queries using string concatenation with user input"
      }
    ],
    "anti_pattern_detected": "Template literal SQL construction",
    "recommended_pattern": {
      "name": "Parameterized Query Pattern",
      "description": "Separate SQL structure from data values",
      "example_code": "db.execute('SELECT * FROM accounts WHERE id = ?', [id])",
      "framework": "Express.js + mysql2"
    },
    "related_vulnerabilities": [
      "Command Injection (CWE-78)", "LDAP Injection (CWE-90)"
    ],
    "developer_education": "The core issue is mixing code and data..."
  }
}
```

**Implementation approach**: Extend the LLM prompt in the analyzer to request these two additional output sections. The existing structured fields (`attack_scenario`, `auth_context`, etc.) remain unchanged — they complement the narrative reasoning.

### 2.3 Fixer Agent (`agents/fixer/fixer.py`)

**Current state**: Outputs `status` (SUCCESS/FAILED/DRY_RUN/PARTIAL), `fix_summary`, `branch`, `pr_number`, `pr_url`, `error`.

**Changes**:
- Store `fixed_code` — the full generated fix code before committing to GitHub
- Store `fix_error` explicitly when PR creation fails (currently may be in `error` field)
- Add `fix_explanation` — rationale for why this specific fix approach was chosen
- **New status**: `FIX_GENERATED` — when fix code was created but PR creation failed

**New output fields per fix**:
```json
{
  "fixed_code": "router.get('/api/accounts', (req, res) => {\n  const id = req.query.id;\n  if (!id || isNaN(id)) {\n    return res.status(400).json({ error: 'Invalid account ID' });\n  }\n  const query = 'SELECT * FROM accounts WHERE id = ?';\n  db.query(query, [id], (err, results) => {\n    if (err) return res.status(500).json({error});\n    res.json(results);\n  });\n});",
  "fix_explanation": "Parameterized queries separate SQL structure from data, preventing injection regardless of input content. Added input validation as defense-in-depth.",
  "status": "FIX_GENERATED"
}
```

**Implementation approach**: Before the GitHub commit step, serialize the generated fix code to the output JSON. If the PR creation step fails, set status to `FIX_GENERATED` instead of `FAILED` (since the AI successfully generated the fix). Only use `FAILED` when the fix code generation itself fails.

---

## 3. Layer 2: API Gateway Changes

### 3.1 Schema Extensions (`api/schemas.py`)

**New/modified Pydantic models**:

```python
class CodeContext(BaseModel):
    file_content_snippet: str = ""
    start_line: int = 0
    end_line: int = 0
    highlight_lines: list[int] = []
    related_files: list[dict] = []  # {file, relevance, snippet}

class ComplianceMapping(BaseModel):
    requirement: str = ""
    description: str = ""
    status: str = "UNKNOWN"  # NON_COMPLIANT | PARTIALLY_COMPLIANT | COMPLIANT
    remediation: str = ""

class BestPracticesAnalysis(BaseModel):
    root_cause_pattern: str = ""
    violated_standards: list[dict] = []
    anti_pattern_detected: str = ""
    recommended_pattern: dict = {}
    related_vulnerabilities: list[str] = []
    developer_education: str = ""

class Finding(BaseModel):
    # Existing fields (unchanged)
    scan_id: str
    anlz_id: Optional[str] = None
    file: str
    line: int = 0
    vulnerability: str
    cwe: str = ""
    severity: str = "MEDIUM"
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    verdict: str = "CONFIRMED"
    exploitability_score: int = 0
    fix_status: str = "PENDING"
    fix_summary: Optional[str] = None
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None

    # NEW fields — Feature 1 (Modal)
    code_context: Optional[CodeContext] = None
    analysis_reasoning: Optional[str] = None
    fixed_code: Optional[str] = None
    fix_explanation: Optional[str] = None
    fix_error: Optional[str] = None
    compliance_mappings: list[ComplianceMapping] = []
    best_practices_analysis: Optional[BestPracticesAnalysis] = None

    # NEW fields — Feature 3 (Re-Scan)
    status_change: Optional[str] = None  # RESOLVED | PERSISTENT | NEW | REGRESSION
    first_detected_scan: Optional[str] = None

class ScanRequest(BaseModel):
    repository_path: str = "demo-app"
    ref: Optional[str] = None
    dry_run: bool = False
    parent_scan_id: Optional[str] = None  # NEW — Feature 3

class ScanComparison(BaseModel):
    new_findings: int = 0
    resolved_findings: int = 0
    persistent_findings: int = 0
    regression_findings: int = 0
    risk_delta: str = ""

class ScanSummary(BaseModel):
    # Existing fields plus:
    parent_scan_id: Optional[str] = None  # NEW
    scan_number: int = 1                   # NEW
    comparison: Optional[ScanComparison] = None  # NEW
```

### 3.2 Findings Endpoint Enrichment (`api/routers/findings.py`)

**Current**: `_build_finding_list()` merges Scanner + Analyzer + Fixer outputs.

**Extended merge logic**:
1. Start with Scanner findings (base)
2. Merge Analyzer data: `verdict`, `exploitability_score`, `analysis_reasoning`, `attack_scenario`, `auth_context`, `data_sensitivity`, `best_practices_analysis`
3. Merge Fixer data: `fix_status`, `fix_summary`, `fixed_code`, `fix_explanation`, `fix_error`, `pr_url`, `pr_number`
4. Merge Compliance data: For each finding, find matching entries in compliance output by `scan_id` and extract `pci_dss_requirements` → map to `compliance_mappings`
5. Merge Scanner code_context: `code_context` object with snippet, line range, related files
6. If re-scan: add `status_change` from comparison results

### 3.3 Re-Scan Support

**`POST /api/scans`**: Accept `parent_scan_id` in request body. Store in `ScanRecord`.

**Comparison logic** (in `pipeline.py`, after pipeline completes):
```python
def compare_findings(current_findings, parent_findings):
    """Compare findings between two scans using match key: cwe + file + line_range"""
    results = []
    for finding in current_findings:
        match_key = f"{finding.cwe}:{finding.file}:{finding.line // 10}"  # approximate line range
        parent_match = find_by_key(parent_findings, match_key)
        if parent_match:
            finding.status_change = "PERSISTENT"
        else:
            finding.status_change = "NEW"

    for parent_finding in parent_findings:
        match_key = f"{parent_finding.cwe}:{parent_finding.file}:{parent_finding.line // 10}"
        if not find_by_key(current_findings, match_key):
            # Create a resolved finding entry
            resolved = parent_finding.copy()
            resolved.status_change = "RESOLVED"
            results.append(resolved)

    return results
```

**Scan numbering**: When `parent_scan_id` is set, count the chain length to determine `scan_number`.

### 3.4 New Endpoint: Scan History

**`GET /api/scans/{id}/history`**

Returns the chain of linked scans by following `parent_scan_id` backward:
```json
{
  "scans": [
    {
      "id": "scan-abc",
      "scan_number": 1,
      "created_at": "2026-02-18T19:37:00Z",
      "confirmed_findings": 6,
      "fixed_findings": 0,
      "risk_score": 85,
      "risk_level": "CRITICAL"
    },
    {
      "id": "scan-def",
      "scan_number": 2,
      "parent_scan_id": "scan-abc",
      "created_at": "2026-02-19T14:15:00Z",
      "confirmed_findings": 4,
      "fixed_findings": 2,
      "risk_score": 70,
      "risk_level": "HIGH",
      "comparison": { "resolved": 2, "new": 0, "persistent": 4 }
    }
  ]
}
```

### 3.5 New Endpoint: Best Practices

**`GET /api/scans/{id}/practices`**

Aggregates `best_practices_analysis` from all confirmed findings into a consolidated view:
```json
{
  "stack": {
    "runtime": "Node.js",
    "framework": "Express.js",
    "database": "MySQL",
    "auth": "JWT (partial coverage)"
  },
  "anti_patterns": [
    {
      "pattern": "SQL String Concatenation",
      "instances": 3,
      "affected_files": ["routes/accounts.js", "routes/transfers.js"],
      "recommendation": "Adopt parameterized queries project-wide",
      "severity": "CRITICAL"
    }
  ],
  "maturity_scores": {
    "input_validation": 20,
    "authentication": 40,
    "authorization": 20,
    "secrets_management": 0,
    "logging_monitoring": 80,
    "error_handling": 60,
    "overall": 37,
    "level": "DEVELOPING"
  },
  "standards_violated": [
    { "standard": "OWASP ASVS v4.0", "violations": 4 },
    { "standard": "Node.js Security Checklist", "violations": 3 }
  ]
}
```

**Implementation**: The Analyzer already produces per-finding `best_practices_analysis`. This endpoint aggregates across all findings, deduplicates anti-patterns, and computes the maturity score based on coverage of security domains.

### 3.6 GitHub PR Fetch Fallback

**`GET /api/scans/{id}/findings/{scan_id}/fix-diff`**

If `fixed_code` isn't stored in the Fixer output (backward compatibility with old scans), fetch the PR diff from GitHub using the `pr_number` field. Returns the diff content for display in the Fix tab.

---

## 4. Layer 3: Dashboard Frontend

### 4.1 New Dependency

```bash
npm install highlight.js
```

Lightweight syntax highlighting. Use `hljs.highlight(code, {language: 'javascript'})` and render with `dangerouslySetInnerHTML`. No React wrapper needed.

### 4.2 Component Architecture

```
dashboard/
├── components/
│   ├── findings/
│   │   ├── SeverityBadge.tsx           (existing — extend with new statuses)
│   │   ├── FindingDetailPanel.tsx       (NEW — slide-over container)
│   │   ├── FindingOverviewTab.tsx       (NEW — severity, score, description, impact)
│   │   ├── FindingCodeTab.tsx           (NEW — syntax-highlighted vulnerable code)
│   │   ├── FindingAnalysisTab.tsx       (NEW — AI reasoning + best practices)
│   │   ├── FindingFixTab.tsx            (NEW — fix code + PR status)
│   │   ├── FindingComplianceTab.tsx     (NEW — PCI-DSS mapping cards)
│   │   └── CodeBlock.tsx                (NEW — reusable syntax highlighting)
│   ├── scans/
│   │   ├── NewScanDialog.tsx            (existing — no changes)
│   │   ├── PipelineStatus.tsx           (existing — no changes)
│   │   ├── ScanHistoryTimeline.tsx      (NEW — visual timeline of linked scans)
│   │   └── ComparisonBanner.tsx         (NEW — delta summary banner)
│   ├── practices/
│   │   ├── MaturityScoreChart.tsx       (NEW — horizontal bar chart)
│   │   ├── AntiPatternCard.tsx          (NEW — pattern violation card)
│   │   └── StackDetection.tsx           (NEW — tech stack display)
│   └── risk/
│       ├── OWASPRadarChart.tsx          (existing — no changes)
│       └── RiskScoreGauge.tsx           (existing — no changes)
├── app/
│   └── scans/
│       └── [id]/
│           ├── findings/page.tsx        (MODIFY — add row click + status_change column)
│           ├── page.tsx                 (MODIFY — add Re-Scan button + comparison banner)
│           └── practices/
│               └── page.tsx             (NEW — consolidated best practices page)
├── lib/
│   ├── api.ts                           (MODIFY — add new endpoint calls)
│   └── utils.ts                         (MODIFY — add new color maps)
```

### 4.3 FindingDetailPanel (Slide-Over)

**Behavior**:
- Opens from right side, occupies 60% of screen width
- Dark overlay (opacity 50%) on left 40% — clicking it closes the panel
- Slide-in animation: 300ms ease-out transform
- Escape key closes
- 6 tabs at top: Overview | Code | Analysis | Fix | Compliance | Best Practices

**State management**: React useState in `findings/page.tsx`:
```typescript
const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
// Row click: setSelectedFinding(finding)
// Close: setSelectedFinding(null)
```

### 4.4 Tab Implementations

#### Overview Tab
- Severity badge (large) + CWE badge
- Vulnerability title (h2)
- File path + line number (monospace)
- Exploitability score bar (0-100, color gradient)
- Description paragraph
- Impact bullet list (from description/attack_scenario)

#### Code Tab
- CodeBlock component with highlight.js
- Line numbers (gutter)
- Vulnerable lines highlighted with red semi-transparent background
- Below: issue summary annotation
- Related files section (collapsible) showing middleware/config snippets

#### Analysis Tab (The "Money Shot")
- Verdict badge (CONFIRMED / FALSE_POSITIVE)
- `analysis_reasoning` narrative text — the full LLM reasoning chain
- Structured factors grid:
  - Endpoint Exposure (auth_context)
  - Input Sanitization
  - Data Sensitivity
  - Exploitability assessment
- If FALSE_POSITIVE: show `false_positive_reason` with contrast explanation
- If CONFIRMED: show `attack_scenario` with example attack

#### Fix Tab
- Fix status badge (granular: PR_CREATED / FIX_GENERATED / FAILED / PENDING / N/A)
- If fix_error: red alert box with error message
- `fix_explanation` — why this fix approach
- CodeBlock showing `fixed_code` with green-highlighted lines
- PR info card: branch name, PR number, PR URL (link to GitHub)
- If no fixed_code but pr_url exists: "View diff on GitHub" button

#### Compliance Tab
- List of PCI-DSS requirement cards
- Each card: requirement ID, title, status badge (NON_COMPLIANT / PARTIALLY_COMPLIANT / COMPLIANT)
- Remediation text per requirement
- Evidence chain timeline: Detected → Analyzed → Fix PR → Pending Merge

#### Best Practices Tab
- Root cause pattern (highlighted)
- Violated standards list with ✗ markers
- Recommended pattern with code example (CodeBlock)
- Related vulnerabilities list
- Developer education paragraph

### 4.5 Fix Status Badge Enhancement

**Updated badge logic** (replaces current FixStatusBadge):
```typescript
const getFixDisplay = (finding: Finding) => {
  if (finding.verdict === 'FALSE_POSITIVE')
    return { label: 'N/A', color: 'gray' }
  if (finding.pr_url && finding.fix_status === 'SUCCESS')
    return { label: 'PR CREATED', color: 'green' }
  if (finding.fixed_code && !finding.pr_url)
    return { label: 'FIX READY', color: 'yellow' }
  if (finding.fix_status === 'DRY_RUN')
    return { label: 'DRY RUN', color: 'blue' }
  if (finding.fix_error)
    return { label: 'FAILED', color: 'red', tooltip: finding.fix_error }
  return { label: 'PENDING', color: 'gray' }
}
```

**Tooltip on FAILED**: Hover shows `fix_error` message.

### 4.6 Re-Scan UI

**Scan Overview page** (`[id]/page.tsx`):
- "Re-Scan" button next to the COMPLETED badge
- Click opens confirmation: "Re-scan {repo} using same configuration?"
- Sends `POST /api/scans` with `parent_scan_id: currentScanId`
- Redirects to new scan's overview page

**Comparison Banner** (shows when `parent_scan_id` exists):
```
vs Scan #1: 2 resolved · 0 new · 4 persistent | Risk: 85 → 70 (-15)
```

**Scan History Timeline** (new component on overview page):
- Horizontal timeline with dots per scan
- Each dot shows: scan number, date, confirmed count, risk score
- Color-coded: CRITICAL (red) → HIGH (orange) → MEDIUM (yellow) → LOW (green)

**Findings table for re-scans**:
- New column: "Status Change" with badges: RESOLVED (green), PERSISTENT (yellow), NEW (red), REGRESSION (purple)
- Resolved findings shown at bottom with strikethrough styling

### 4.7 Best Practices Page (`/scans/{id}/practices`)

**New page** added to scan detail navigation tabs:
`Findings | Risk Profile | Compliance | Best Practices`

**Sections**:
1. **Stack Detection card**: Runtime, framework, database, auth info
2. **Anti-Patterns Found**: List of AntiPatternCard components (pattern name, instance count, affected files, recommendation, severity badge)
3. **Security Maturity Score**: Horizontal bar chart showing scores per domain (input validation, authentication, authorization, secrets management, logging, error handling) with overall score and maturity level badge

### 4.8 API Client Extensions (`lib/api.ts`)

```typescript
// New functions
export async function getScanHistory(scanId: string): Promise<ScanHistory>
export async function getPractices(scanId: string): Promise<PracticesResponse>
export async function getFixDiff(scanId: string, findingId: string): Promise<string>

// Extended interfaces
interface Finding {
  // ... existing fields ...
  code_context?: CodeContext
  analysis_reasoning?: string
  fixed_code?: string
  fix_explanation?: string
  fix_error?: string
  compliance_mappings?: ComplianceMapping[]
  best_practices_analysis?: BestPracticesAnalysis
  status_change?: string
  first_detected_scan?: string
}
```

---

## 5. Implementation Order

### Phase 1: Agent Modifications (Foundation)
1. Scanner: Add `code_context` with 30-line window + related files
2. Analyzer: Add `analysis_reasoning` narrative + `best_practices_analysis`
3. Fixer: Store `fixed_code` + `fix_explanation` + `fix_error`, add FIX_GENERATED status

### Phase 2: API Gateway (Data Pipeline)
4. Extend `Finding` schema with all new fields
5. Enrich findings endpoint merge logic (Scanner + Analyzer + Fixer + Compliance)
6. Add `parent_scan_id` support to scan creation
7. Implement comparison logic in pipeline
8. Add `/history` endpoint
9. Add `/practices` endpoint
10. Add `/fix-diff` fallback endpoint

### Phase 3: Dashboard — Modal (Highest Impact)
11. Install highlight.js
12. Create CodeBlock component
13. Create FindingDetailPanel slide-over container
14. Create 6 tab components (Overview, Code, Analysis, Fix, Compliance, Best Practices)
15. Add row click handler to findings table
16. Update FixStatusBadge with granular states + tooltip

### Phase 4: Dashboard — Re-Scan (Closed Loop)
17. Add Re-Scan button to scan overview
18. Create ComparisonBanner component
19. Create ScanHistoryTimeline component
20. Add status_change column to findings table
21. Update scans list with scan numbers and delta badges

### Phase 5: Dashboard — Best Practices Page
22. Create MaturityScoreChart component
23. Create AntiPatternCard component
24. Create StackDetection component
25. Create practices page
26. Add "Best Practices" tab to scan navigation

---

## 6. Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Agent prompt changes break existing output | Add new fields as optional; validate backward compatibility |
| Fixer still can't create PRs (GitHub permissions) | FIX_GENERATED status shows capability; fix code displayed in modal regardless |
| Re-scan comparison has false matches | Use fuzzy matching (cwe + file + line_range/10) with manual override option |
| highlight.js bundle size | Import only JavaScript language module, not full bundle (~20KB) |
| 24-48h timeline pressure | Phases 1-3 are mandatory; Phase 4-5 are stretch goals |

---

## 7. Demo Script (Golden Path)

1. Show Scan #1 with 6 confirmed vulnerabilities
2. Click a finding → modal opens → show Analysis tab (AI reasoning "money shot")
3. Show Code tab with highlighted vulnerable lines
4. Show Fix tab with generated fix code + PR status
5. Show Compliance tab with PCI-DSS mapping
6. Show Best Practices tab with root cause analysis
7. Close modal → show fix status badges (green PR CREATED, yellow FIX READY)
8. Click "Re-Scan" → Scan #2 runs
9. Show Scan #2: 4 confirmed, 2 resolved → timeline shows improvement
10. Navigate to Best Practices page → Security Maturity Score visualization
11. Pitch: "5 AI agents, closed-loop remediation, audit-ready for regulators"
