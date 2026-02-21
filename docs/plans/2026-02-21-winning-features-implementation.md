# Winning Features Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement 4 competitive-gap features (Vulnerability Detail Modal, Fix Status Resolution, Re-Scan with History, Best Practices Analysis) to make DevSecOps Guardian the winning hackathon entry.

**Architecture:** 3-layer changes — Agent modifications (Scanner/Analyzer/Fixer Python agents) → API Gateway enrichment (FastAPI schemas + merge logic) → Dashboard frontend (Next.js slide-over modal, re-scan UI, practices page). Each layer is independent and testable before moving to the next.

**Tech Stack:** Python 3.12 + FastAPI (backend), Next.js 16 + React 19 + TypeScript + Tailwind CSS 4 (frontend), Azure OpenAI GPT-4o (LLM), highlight.js (syntax highlighting), Recharts 3.7 (charts)

---

## Phase 1: Agent Layer Modifications

### Task 1: Scanner — Add `code_context` to Finding Output

**Files:**
- Modify: `agents/scanner/prompts.py:48-84` (SCANNER_SYSTEM_PROMPT output format)
- Modify: `agents/scanner/smart_scan.py:70-109` (GROUPED_SCAN_PROMPT output format)
- Modify: `agents/scanner/smart_scan.py:249-271` (deduplicate_findings to preserve code_context)

**Step 1: Update SCANNER_SYSTEM_PROMPT output schema**

In `agents/scanner/prompts.py`, replace lines 48-84 (the Output Format section through end of SCANNER_SYSTEM_PROMPT) with:

```python
## Output Format

Respond ONLY with a JSON object containing a "findings" array. No explanations before or after. You MUST return ALL vulnerabilities found across ALL files in a single response.

```json
{
  "findings": [
    {
      "id": "SCAN-001",
      "file": "path/to/file.js",
      "line": 25,
      "vulnerability": "SQL Injection",
      "cwe": "CWE-89",
      "severity": "CRITICAL",
      "description": "User input from query parameter is concatenated directly into SQL query without parameterization.",
      "evidence": "const query = `SELECT * FROM accounts WHERE id = ${id}`",
      "recommendation": "Use parameterized queries: db.prepare('SELECT * FROM accounts WHERE id = ?').get(id)",
      "code_context": {
        "vulnerable_code": "Lines 20-40 of the vulnerable file showing the vulnerability in context with surrounding code",
        "related_files": [
          {
            "file": "middleware/auth.js",
            "relevance": "Authentication middleware - this route has NO auth middleware applied",
            "snippet": "Key lines from the related file showing how auth is (or isn't) applied"
          }
        ]
      }
    }
  ]
}
```

IMPORTANT: Return ALL findings in a single "findings" array. Do NOT stop after the first finding. Analyze EVERY file thoroughly.

If no vulnerabilities are found, respond with: {"findings": []}

## Code Context Rules
- **vulnerable_code**: Include approximately 30 lines centered on the vulnerability (15 lines above and below the vulnerable line). Include the full function containing the vulnerability if possible.
- **related_files**: Include 1-3 related files that affect the vulnerability context:
  - Auth middleware files (to show if route is protected or not)
  - Configuration files (to show where secrets/config are defined)
  - Server setup files (to show route registration and middleware chain)
  - Only include files that are in the scan group or context map
- Each related_files snippet should be 10-20 lines of the most relevant section

## Important
- Do NOT flag parameterized/prepared statements as SQL injection
- Do NOT flag bcrypt or argon2 as weak cryptography
- Do NOT flag code behind proper authentication + authorization as the same severity as public endpoints
- Focus on REAL exploitable issues, not theoretical concerns
"""
```

**Step 2: Update GROUPED_SCAN_PROMPT output schema**

In `agents/scanner/smart_scan.py`, replace the JSON schema section of GROUPED_SCAN_PROMPT (lines 89-106) with the same schema that includes `code_context`:

```python
GROUPED_SCAN_PROMPT = """You are scanning a banking application for security vulnerabilities.

## REPO CONTEXT MAP (summary of full application - DO NOT scan this, use it for context only):
```json
{context_map}
```

## FILES TO SCAN (analyze these files for vulnerabilities):

{files_content}

## RULES
- Use the context map to understand which endpoints are public vs protected
- A SQL query behind JWT auth + parameterized query is LOWER risk than one on a public endpoint
- Hardcoded secrets are always a finding regardless of auth
- PII in logs is a finding regardless of auth
- Report ALL vulnerabilities you find in the files above
- Do NOT report issues in files not shown above (they'll be scanned separately)

Respond ONLY with a JSON object containing a "findings" array:
```json
{{
  "findings": [
    {{
      "id": "SCAN-001",
      "file": "path/to/file.js",
      "line": 25,
      "vulnerability": "SQL Injection",
      "cwe": "CWE-89",
      "severity": "CRITICAL",
      "description": "Detailed description of the vulnerability",
      "evidence": "The actual vulnerable code snippet",
      "recommendation": "How to fix it",
      "code_context": {{
        "vulnerable_code": "~30 lines centered on the vulnerability showing surrounding context",
        "related_files": [
          {{
            "file": "middleware/auth.js",
            "relevance": "Why this file matters for the vulnerability",
            "snippet": "Key lines from the related file"
          }}
        ]
      }}
    }}
  ]
}}
```

If no vulnerabilities found in these files, respond with: {{"findings": []}}
"""
```

**Step 3: Update deduplicate_findings to preserve code_context**

In `agents/scanner/smart_scan.py`, the `deduplicate_findings` function (line 249) already keeps the finding with more detail. No change needed since it preserves all fields. Verify it doesn't strip `code_context`.

**Step 4: Verify scanner agent runs**

Run: `cd agents/scanner && python -c "from prompts import SCANNER_SYSTEM_PROMPT; print('OK:', 'code_context' in SCANNER_SYSTEM_PROMPT)"`
Expected: `OK: True`

**Step 5: Commit**

```bash
git add agents/scanner/prompts.py agents/scanner/smart_scan.py
git commit -m "feat(scanner): add code_context with vulnerable code and related files to findings output"
```

---

### Task 2: Analyzer — Add `analysis_reasoning` and `best_practices_analysis`

**Files:**
- Modify: `agents/analyzer/prompts.py:9-84` (ANALYZER_SYSTEM_PROMPT — add new output fields)
- Modify: `agents/analyzer/llm_engine.py:104-143` (_parse_analyses — handle new fields)
- Modify: `agents/analyzer/analyzer.py:99-126` (merge_findings_with_analyses — pass through new fields)

**Step 1: Update ANALYZER_SYSTEM_PROMPT output schema**

In `agents/analyzer/prompts.py`, replace the Output Format section (lines 48-84) with:

```python
## Output Format
Respond ONLY with a JSON object containing an "analyses" array. No text before or after the JSON.

```json
{{
  "analyses": [
    {{
      "scan_id": "SCAN-001",
      "verdict": "CONFIRMED",
      "exploitability_score": 95,
      "auth_context": "PUBLIC - no authenticateToken middleware on GET /api/accounts",
      "data_sensitivity": "HIGH - exposes account_number, owner_name, balance (PCI data)",
      "attack_scenario": "Attacker sends GET /api/accounts?id=1 OR 1=1 to dump all account records",
      "false_positive_reason": null,
      "confirmed_evidence": "const query = `SELECT ... WHERE id = ${{id}}`",
      "analysis_reasoning": "This SQL injection vulnerability is confirmed as CRITICAL because: 1) The endpoint GET /api/accounts is PUBLIC with no authentication middleware applied (verified by checking server.js route registration). 2) User input from req.query.id flows directly into a template literal SQL string without parameterization. 3) The query targets the accounts table which contains PCI-regulated data (account_number, balance, owner_name). 4) No input validation or sanitization exists before the query. An attacker can trivially exploit this via URL parameter injection to extract all banking records.",
      "best_practices_analysis": {{
        "violated_practices": [
          {{
            "practice": "Parameterized Queries",
            "category": "Input Validation",
            "current_state": "Raw string concatenation in SQL query using template literals",
            "recommended_state": "Use prepared statements with ? placeholders via db.prepare()",
            "owasp_reference": "A03:2021 - Injection"
          }},
          {{
            "practice": "Input Validation",
            "category": "Input Validation",
            "current_state": "No validation on req.query.id parameter",
            "recommended_state": "Validate that id is a positive integer before use",
            "owasp_reference": "A03:2021 - Injection"
          }}
        ],
        "followed_practices": [
          {{
            "practice": "Database Abstraction",
            "category": "Architecture",
            "detail": "Using better-sqlite3 which supports parameterized queries"
          }}
        ]
      }}
    }},
    {{
      "scan_id": "SCAN-006",
      "verdict": "FALSE_POSITIVE",
      "exploitability_score": 5,
      "auth_context": "PROTECTED - authenticateToken middleware applied, req.user.id from JWT",
      "data_sensitivity": "HIGH - account balances, but access is properly restricted",
      "attack_scenario": null,
      "false_positive_reason": "Query uses prepared statement with ? placeholder. User ID from verified JWT, not user input.",
      "confirmed_evidence": null,
      "analysis_reasoning": "This finding is a FALSE POSITIVE because the code already implements the recommended fix. The query uses db.prepare('SELECT ... WHERE user_id = ?').get(req.user.id) which is a parameterized query. Furthermore, the user_id comes from req.user.id which is extracted from a verified JWT token (set by authenticateToken middleware), NOT from user-controlled input. The endpoint is protected by authentication middleware verified in the server.js route registration.",
      "best_practices_analysis": {{
        "violated_practices": [],
        "followed_practices": [
          {{
            "practice": "Parameterized Queries",
            "category": "Input Validation",
            "detail": "Uses db.prepare() with ? placeholder for SQL parameters"
          }},
          {{
            "practice": "JWT Authentication",
            "category": "Authentication",
            "detail": "Route protected by authenticateToken middleware, user ID from verified JWT"
          }}
        ]
      }}
    }}
  ]
}}
```

IMPORTANT:
- Analyze EVERY finding in the scanner report - do not skip any
- Include EVERY finding in your "analyses" array
- Do NOT add new findings - only analyze the ones provided
- Base your verdict on the ACTUAL source code, not just the scanner's description
- The scan_id in your output MUST match the id field from the scanner finding
- The `analysis_reasoning` must be a detailed 3-5 sentence narrative explaining your reasoning chain
- The `best_practices_analysis` must list specific security practices that are violated or followed
"""
```

**Step 2: Update _parse_analyses to handle new fields**

In `agents/analyzer/llm_engine.py`, after line 138 (inside the validation loop, after the exploitability_score section), add preservation of new fields:

```python
            # Preserve new enrichment fields (pass through as-is)
            # analysis_reasoning and best_practices_analysis are already in the dict
            # Just ensure defaults if missing
            if "analysis_reasoning" not in analysis:
                analysis["analysis_reasoning"] = ""
            if "best_practices_analysis" not in analysis:
                analysis["best_practices_analysis"] = {
                    "violated_practices": [],
                    "followed_practices": [],
                }
```

**Step 3: Update merge_findings_with_analyses to include new fields**

In `agents/analyzer/analyzer.py`, in the `merge_findings_with_analyses` function, add the new fields to the `merged_finding` dict (after line 123, before the closing brace):

```python
            # New enrichment fields
            "analysis_reasoning": analysis.get("analysis_reasoning", ""),
            "best_practices_analysis": analysis.get("best_practices_analysis", {
                "violated_practices": [],
                "followed_practices": [],
            }),
```

**Step 4: Verify analyzer agent loads**

Run: `cd agents/analyzer && python -c "from prompts import ANALYZER_SYSTEM_PROMPT; print('OK:', 'analysis_reasoning' in ANALYZER_SYSTEM_PROMPT and 'best_practices_analysis' in ANALYZER_SYSTEM_PROMPT)"`
Expected: `OK: True`

**Step 5: Commit**

```bash
git add agents/analyzer/prompts.py agents/analyzer/llm_engine.py agents/analyzer/analyzer.py
git commit -m "feat(analyzer): add analysis_reasoning narrative and best_practices_analysis to output"
```

---

### Task 3: Fixer — Store `fixed_code` in Output JSON

**Files:**
- Modify: `agents/fixer/fixer.py:146-157` (result dict — add fixed_code, fix_explanation, fix_error)
- Modify: `agents/fixer/fixer.py:174-185` (after LLM fix — store fixed_code in result)
- Modify: `agents/fixer/fixer.py:224-232` (PARTIAL status — add FIX_GENERATED)

**Step 1: Extend the result dict template**

In `agents/fixer/fixer.py`, replace the result dict (lines 146-157) with:

```python
    result = {
        "scan_id": scan_id,
        "anlz_id": finding.get("anlz_id", ""),
        "file": file_path,
        "vulnerability": vuln,
        "status": "FAILED",
        "fix_summary": "",
        "fixed_code": "",
        "fix_explanation": "",
        "fix_error": "",
        "branch": "",
        "pr_number": None,
        "pr_url": "",
        "error": "",
    }
```

**Step 2: Store fixed_code after LLM generation**

In `agents/fixer/fixer.py`, replace lines 179-185 (after `result["fix_summary"] = ...`) with:

```python
        result["fix_summary"] = fix.get("fix_summary", "")
        result["fixed_code"] = fix.get("fixed_code", "")
        result["fix_explanation"] = fix.get("fix_details", "")

        if dry_run:
            result["status"] = "DRY_RUN"
            print(f"  [DRY RUN] Fix generated but not pushed to GitHub")
            return result
```

**Step 3: Add FIX_GENERATED status for committed but no-PR case**

In `agents/fixer/fixer.py`, replace lines 229-232 (the else branch after PR creation) with:

```python
        else:
            # Fix was committed but PR creation failed
            result["status"] = "FIX_GENERATED"
            result["fix_error"] = "Fix code generated and committed but PR creation failed"
```

Also update the error case at line 175-177 to store the error:

```python
        if not fix or not fix.get("fixed_code"):
            result["fix_error"] = "LLM failed to generate fix code"
            result["error"] = "LLM failed to generate fix"
            return result
```

**Step 4: Update print_results to handle FIX_GENERATED**

In `agents/fixer/fixer.py`, after line 258 (the PARTIAL icon line), add:

```python
        elif status == "FIX_GENERATED":
            icon = "[~]"
```

And in the summary section (line 278), add:

```python
    fix_generated = sum(1 for r in results if r["status"] == "FIX_GENERATED")
```

And include it in the parts list.

**Step 5: Verify fixer agent loads**

Run: `cd agents/fixer && python -c "from fixer import process_finding; print('OK')"`
Expected: `OK`

**Step 6: Commit**

```bash
git add agents/fixer/fixer.py
git commit -m "feat(fixer): store fixed_code in output JSON and add FIX_GENERATED status"
```

---

## Phase 2: API Gateway Layer

### Task 4: Extend API Schemas

**Files:**
- Modify: `api/schemas.py` (add new models, extend Finding, extend ScanRequest, add FixStatus.FIX_GENERATED)

**Step 1: Add FIX_GENERATED to FixStatus enum**

In `api/schemas.py`, replace the FixStatus enum (lines 38-42) with:

```python
class FixStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    DRY_RUN = "DRY_RUN"
    PENDING = "PENDING"
    FIX_GENERATED = "FIX_GENERATED"
    PARTIAL = "PARTIAL"
```

**Step 2: Add new model classes after RiskLevel enum (after line 51)**

```python
class StatusChange(str, Enum):
    NEW = "NEW"
    PERSISTENT = "PERSISTENT"
    RESOLVED = "RESOLVED"
    REGRESSION = "REGRESSION"


class CodeContext(BaseModel):
    vulnerable_code: str = ""
    related_files: list[dict[str, str]] = Field(default_factory=list)


class BestPracticeViolation(BaseModel):
    practice: str
    category: str
    current_state: str = ""
    recommended_state: str = ""
    owasp_reference: str = ""


class BestPracticeFollowed(BaseModel):
    practice: str
    category: str
    detail: str = ""


class BestPracticesAnalysis(BaseModel):
    violated_practices: list[BestPracticeViolation] = Field(default_factory=list)
    followed_practices: list[BestPracticeFollowed] = Field(default_factory=list)
```

**Step 3: Add parent_scan_id to ScanRequest**

In `api/schemas.py`, replace ScanRequest (lines 55-67) with:

```python
class ScanRequest(BaseModel):
    repository_path: str = Field(
        default="demo-app",
        description="Repository path to scan (e.g., 'demo-app')"
    )
    ref: Optional[str] = Field(
        default=None,
        description="Branch or commit SHA to scan"
    )
    dry_run: bool = Field(
        default=False,
        description="Skip GitHub writes (no branches, commits, or PRs)"
    )
    parent_scan_id: Optional[str] = Field(
        default=None,
        description="ID of parent scan for re-scan comparison"
    )
```

**Step 4: Add parent_scan_id + scan_number to ScanSummary**

In `api/schemas.py`, replace ScanSummary (lines 72-86) with:

```python
class ScanSummary(BaseModel):
    id: str
    status: ScanStatus
    repository_path: str
    ref: Optional[str] = None
    dry_run: bool = False
    created_at: str
    updated_at: str
    total_findings: int = 0
    confirmed_findings: int = 0
    fixed_findings: int = 0
    risk_level: Optional[str] = None
    compliance_rating: Optional[str] = None
    current_stage: Optional[str] = None
    error: Optional[str] = None
    parent_scan_id: Optional[str] = None
    scan_number: int = 1
```

**Step 5: Extend Finding model with all new fields**

In `api/schemas.py`, replace Finding (lines 98-114) with:

```python
class Finding(BaseModel):
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
    # New fields - Feature 1: Detail Modal
    code_context: Optional[CodeContext] = None
    analysis_reasoning: str = ""
    best_practices_analysis: Optional[BestPracticesAnalysis] = None
    fixed_code: str = ""
    fix_explanation: str = ""
    fix_error: str = ""
    # Analyzer enrichment fields
    auth_context: str = ""
    data_sensitivity: str = ""
    attack_scenario: Optional[str] = None
    false_positive_reason: Optional[str] = None
    confirmed_evidence: Optional[str] = None
    # Re-scan comparison
    status_change: Optional[str] = None
```

**Step 6: Add ScanComparison and PracticesResponse models at the end of the file (before HealthResponse)**

```python
class ScanComparisonFinding(BaseModel):
    scan_id: str
    vulnerability: str
    cwe: str
    file: str
    severity: str
    status_change: str  # NEW, RESOLVED, PERSISTENT, REGRESSION


class ScanComparison(BaseModel):
    current_scan_id: str
    parent_scan_id: str
    new_findings: int = 0
    resolved_findings: int = 0
    persistent_findings: int = 0
    regression_findings: int = 0
    findings: list[ScanComparisonFinding] = Field(default_factory=list)


class PracticesSummary(BaseModel):
    scan_id: str
    total_violations: int = 0
    total_followed: int = 0
    maturity_score: int = 0  # 0-100
    categories: dict[str, dict[str, int]] = Field(default_factory=dict)
    top_violations: list[BestPracticeViolation] = Field(default_factory=list)
    top_followed: list[BestPracticeFollowed] = Field(default_factory=list)
    anti_patterns: list[dict[str, Any]] = Field(default_factory=list)
```

**Step 7: Verify schemas load**

Run: `cd api && python -c "from schemas import Finding, ScanRequest, CodeContext, BestPracticesAnalysis, ScanComparison, PracticesSummary; print('OK')"`
Expected: `OK`

**Step 8: Commit**

```bash
git add api/schemas.py
git commit -m "feat(api): extend schemas with code_context, analysis_reasoning, best_practices, re-scan models"
```

---

### Task 5: Enrich Findings Merge Logic

**Files:**
- Modify: `api/routers/findings.py:37-66` (merge logic — add scanner, analyzer, fixer, compliance fields)

**Step 1: Replace the entire merge logic in get_findings**

In `api/routers/findings.py`, replace lines 37-74 (from fixer_lookup through the filter section) with:

```python
    # Build fixer lookup: scan_id -> fix info
    fixer_lookup = {}
    if scan.fixer_output and scan.fixer_output.get("fixes"):
        for fix in scan.fixer_output["fixes"]:
            fixer_lookup[fix.get("scan_id", "")] = fix

    # Build scanner lookup: scan_id -> scanner finding (for code_context)
    scanner_lookup = {}
    if scan.scanner_output and scan.scanner_output.get("findings"):
        for sf in scan.scanner_output["findings"]:
            scanner_lookup[sf.get("id", "")] = sf

    # Build compliance lookup: scan_id -> compliance mappings
    compliance_lookup = {}
    if scan.compliance_output and scan.compliance_output.get("findings"):
        for cf in scan.compliance_output["findings"]:
            compliance_lookup[cf.get("scan_id", "")] = cf

    # Merge analyzer findings with scanner, fixer, and compliance data
    findings = []
    for f in scan.analyzer_output.get("findings", []):
        scan_ref = f.get("scan_id", "")
        fix = fixer_lookup.get(scan_ref, {})
        scanner_finding = scanner_lookup.get(scan_ref, {})
        compliance_finding = compliance_lookup.get(scan_ref, {})

        # Build code_context from scanner output
        raw_code_context = scanner_finding.get("code_context")
        code_context = None
        if raw_code_context and isinstance(raw_code_context, dict):
            from schemas import CodeContext
            code_context = CodeContext(
                vulnerable_code=raw_code_context.get("vulnerable_code", ""),
                related_files=raw_code_context.get("related_files", []),
            )

        # Build best_practices_analysis from analyzer output
        raw_bp = f.get("best_practices_analysis")
        best_practices = None
        if raw_bp and isinstance(raw_bp, dict):
            from schemas import BestPracticesAnalysis, BestPracticeViolation, BestPracticeFollowed
            best_practices = BestPracticesAnalysis(
                violated_practices=[
                    BestPracticeViolation(**v) for v in raw_bp.get("violated_practices", [])
                    if isinstance(v, dict)
                ],
                followed_practices=[
                    BestPracticeFollowed(**fp) for fp in raw_bp.get("followed_practices", [])
                    if isinstance(fp, dict)
                ],
            )

        # Determine fix_status with FIX_GENERATED support
        fix_status = fix.get("status", "PENDING")
        if fix_status == "PARTIAL":
            fix_status = "FIX_GENERATED"

        finding = Finding(
            scan_id=scan_ref,
            anlz_id=f.get("anlz_id", ""),
            file=f.get("file", ""),
            line=f.get("line", 0),
            vulnerability=f.get("vulnerability", ""),
            cwe=f.get("cwe", ""),
            severity=f.get("severity", "MEDIUM"),
            description=f.get("description", ""),
            evidence=f.get("evidence", ""),
            recommendation=f.get("recommendation", ""),
            verdict=f.get("verdict", "CONFIRMED"),
            exploitability_score=f.get("exploitability_score", 0),
            fix_status=fix_status,
            fix_summary=fix.get("fix_summary"),
            pr_url=fix.get("pr_url"),
            pr_number=fix.get("pr_number"),
            # New Feature 1 fields
            code_context=code_context,
            analysis_reasoning=f.get("analysis_reasoning", ""),
            best_practices_analysis=best_practices,
            fixed_code=fix.get("fixed_code", ""),
            fix_explanation=fix.get("fix_explanation", ""),
            fix_error=fix.get("fix_error", fix.get("error", "")),
            # Analyzer enrichment
            auth_context=f.get("auth_context", ""),
            data_sensitivity=f.get("data_sensitivity", ""),
            attack_scenario=f.get("attack_scenario"),
            false_positive_reason=f.get("false_positive_reason"),
            confirmed_evidence=f.get("confirmed_evidence"),
        )

        # Apply filters
        if severity and finding.severity.upper() != severity.upper():
            continue
        if verdict and finding.verdict.upper() != verdict.upper():
            continue

        findings.append(finding)
```

**Step 2: Verify API starts**

Run: `cd api && python -c "from routers.findings import router; print('OK')"`
Expected: `OK`

**Step 3: Commit**

```bash
git add api/routers/findings.py
git commit -m "feat(api): enrich findings merge with code_context, analysis_reasoning, best_practices, fixed_code"
```

---

### Task 6: Add Re-Scan Support to ScanRecord + Scans Router

**Files:**
- Modify: `api/models.py:21-45` (ScanRecord.__init__ — add parent_scan_id, scan_number)
- Modify: `api/models.py:102-130` (to_summary, to_detail — include new fields)
- Modify: `api/models.py:139-147` (ScanStore.create — accept parent_scan_id)
- Modify: `api/routers/scans.py:18-37` (create_scan — pass parent_scan_id)

**Step 1: Extend ScanRecord.__init__**

In `api/models.py`, replace ScanRecord.__init__ (lines 21-45) with:

```python
    def __init__(
        self,
        repository_path: str,
        ref: Optional[str] = None,
        dry_run: bool = False,
        parent_scan_id: Optional[str] = None,
    ):
        self.id = f"scan-{uuid.uuid4().hex[:12]}"
        self.status = ScanStatus.QUEUED
        self.repository_path = repository_path
        self.ref = ref
        self.dry_run = dry_run
        self.parent_scan_id = parent_scan_id
        self.scan_number = 1
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at
        self.current_stage: Optional[str] = None
        self.error: Optional[str] = None

        # Agent outputs (loaded from JSON files after each stage)
        self.scanner_output: Optional[dict] = None
        self.analyzer_output: Optional[dict] = None
        self.fixer_output: Optional[dict] = None
        self.risk_profile_output: Optional[dict] = None
        self.compliance_output: Optional[dict] = None

        # Stage tracking
        self.stages: dict[str, str] = {}

        # Re-scan comparison results
        self.comparison: Optional[dict] = None
```

**Step 2: Update to_summary and to_detail**

In `api/models.py`, replace to_summary (lines 102-118) with:

```python
    def to_summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status.value,
            "repository_path": self.repository_path,
            "ref": self.ref,
            "dry_run": self.dry_run,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "total_findings": self.total_findings,
            "confirmed_findings": self.confirmed_findings,
            "fixed_findings": self.fixed_findings,
            "risk_level": self.risk_level,
            "compliance_rating": self.compliance_rating,
            "current_stage": self.current_stage,
            "error": self.error,
            "parent_scan_id": self.parent_scan_id,
            "scan_number": self.scan_number,
        }
```

Replace to_detail (lines 120-130) with:

```python
    def to_detail(self) -> dict[str, Any]:
        detail = self.to_summary()
        detail.update({
            "scanner_output": self.scanner_output,
            "analyzer_output": self.analyzer_output,
            "fixer_output": self.fixer_output,
            "risk_profile_output": self.risk_profile_output,
            "compliance_output": self.compliance_output,
            "stages": self.stages,
            "comparison": self.comparison,
        })
        return detail
```

**Step 3: Update ScanStore.create**

In `api/models.py`, replace ScanStore.create (lines 139-147) with:

```python
    def create(
        self,
        repository_path: str,
        ref: Optional[str] = None,
        dry_run: bool = False,
        parent_scan_id: Optional[str] = None,
    ) -> ScanRecord:
        scan = ScanRecord(repository_path, ref, dry_run, parent_scan_id)

        # Calculate scan_number based on parent chain
        if parent_scan_id:
            parent = self.get(parent_scan_id)
            if parent:
                scan.scan_number = parent.scan_number + 1

        self._scans[scan.id] = scan
        return scan

    def get_history(self, scan_id: str) -> list["ScanRecord"]:
        """Get scan history chain (parent → child)."""
        # Find root scan
        scan = self.get(scan_id)
        if not scan:
            return []

        # Walk up to find root
        root = scan
        while root.parent_scan_id:
            parent = self.get(root.parent_scan_id)
            if not parent:
                break
            root = parent

        # Walk down collecting chain
        chain = [root]
        current_id = root.id
        while True:
            child = next(
                (s for s in self._scans.values() if s.parent_scan_id == current_id),
                None,
            )
            if not child:
                break
            chain.append(child)
            current_id = child.id

        return chain
```

**Step 4: Update scans router to pass parent_scan_id**

In `api/routers/scans.py`, replace create_scan (lines 18-37) with:

```python
@router.post("", response_model=ScanSummary, status_code=202)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
):
    """Trigger a new security scan.

    Creates a scan record and launches the multi-agent pipeline
    in the background. Poll GET /api/scans/{id} for status updates.
    """
    scan = scan_store.create(
        repository_path=request.repository_path,
        ref=request.ref,
        dry_run=request.dry_run,
        parent_scan_id=request.parent_scan_id,
    )

    # Launch pipeline in background
    background_tasks.add_task(run_pipeline, scan)

    return ScanSummary(**scan.to_summary())
```

**Step 5: Add history endpoint**

In `api/routers/scans.py`, add after the get_scan endpoint:

```python
@router.get("/{scan_id}/history", response_model=list[ScanSummary])
async def get_scan_history(scan_id: str):
    """Get the scan history chain for re-scans."""
    history = scan_store.get_history(scan_id)
    if not history:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return [ScanSummary(**s.to_summary()) for s in history]
```

**Step 6: Verify API starts**

Run: `cd api && python -c "from routers.scans import router; print('OK')"`
Expected: `OK`

**Step 7: Commit**

```bash
git add api/models.py api/routers/scans.py
git commit -m "feat(api): add parent_scan_id, scan history chain, and re-scan support"
```

---

### Task 7: Add Practices Endpoint + Comparison Logic

**Files:**
- Create: `api/routers/practices.py`
- Modify: `api/pipeline.py:220-231` (add comparison after pipeline completes)
- Modify: `api/main.py` (register practices router — need to check this file first)

**Step 1: Create practices router**

Create `api/routers/practices.py`:

```python
"""
DevSecOps Guardian - Best Practices Router

Aggregates best_practices_analysis from all findings into a maturity score.
"""

from fastapi import APIRouter, HTTPException
from typing import Any

from models import scan_store
from schemas import PracticesSummary

router = APIRouter(prefix="/api/scans", tags=["practices"])


def _compute_maturity_score(
    total_violations: int,
    total_followed: int,
) -> int:
    """Compute security maturity score 0-100.

    Score = (followed / (followed + violations)) * 100
    Clamped to 0-100.
    """
    total = total_violations + total_followed
    if total == 0:
        return 50  # No data = neutral
    return max(0, min(100, round((total_followed / total) * 100)))


@router.get("/{scan_id}/practices", response_model=PracticesSummary)
async def get_practices(scan_id: str):
    """Get aggregated best practices analysis for a scan."""
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    if not scan.analyzer_output:
        raise HTTPException(
            status_code=400,
            detail="Analyzer has not completed yet"
        )

    all_violations: list[dict] = []
    all_followed: list[dict] = []
    category_stats: dict[str, dict[str, int]] = {}

    for f in scan.analyzer_output.get("findings", []):
        bp = f.get("best_practices_analysis", {})
        if not isinstance(bp, dict):
            continue

        for v in bp.get("violated_practices", []):
            if isinstance(v, dict):
                all_violations.append(v)
                cat = v.get("category", "Other")
                if cat not in category_stats:
                    category_stats[cat] = {"violations": 0, "followed": 0}
                category_stats[cat]["violations"] += 1

        for fp in bp.get("followed_practices", []):
            if isinstance(fp, dict):
                all_followed.append(fp)
                cat = fp.get("category", "Other")
                if cat not in category_stats:
                    category_stats[cat] = {"violations": 0, "followed": 0}
                category_stats[cat]["followed"] += 1

    # Deduplicate violations by (practice, category)
    seen_violations: set[tuple] = set()
    unique_violations = []
    for v in all_violations:
        key = (v.get("practice", ""), v.get("category", ""))
        if key not in seen_violations:
            seen_violations.add(key)
            unique_violations.append(v)

    # Deduplicate followed
    seen_followed: set[tuple] = set()
    unique_followed = []
    for fp in all_followed:
        key = (fp.get("practice", ""), fp.get("category", ""))
        if key not in seen_followed:
            seen_followed.add(key)
            unique_followed.append(fp)

    # Anti-patterns: violations that appear 2+ times
    violation_counts: dict[str, int] = {}
    for v in all_violations:
        name = v.get("practice", "Unknown")
        violation_counts[name] = violation_counts.get(name, 0) + 1

    anti_patterns = [
        {
            "practice": name,
            "occurrences": count,
            "category": next(
                (v.get("category", "Other") for v in all_violations if v.get("practice") == name),
                "Other",
            ),
        }
        for name, count in sorted(violation_counts.items(), key=lambda x: -x[1])
        if count >= 2
    ]

    maturity = _compute_maturity_score(len(all_violations), len(all_followed))

    return PracticesSummary(
        scan_id=scan_id,
        total_violations=len(all_violations),
        total_followed=len(all_followed),
        maturity_score=maturity,
        categories=category_stats,
        top_violations=unique_violations[:10],
        top_followed=unique_followed[:10],
        anti_patterns=anti_patterns,
    )
```

**Step 2: Add comparison logic to pipeline.py**

In `api/pipeline.py`, replace the DONE section (lines 220-231) with:

```python
    # ---- COMPARISON (if re-scan) ----
    if scan.parent_scan_id:
        parent = scan_store.get(scan.parent_scan_id)
        if parent and parent.analyzer_output:
            comparison = _compare_scans(parent, scan)
            scan.comparison = comparison
            print(f"  [>] Re-scan comparison: {comparison.get('new_findings', 0)} new, "
                  f"{comparison.get('resolved_findings', 0)} resolved, "
                  f"{comparison.get('persistent_findings', 0)} persistent")

    # ---- DONE ----
    scan.update_status(ScanStatus.COMPLETED)
    scan.current_stage = None
    scan_store.save(scan)

    print(f"\n{'='*60}")
    print(f"  Pipeline completed: {scan.id}")
    print(f"  Status: {scan.status.value}")
    print(f"  Findings: {scan.total_findings} total, "
          f"{scan.confirmed_findings} confirmed, "
          f"{scan.fixed_findings} fixed")
    print(f"{'='*60}\n")
```

**Step 3: Add _compare_scans helper function**

In `api/pipeline.py`, add before `run_pipeline`:

```python
def _make_finding_key(finding: dict) -> str:
    """Create a match key for comparing findings across scans.

    Uses CWE + file + approximate line range (within 10 lines).
    """
    cwe = finding.get("cwe", "")
    file = finding.get("file", "")
    line = finding.get("line", 0)
    # Round line to nearest 10 for fuzzy matching
    line_bucket = (line // 10) * 10
    return f"{cwe}:{file}:{line_bucket}"


def _compare_scans(parent: "ScanRecord", current: "ScanRecord") -> dict:
    """Compare findings between parent and current scan."""
    parent_findings = {}
    if parent.analyzer_output:
        for f in parent.analyzer_output.get("findings", []):
            if f.get("verdict") == "CONFIRMED":
                key = _make_finding_key(f)
                parent_findings[key] = f

    current_findings = {}
    if current.analyzer_output:
        for f in current.analyzer_output.get("findings", []):
            if f.get("verdict") == "CONFIRMED":
                key = _make_finding_key(f)
                current_findings[key] = f

    comparison_findings = []
    new_count = 0
    resolved_count = 0
    persistent_count = 0

    # Check current findings against parent
    for key, finding in current_findings.items():
        if key in parent_findings:
            status_change = "PERSISTENT"
            persistent_count += 1
        else:
            status_change = "NEW"
            new_count += 1
        comparison_findings.append({
            "scan_id": finding.get("scan_id", ""),
            "vulnerability": finding.get("vulnerability", ""),
            "cwe": finding.get("cwe", ""),
            "file": finding.get("file", ""),
            "severity": finding.get("severity", ""),
            "status_change": status_change,
        })

    # Check parent findings not in current (resolved)
    for key, finding in parent_findings.items():
        if key not in current_findings:
            resolved_count += 1
            comparison_findings.append({
                "scan_id": finding.get("scan_id", ""),
                "vulnerability": finding.get("vulnerability", ""),
                "cwe": finding.get("cwe", ""),
                "file": finding.get("file", ""),
                "severity": finding.get("severity", ""),
                "status_change": "RESOLVED",
            })

    return {
        "current_scan_id": current.id,
        "parent_scan_id": parent.id,
        "new_findings": new_count,
        "resolved_findings": resolved_count,
        "persistent_findings": persistent_count,
        "regression_findings": 0,
        "findings": comparison_findings,
    }
```

**Step 4: Register practices router in main.py**

Check what the main.py looks like, then add `from routers.practices import router as practices_router` and `app.include_router(practices_router)`.

**Step 5: Verify API starts**

Run: `cd api && python -c "from routers.practices import router; from pipeline import _compare_scans; print('OK')"`
Expected: `OK`

**Step 6: Commit**

```bash
git add api/routers/practices.py api/pipeline.py api/main.py
git commit -m "feat(api): add practices endpoint, re-scan comparison logic, and scan history"
```

---

## Phase 3: Dashboard — Finding Detail Modal

### Task 8: Install highlight.js

**Step 1: Install dependency**

Run: `cd dashboard && npm install highlight.js`

**Step 2: Commit**

```bash
git add dashboard/package.json dashboard/package-lock.json
git commit -m "chore(dashboard): install highlight.js for syntax highlighting"
```

---

### Task 9: Create CodeBlock Component

**Files:**
- Create: `dashboard/components/findings/CodeBlock.tsx`

**Step 1: Create the component**

Create `dashboard/components/findings/CodeBlock.tsx`:

```tsx
"use client";

import { useEffect, useRef } from "react";
import hljs from "highlight.js/lib/core";
import javascript from "highlight.js/lib/languages/javascript";
import typescript from "highlight.js/lib/languages/typescript";
import python from "highlight.js/lib/languages/python";
import json from "highlight.js/lib/languages/json";
import "highlight.js/styles/github-dark.css";

// Register languages
hljs.registerLanguage("javascript", javascript);
hljs.registerLanguage("typescript", typescript);
hljs.registerLanguage("python", python);
hljs.registerLanguage("json", json);

interface CodeBlockProps {
  code: string;
  language?: string;
  highlightLine?: number;
  startLine?: number;
  fileName?: string;
}

export function CodeBlock({
  code,
  language = "javascript",
  highlightLine,
  startLine = 1,
  fileName,
}: CodeBlockProps) {
  const codeRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (codeRef.current) {
      hljs.highlightElement(codeRef.current);
    }
  }, [code, language]);

  const lines = code.split("\n");

  return (
    <div className="rounded-lg overflow-hidden border border-[#2a2a4e]">
      {fileName && (
        <div className="px-4 py-2 bg-[#1a1a2e] border-b border-[#2a2a4e] flex items-center gap-2">
          <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
          </svg>
          <span className="text-xs text-slate-400 mono">{fileName}</span>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <tbody>
            {lines.map((line, i) => {
              const lineNum = startLine + i;
              const isHighlighted = highlightLine === lineNum;
              return (
                <tr
                  key={i}
                  className={isHighlighted ? "bg-red-500/20" : "hover:bg-white/5"}
                >
                  <td className="px-3 py-0 text-right text-xs text-slate-600 select-none w-10 border-r border-[#2a2a4e]">
                    {lineNum}
                  </td>
                  <td className="px-4 py-0">
                    <pre className="!bg-transparent !p-0 !m-0">
                      <code
                        ref={i === 0 ? codeRef : undefined}
                        className={`language-${language} !bg-transparent`}
                      >
                        {line || " "}
                      </code>
                    </pre>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
```

**Step 2: Commit**

```bash
git add dashboard/components/findings/CodeBlock.tsx
git commit -m "feat(dashboard): create CodeBlock component with highlight.js and line highlighting"
```

---

### Task 10: Create FindingDetailPanel (Slide-Over Modal)

**Files:**
- Create: `dashboard/components/findings/FindingDetailPanel.tsx`

**Step 1: Create the slide-over panel with 6 tabs**

Create `dashboard/components/findings/FindingDetailPanel.tsx`:

```tsx
"use client";

import { useState, useEffect } from "react";
import type { Finding } from "@/lib/api";
import { SeverityBadge, VerdictBadge, FixStatusBadge } from "./SeverityBadge";
import { CodeBlock } from "./CodeBlock";

interface FindingDetailPanelProps {
  finding: Finding | null;
  onClose: () => void;
}

const TABS = ["Overview", "Code", "Analysis", "Fix", "Compliance", "Best Practices"] as const;
type Tab = typeof TABS[number];

export function FindingDetailPanel({ finding, onClose }: FindingDetailPanelProps) {
  const [activeTab, setActiveTab] = useState<Tab>("Overview");

  // Reset tab when finding changes
  useEffect(() => {
    setActiveTab("Overview");
  }, [finding?.scan_id]);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  if (!finding) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 z-40 transition-opacity"
        onClick={onClose}
      />

      {/* Slide-over Panel */}
      <div className="fixed inset-y-0 right-0 w-[60%] min-w-[600px] max-w-[900px] bg-[#0d0d14] border-l border-[#2a2a4e] z-50 flex flex-col overflow-hidden animate-slide-in">
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#2a2a4e] flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <SeverityBadge severity={finding.severity} />
              <VerdictBadge verdict={finding.verdict} />
              <FixStatusBadge status={finding.fix_status} />
            </div>
            <h2 className="text-lg font-bold text-white truncate">{finding.vulnerability}</h2>
            <p className="text-sm text-slate-400 mono mt-1">{finding.file}:{finding.line}</p>
            <p className="text-xs text-slate-500 mt-1">{finding.cwe} &middot; Score: {finding.exploitability_score}/100</p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-white/10 text-slate-400 hover:text-white transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Tab Bar */}
        <div className="px-6 border-b border-[#2a2a4e] flex gap-1 overflow-x-auto">
          {TABS.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === tab
                  ? "border-blue-500 text-blue-400"
                  : "border-transparent text-slate-400 hover:text-white"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
          {activeTab === "Overview" && <OverviewTab finding={finding} />}
          {activeTab === "Code" && <CodeTab finding={finding} />}
          {activeTab === "Analysis" && <AnalysisTab finding={finding} />}
          {activeTab === "Fix" && <FixTab finding={finding} />}
          {activeTab === "Compliance" && <ComplianceTab finding={finding} />}
          {activeTab === "Best Practices" && <BestPracticesTab finding={finding} />}
        </div>
      </div>
    </>
  );
}

/* ========== TAB COMPONENTS ========== */

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-2">{title}</h3>
      {children}
    </div>
  );
}

function InfoCard({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg bg-[#1a1a2e] border border-[#2a2a4e] p-4 ${className}`}>
      {children}
    </div>
  );
}

function OverviewTab({ finding }: { finding: Finding }) {
  return (
    <>
      <Section title="Description">
        <InfoCard>
          <p className="text-sm text-slate-300 leading-relaxed">{finding.description}</p>
        </InfoCard>
      </Section>

      <Section title="Evidence">
        <CodeBlock code={finding.evidence} language="javascript" fileName={finding.file} />
      </Section>

      <Section title="Recommendation">
        <InfoCard>
          <p className="text-sm text-slate-300 leading-relaxed">{finding.recommendation}</p>
        </InfoCard>
      </Section>

      {finding.attack_scenario && (
        <Section title="Attack Scenario">
          <InfoCard className="border-red-500/30">
            <p className="text-sm text-red-300 leading-relaxed">{finding.attack_scenario}</p>
          </InfoCard>
        </Section>
      )}

      <div className="grid grid-cols-2 gap-3">
        {finding.auth_context && (
          <Section title="Auth Context">
            <InfoCard>
              <p className="text-xs text-slate-300 mono">{finding.auth_context}</p>
            </InfoCard>
          </Section>
        )}
        {finding.data_sensitivity && (
          <Section title="Data Sensitivity">
            <InfoCard>
              <p className="text-xs text-slate-300 mono">{finding.data_sensitivity}</p>
            </InfoCard>
          </Section>
        )}
      </div>
    </>
  );
}

function CodeTab({ finding }: { finding: Finding }) {
  const ctx = finding.code_context;

  if (!ctx?.vulnerable_code) {
    return (
      <InfoCard>
        <p className="text-sm text-slate-400 text-center py-4">
          No code context available. Run a new scan to capture code context.
        </p>
      </InfoCard>
    );
  }

  return (
    <>
      <Section title="Vulnerable Code">
        <CodeBlock
          code={ctx.vulnerable_code}
          language="javascript"
          highlightLine={finding.line}
          fileName={finding.file}
        />
      </Section>

      {ctx.related_files && ctx.related_files.length > 0 && (
        <Section title="Related Files">
          <div className="space-y-3">
            {ctx.related_files.map((rf, i) => (
              <div key={i}>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs mono text-blue-300">{rf.file}</span>
                  <span className="text-xs text-slate-500">&mdash; {rf.relevance}</span>
                </div>
                <CodeBlock
                  code={rf.snippet || ""}
                  language="javascript"
                  fileName={rf.file}
                />
              </div>
            ))}
          </div>
        </Section>
      )}
    </>
  );
}

function AnalysisTab({ finding }: { finding: Finding }) {
  return (
    <>
      {finding.analysis_reasoning && (
        <Section title="Analysis Reasoning">
          <InfoCard>
            <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">
              {finding.analysis_reasoning}
            </p>
          </InfoCard>
        </Section>
      )}

      <div className="grid grid-cols-2 gap-4">
        <Section title="Verdict">
          <InfoCard>
            <div className="flex items-center gap-2 mb-2">
              <VerdictBadge verdict={finding.verdict} />
              <span className="text-2xl font-bold text-white">{finding.exploitability_score}/100</span>
            </div>
          </InfoCard>
        </Section>

        <Section title="Auth Context">
          <InfoCard>
            <p className="text-sm text-slate-300">{finding.auth_context || "N/A"}</p>
          </InfoCard>
        </Section>
      </div>

      {finding.confirmed_evidence && (
        <Section title="Confirmed Evidence">
          <CodeBlock code={finding.confirmed_evidence} language="javascript" />
        </Section>
      )}

      {finding.false_positive_reason && (
        <Section title="False Positive Reason">
          <InfoCard className="border-green-500/30">
            <p className="text-sm text-green-300">{finding.false_positive_reason}</p>
          </InfoCard>
        </Section>
      )}
    </>
  );
}

function FixTab({ finding }: { finding: Finding }) {
  return (
    <>
      <Section title="Fix Status">
        <InfoCard>
          <div className="flex items-center gap-3 mb-3">
            <FixStatusBadge status={finding.fix_status} />
            {finding.pr_url && (
              <a
                href={finding.pr_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-400 hover:text-blue-300 text-sm underline"
              >
                PR #{finding.pr_number}
              </a>
            )}
          </div>
          {finding.fix_summary && (
            <p className="text-sm text-slate-300">{finding.fix_summary}</p>
          )}
          {finding.fix_error && (
            <p className="text-sm text-red-400 mt-2">{finding.fix_error}</p>
          )}
        </InfoCard>
      </Section>

      {finding.fix_explanation && (
        <Section title="Fix Explanation">
          <InfoCard>
            <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">
              {finding.fix_explanation}
            </p>
          </InfoCard>
        </Section>
      )}

      {finding.fixed_code && (
        <Section title="Fixed Code">
          <CodeBlock
            code={finding.fixed_code}
            language="javascript"
            fileName={`${finding.file} (fixed)`}
          />
        </Section>
      )}

      {!finding.fixed_code && finding.fix_status === "PENDING" && (
        <InfoCard>
          <p className="text-sm text-slate-400 text-center py-4">
            Fix has not been generated yet.
          </p>
        </InfoCard>
      )}
    </>
  );
}

function ComplianceTab({ finding }: { finding: Finding }) {
  // Compliance data comes from the scan-level compliance output,
  // not per-finding. Show a placeholder directing to the compliance page.
  return (
    <InfoCard>
      <p className="text-sm text-slate-400 text-center py-4">
        View detailed PCI-DSS 4.0 compliance mapping on the{" "}
        <span className="text-blue-400">Compliance</span> page.
      </p>
      <div className="text-center mt-2">
        <span className="text-xs text-slate-500">
          CWE: {finding.cwe} &middot; Severity: {finding.severity}
        </span>
      </div>
    </InfoCard>
  );
}

function BestPracticesTab({ finding }: { finding: Finding }) {
  const bp = finding.best_practices_analysis;

  if (!bp) {
    return (
      <InfoCard>
        <p className="text-sm text-slate-400 text-center py-4">
          No best practices analysis available. Run a new scan to generate this data.
        </p>
      </InfoCard>
    );
  }

  return (
    <>
      {bp.violated_practices.length > 0 && (
        <Section title={`Violated Practices (${bp.violated_practices.length})`}>
          <div className="space-y-2">
            {bp.violated_practices.map((v, i) => (
              <InfoCard key={i} className="border-red-500/20">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-red-400">{v.practice}</span>
                  <span className="text-xs text-slate-500 badge">{v.category}</span>
                </div>
                <p className="text-xs text-slate-400 mb-1">
                  <span className="text-slate-500">Current:</span> {v.current_state}
                </p>
                <p className="text-xs text-green-400">
                  <span className="text-slate-500">Recommended:</span> {v.recommended_state}
                </p>
                {v.owasp_reference && (
                  <p className="text-xs text-slate-500 mt-1">{v.owasp_reference}</p>
                )}
              </InfoCard>
            ))}
          </div>
        </Section>
      )}

      {bp.followed_practices.length > 0 && (
        <Section title={`Followed Practices (${bp.followed_practices.length})`}>
          <div className="space-y-2">
            {bp.followed_practices.map((fp, i) => (
              <InfoCard key={i} className="border-green-500/20">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-green-400">{fp.practice}</span>
                  <span className="text-xs text-slate-500 badge">{fp.category}</span>
                </div>
                <p className="text-xs text-slate-400">{fp.detail}</p>
              </InfoCard>
            ))}
          </div>
        </Section>
      )}
    </>
  );
}
```

**Step 2: Add slide-in animation to globals.css**

Add to `dashboard/app/globals.css`:

```css
@keyframes slide-in {
  from { transform: translateX(100%); }
  to { transform: translateX(0); }
}

.animate-slide-in {
  animation: slide-in 0.2s ease-out;
}
```

**Step 3: Commit**

```bash
git add dashboard/components/findings/FindingDetailPanel.tsx dashboard/app/globals.css
git commit -m "feat(dashboard): create FindingDetailPanel slide-over modal with 6 tabs"
```

---

### Task 11: Update Findings Page with Row Click + Extended API Types

**Files:**
- Modify: `dashboard/lib/api.ts` (extend Finding interface, add new API functions)
- Modify: `dashboard/app/scans/[id]/findings/page.tsx` (add row click, import panel)
- Modify: `dashboard/components/findings/SeverityBadge.tsx` (add FIX_GENERATED)
- Modify: `dashboard/lib/utils.ts` (add FIX_GENERATED color)

**Step 1: Extend Finding interface in api.ts**

In `dashboard/lib/api.ts`, replace the Finding interface (lines 80-97) with:

```typescript
export interface CodeContext {
  vulnerable_code: string;
  related_files: Array<{
    file: string;
    relevance: string;
    snippet: string;
  }>;
}

export interface BestPracticeViolation {
  practice: string;
  category: string;
  current_state: string;
  recommended_state: string;
  owasp_reference: string;
}

export interface BestPracticeFollowed {
  practice: string;
  category: string;
  detail: string;
}

export interface BestPracticesAnalysis {
  violated_practices: BestPracticeViolation[];
  followed_practices: BestPracticeFollowed[];
}

export interface Finding {
  scan_id: string;
  anlz_id: string;
  file: string;
  line: number;
  vulnerability: string;
  cwe: string;
  severity: string;
  description: string;
  evidence: string;
  recommendation: string;
  verdict: string;
  exploitability_score: number;
  fix_status: string;
  fix_summary: string | null;
  pr_url: string | null;
  pr_number: number | null;
  // New fields
  code_context: CodeContext | null;
  analysis_reasoning: string;
  best_practices_analysis: BestPracticesAnalysis | null;
  fixed_code: string;
  fix_explanation: string;
  fix_error: string;
  auth_context: string;
  data_sensitivity: string;
  attack_scenario: string | null;
  false_positive_reason: string | null;
  confirmed_evidence: string | null;
  status_change: string | null;
}
```

**Step 2: Add parent_scan_id to ScanSummary and ScanDetail**

In `dashboard/lib/api.ts`, add to ScanSummary (after `error: string | null`):

```typescript
  parent_scan_id: string | null;
  scan_number: number;
```

Add to ScanDetail (after `stages: Record<string, string>`):

```typescript
  comparison: ScanComparison | null;
```

**Step 3: Add new interfaces and functions at end of api.ts**

```typescript
// Scan Comparison
export interface ScanComparisonFinding {
  scan_id: string;
  vulnerability: string;
  cwe: string;
  file: string;
  severity: string;
  status_change: string;
}

export interface ScanComparison {
  current_scan_id: string;
  parent_scan_id: string;
  new_findings: number;
  resolved_findings: number;
  persistent_findings: number;
  regression_findings: number;
  findings: ScanComparisonFinding[];
}

// Practices
export interface PracticesSummary {
  scan_id: string;
  total_violations: number;
  total_followed: number;
  maturity_score: number;
  categories: Record<string, { violations: number; followed: number }>;
  top_violations: BestPracticeViolation[];
  top_followed: BestPracticeFollowed[];
  anti_patterns: Array<{
    practice: string;
    occurrences: number;
    category: string;
  }>;
}

export async function getScanHistory(scanId: string) {
  return fetchAPI<ScanSummary[]>(`/api/scans/${scanId}/history`);
}

export async function getPractices(scanId: string) {
  return fetchAPI<PracticesSummary>(`/api/scans/${scanId}/practices`);
}
```

**Step 4: Add FIX_GENERATED color to utils.ts**

In `dashboard/lib/utils.ts`, replace the fixStatusColor record (lines 49-54) with:

```typescript
export const fixStatusColor: Record<string, string> = {
  SUCCESS: "text-green-400 bg-green-400/10 border-green-400/30",
  DRY_RUN: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  FAILED: "text-red-400 bg-red-400/10 border-red-400/30",
  PENDING: "text-gray-400 bg-gray-400/10 border-gray-400/30",
  FIX_GENERATED: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  PARTIAL: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  N_A: "text-gray-400 bg-gray-400/10 border-gray-400/30",
};

export const statusChangeColor: Record<string, string> = {
  NEW: "text-red-400 bg-red-400/10 border-red-400/30",
  RESOLVED: "text-green-400 bg-green-400/10 border-green-400/30",
  PERSISTENT: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  REGRESSION: "text-orange-400 bg-orange-400/10 border-orange-400/30",
};
```

**Step 5: Update FixStatusBadge**

In `dashboard/components/findings/SeverityBadge.tsx`, replace FixStatusBadge (lines 29-41) with:

```tsx
export function FixStatusBadge({ status }: { status: string }) {
  const colorMap: Record<string, string> = {
    SUCCESS: "text-green-400 bg-green-400/10 border-green-400/30",
    DRY_RUN: "text-blue-400 bg-blue-400/10 border-blue-400/30",
    FAILED: "text-red-400 bg-red-400/10 border-red-400/30",
    PENDING: "text-gray-400 bg-gray-400/10 border-gray-400/30",
    FIX_GENERATED: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
    PARTIAL: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  };

  const labelMap: Record<string, string> = {
    SUCCESS: "Fixed",
    DRY_RUN: "Dry Run",
    FAILED: "Failed",
    PENDING: "Pending",
    FIX_GENERATED: "Fix Ready",
    PARTIAL: "Partial",
  };

  return (
    <span className={`badge ${colorMap[status] || colorMap.PENDING}`}>
      {labelMap[status] || status}
    </span>
  );
}

export function StatusChangeBadge({ status }: { status: string }) {
  const colorMap: Record<string, string> = {
    NEW: "text-red-400 bg-red-400/10 border-red-400/30",
    RESOLVED: "text-green-400 bg-green-400/10 border-green-400/30",
    PERSISTENT: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
    REGRESSION: "text-orange-400 bg-orange-400/10 border-orange-400/30",
  };

  return (
    <span className={`badge ${colorMap[status] || "text-gray-400 bg-gray-400/10 border-gray-400/30"}`}>
      {status}
    </span>
  );
}
```

**Step 6: Update findings page with row click handler**

Replace the entire `dashboard/app/scans/[id]/findings/page.tsx` with the version that imports and uses FindingDetailPanel, adds onClick handlers to table rows, and manages selected finding state. The key changes:

- Add `useState` for `selectedFinding`
- Add `onClick={() => setSelectedFinding(f)}` to each `<tr>`
- Add `cursor-pointer` to `<tr>` className
- Render `<FindingDetailPanel>` at the end

```tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { getFindings, type Finding, type FindingsResponse } from "@/lib/api";
import { SeverityBadge, VerdictBadge, FixStatusBadge } from "@/components/findings/SeverityBadge";
import { FindingDetailPanel } from "@/components/findings/FindingDetailPanel";

export default function FindingsPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [data, setData] = useState<FindingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const fetchFindings = useCallback(async () => {
    try {
      const result = await getFindings(scanId, {
        severity: severityFilter || undefined,
        verdict: verdictFilter || undefined,
      });
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load findings");
    } finally {
      setLoading(false);
    }
  }, [scanId, severityFilter, verdictFilter]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  if (loading) {
    return <div className="p-6 text-center text-slate-400">Loading findings...</div>;
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="card text-center py-8">
          <p className="text-red-400">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link href="/scans" className="hover:text-white transition-colors">Scans</Link>
        <span>/</span>
        <Link href={`/scans/${scanId}`} className="mono text-blue-400 hover:text-blue-300 transition-colors">
          {scanId}
        </Link>
        <span>/</span>
        <span className="text-white">Findings</span>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Vulnerability Findings</h1>
          <p className="text-sm text-slate-400 mt-1">
            {data?.total || 0} findings &middot;{" "}
            <span className="text-red-400">{data?.confirmed || 0} confirmed</span> &middot;{" "}
            <span className="text-green-400">{data?.fixed || 0} fixed</span>
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-4">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-1.5 rounded-lg bg-[#1a1a2e] border border-[#2a2a4e] text-sm text-white"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select
          value={verdictFilter}
          onChange={(e) => setVerdictFilter(e.target.value)}
          className="px-3 py-1.5 rounded-lg bg-[#1a1a2e] border border-[#2a2a4e] text-sm text-white"
        >
          <option value="">All Verdicts</option>
          <option value="CONFIRMED">Confirmed</option>
          <option value="FALSE_POSITIVE">False Positive</option>
        </select>
      </div>

      {/* Findings Table */}
      <div className="card overflow-hidden p-0">
        <table className="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Vulnerability</th>
              <th>File</th>
              <th>CWE</th>
              <th>Score</th>
              <th>Verdict</th>
              <th>Fix</th>
            </tr>
          </thead>
          <tbody>
            {data?.findings.map((f, i) => (
              <tr
                key={i}
                onClick={() => setSelectedFinding(f)}
                className="cursor-pointer hover:bg-blue-500/5 transition-colors"
              >
                <td><SeverityBadge severity={f.severity} /></td>
                <td>
                  <div className="font-medium text-white text-sm">{f.vulnerability}</div>
                  <div className="text-xs text-slate-400 mt-0.5 max-w-xs truncate">
                    {f.description}
                  </div>
                </td>
                <td>
                  <div className="mono text-xs text-blue-300">{f.file}</div>
                  <div className="text-xs text-slate-500">Line {f.line}</div>
                </td>
                <td className="mono text-xs text-slate-300">{f.cwe}</td>
                <td>
                  <div className={`font-bold text-sm ${
                    f.exploitability_score >= 80 ? "text-red-400" :
                    f.exploitability_score >= 60 ? "text-orange-400" :
                    f.exploitability_score >= 40 ? "text-yellow-400" :
                    "text-blue-400"
                  }`}>
                    {f.exploitability_score}
                  </div>
                </td>
                <td><VerdictBadge verdict={f.verdict} /></td>
                <td>
                  <div className="flex items-center gap-2">
                    <FixStatusBadge status={f.fix_status} />
                    {f.pr_url && (
                      <a
                        href={f.pr_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-400 hover:text-blue-300 text-xs"
                        onClick={(e) => e.stopPropagation()}
                      >
                        PR #{f.pr_number}
                      </a>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {(!data?.findings || data.findings.length === 0) && (
          <div className="text-center py-8 text-slate-400 text-sm">
            No findings match the current filters
          </div>
        )}
      </div>

      {/* Finding Detail Panel */}
      <FindingDetailPanel
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
```

**Step 7: Verify dashboard builds**

Run: `cd dashboard && npx next build`
Expected: Build succeeds

**Step 8: Commit**

```bash
git add dashboard/lib/api.ts dashboard/lib/utils.ts dashboard/components/findings/SeverityBadge.tsx dashboard/app/scans/[id]/findings/page.tsx
git commit -m "feat(dashboard): wire up FindingDetailPanel with row click, extend API types, update badges"
```

---

## Phase 4: Dashboard — Re-Scan & History

### Task 12: Add Re-Scan Button to Scan Detail Page

**Files:**
- Modify: `dashboard/app/scans/[id]/page.tsx` (add Re-Scan button, comparison banner)
- Modify: `dashboard/components/scans/NewScanDialog.tsx` (accept parentScanId prop)

**Step 1: Add Re-Scan button and ComparisonBanner to scan detail page**

In `dashboard/app/scans/[id]/page.tsx`, add after the header `</div>` (line 93), before Pipeline Status:

```tsx
      {/* Comparison Banner (for re-scans) */}
      {scan.comparison && (
        <div className="card mb-6 border-blue-500/30">
          <h3 className="text-sm font-medium text-blue-400 mb-3">Re-Scan Comparison</h3>
          <div className="grid grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-red-400">{scan.comparison.new_findings}</div>
              <div className="text-xs text-slate-400">New</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-400">{scan.comparison.resolved_findings}</div>
              <div className="text-xs text-slate-400">Resolved</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-400">{scan.comparison.persistent_findings}</div>
              <div className="text-xs text-slate-400">Persistent</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-400">{scan.comparison.regression_findings}</div>
              <div className="text-xs text-slate-400">Regressions</div>
            </div>
          </div>
        </div>
      )}
```

Add a Re-Scan button inside the header div (before closing `</div>` at line 93):

```tsx
        {scan.status === "COMPLETED" && (
          <button
            onClick={() => setShowRescan(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-blue-600 text-white hover:bg-blue-500 text-sm font-medium transition-colors"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Re-Scan
          </button>
        )}
```

Add state and imports at the top:

```tsx
import { NewScanDialog } from "@/components/scans/NewScanDialog";

// Inside the component, add:
const [showRescan, setShowRescan] = useState(false);
```

Add dialog at the bottom (before closing `</div>`):

```tsx
      <NewScanDialog
        open={showRescan}
        onClose={() => setShowRescan(false)}
        onCreated={() => {
          setShowRescan(false);
          fetchScan();
        }}
        parentScanId={scan.id}
        defaultRepo={scan.repository_path}
      />
```

**Step 2: Update NewScanDialog to accept parentScanId**

Check the NewScanDialog component and add optional `parentScanId` and `defaultRepo` props that get passed to the `createScan` API call.

**Step 3: Add "Best Practices" to scan detail navTabs**

In `dashboard/app/scans/[id]/page.tsx`, update the navTabs array:

```tsx
  const navTabs = [
    { label: "Findings", href: `/scans/${scanId}/findings`, ready: !!scan.analyzer_output },
    { label: "Risk Profile", href: `/scans/${scanId}/risk-profile`, ready: !!scan.analyzer_output },
    { label: "Compliance", href: `/scans/${scanId}/compliance`, ready: !!scan.compliance_output },
    { label: "Best Practices", href: `/scans/${scanId}/practices`, ready: !!scan.analyzer_output },
  ];
```

**Step 4: Commit**

```bash
git add dashboard/app/scans/[id]/page.tsx dashboard/components/scans/NewScanDialog.tsx
git commit -m "feat(dashboard): add Re-Scan button, comparison banner, and Best Practices nav tab"
```

---

## Phase 5: Dashboard — Best Practices Page

### Task 13: Create Best Practices Page

**Files:**
- Create: `dashboard/app/scans/[id]/practices/page.tsx`

**Step 1: Create the practices page**

Create `dashboard/app/scans/[id]/practices/page.tsx`:

```tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { getPractices, type PracticesSummary } from "@/lib/api";

function MaturityScoreRing({ score }: { score: number }) {
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 70 ? "#22c55e" : score >= 40 ? "#eab308" : "#ef4444";

  return (
    <div className="relative w-32 h-32">
      <svg className="w-32 h-32 transform -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={radius} fill="none" stroke="#1a1a2e" strokeWidth="8" />
        <circle
          cx="50" cy="50" r={radius} fill="none"
          stroke={color} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          className="transition-all duration-1000 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-white">{score}</span>
        <span className="text-xs text-slate-400">/ 100</span>
      </div>
    </div>
  );
}

export default function PracticesPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [data, setData] = useState<PracticesSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchPractices = useCallback(async () => {
    try {
      const result = await getPractices(scanId);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load practices");
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    fetchPractices();
  }, [fetchPractices]);

  if (loading) return <div className="p-6 text-center text-slate-400">Loading practices...</div>;
  if (error) return <div className="p-6"><div className="card text-center py-8"><p className="text-red-400">{error}</p></div></div>;
  if (!data) return null;

  return (
    <div className="p-6 max-w-7xl mx-auto">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-400 mb-4">
        <Link href="/scans" className="hover:text-white transition-colors">Scans</Link>
        <span>/</span>
        <Link href={`/scans/${scanId}`} className="mono text-blue-400 hover:text-blue-300 transition-colors">{scanId}</Link>
        <span>/</span>
        <span className="text-white">Best Practices</span>
      </div>

      {/* Header with Maturity Score */}
      <div className="flex items-center gap-8 mb-8">
        <MaturityScoreRing score={data.maturity_score} />
        <div>
          <h1 className="text-2xl font-bold text-white">Security Maturity Score</h1>
          <p className="text-sm text-slate-400 mt-1">
            {data.total_violations} violations &middot; {data.total_followed} good practices
          </p>
          <p className="text-xs text-slate-500 mt-2">
            Score based on the ratio of followed to violated security best practices across all findings.
          </p>
        </div>
      </div>

      {/* Category Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        {Object.entries(data.categories).map(([category, stats]) => {
          const total = stats.violations + stats.followed;
          const pct = total > 0 ? Math.round((stats.followed / total) * 100) : 0;
          return (
            <div key={category} className="card">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-white">{category}</span>
                <span className={`text-sm font-bold ${pct >= 70 ? "text-green-400" : pct >= 40 ? "text-yellow-400" : "text-red-400"}`}>
                  {pct}%
                </span>
              </div>
              <div className="w-full h-2 rounded-full bg-[#1a1a2e] overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${pct}%`,
                    backgroundColor: pct >= 70 ? "#22c55e" : pct >= 40 ? "#eab308" : "#ef4444",
                  }}
                />
              </div>
              <div className="flex justify-between mt-1 text-xs text-slate-500">
                <span>{stats.followed} followed</span>
                <span>{stats.violations} violated</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Anti-Patterns */}
      {data.anti_patterns.length > 0 && (
        <div className="mb-8">
          <h2 className="text-lg font-bold text-white mb-4">Recurring Anti-Patterns</h2>
          <div className="space-y-3">
            {data.anti_patterns.map((ap, i) => (
              <div key={i} className="card flex items-center gap-4 border-red-500/20">
                <div className="w-12 h-12 rounded-lg bg-red-500/10 flex items-center justify-center">
                  <span className="text-xl font-bold text-red-400">{ap.occurrences}x</span>
                </div>
                <div>
                  <div className="text-sm font-medium text-white">{ap.practice}</div>
                  <div className="text-xs text-slate-400">{ap.category}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top Violations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div>
          <h2 className="text-lg font-bold text-red-400 mb-4">Top Violations</h2>
          <div className="space-y-2">
            {data.top_violations.map((v, i) => (
              <div key={i} className="card border-red-500/20 p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-white">{v.practice}</span>
                  <span className="text-xs text-slate-500 badge">{v.category}</span>
                </div>
                <p className="text-xs text-slate-400">{v.current_state}</p>
                <p className="text-xs text-green-400 mt-1">{v.recommended_state}</p>
              </div>
            ))}
            {data.top_violations.length === 0 && (
              <p className="text-sm text-slate-400">No violations found</p>
            )}
          </div>
        </div>

        <div>
          <h2 className="text-lg font-bold text-green-400 mb-4">Good Practices</h2>
          <div className="space-y-2">
            {data.top_followed.map((fp, i) => (
              <div key={i} className="card border-green-500/20 p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-white">{fp.practice}</span>
                  <span className="text-xs text-slate-500 badge">{fp.category}</span>
                </div>
                <p className="text-xs text-slate-400">{fp.detail}</p>
              </div>
            ))}
            {data.top_followed.length === 0 && (
              <p className="text-sm text-slate-400">No good practices found</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
```

**Step 2: Commit**

```bash
git add dashboard/app/scans/[id]/practices/page.tsx
git commit -m "feat(dashboard): create Best Practices page with maturity score, categories, and anti-patterns"
```

---

### Task 14: Register Practices Router in API Main

**Files:**
- Modify: `api/main.py` (import and include practices router)

**Step 1: Find and update main.py**

Look at the existing router imports in `api/main.py` and add:

```python
from routers.practices import router as practices_router
app.include_router(practices_router)
```

**Step 2: Verify full API starts**

Run: `cd api && python -c "from main import app; print('Routes:', [r.path for r in app.routes][:10])"`
Expected: Shows routes including `/api/scans/{scan_id}/practices`

**Step 3: Commit**

```bash
git add api/main.py
git commit -m "feat(api): register practices router in FastAPI app"
```

---

### Task 15: Add Best Practices to Sidebar Navigation

**Files:**
- Modify: `dashboard/components/layout/Sidebar.tsx` (add Practices nav item)

**Step 1: Add Practices to navItems**

In `dashboard/components/layout/Sidebar.tsx`, add to the navItems array after the Scans item:

```tsx
  {
    label: "Practices",
    href: "/practices",
    icon: (
      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
  },
```

Note: The /practices route is per-scan, so this sidebar link would need the latest scan context. For the hackathon, the primary entry point is the scan detail navTabs (already added in Task 12). The sidebar item is optional.

**Step 2: Commit**

```bash
git add dashboard/components/layout/Sidebar.tsx
git commit -m "feat(dashboard): add Best Practices to sidebar navigation"
```

---

### Task 16: Final Build Verification

**Step 1: Verify API starts**

Run: `cd api && python -c "from main import app; print('API OK')"`

**Step 2: Verify dashboard builds**

Run: `cd dashboard && npx next build`

**Step 3: Run end-to-end verification**

Start the API, create a scan, wait for completion, verify new fields in findings response:

```bash
cd api && python -m uvicorn main:app --port 8000 &
sleep 2
curl -s http://localhost:8000/api/health | python -m json.tool
curl -s -X POST http://localhost:8000/api/scans -H "Content-Type: application/json" -d '{"repository_path": "demo-app", "dry_run": true}' | python -m json.tool
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete winning features implementation - modal, fix status, re-scan, best practices"
```

---

## Implementation Order Summary

| # | Task | Layer | Time Est. | Critical Path |
|---|------|-------|-----------|---------------|
| 1 | Scanner code_context | Agent | 15 min | Yes |
| 2 | Analyzer reasoning + best practices | Agent | 20 min | Yes |
| 3 | Fixer fixed_code storage | Agent | 10 min | Yes |
| 4 | API schema extensions | API | 15 min | Yes |
| 5 | Findings merge enrichment | API | 15 min | Yes |
| 6 | Re-scan support (models + router) | API | 20 min | Feature 3 |
| 7 | Practices endpoint + comparison | API | 25 min | Feature 4 |
| 8 | Install highlight.js | Dashboard | 2 min | Feature 1 |
| 9 | CodeBlock component | Dashboard | 10 min | Feature 1 |
| 10 | FindingDetailPanel (6 tabs) | Dashboard | 30 min | Feature 1 |
| 11 | Findings page + API types + badges | Dashboard | 20 min | Feature 1 |
| 12 | Re-Scan button + comparison banner | Dashboard | 15 min | Feature 3 |
| 13 | Best Practices page | Dashboard | 25 min | Feature 4 |
| 14 | Register practices router | API | 5 min | Feature 4 |
| 15 | Sidebar navigation update | Dashboard | 5 min | Optional |
| 16 | Final build verification | All | 10 min | Yes |

**Total estimated time: ~4-5 hours of coding** (excluding LLM response time during actual scans)

## Dependencies

```
Task 1,2,3 (agents) → Task 4,5 (schemas + merge) → Task 8,9,10,11 (modal)
Task 6 (re-scan models) → Task 12 (re-scan UI)
Task 7 (practices endpoint) → Task 13,14 (practices page)
Task 4 (schemas) blocks all API tasks
Task 8 (highlight.js) blocks Task 9,10
```

Tasks 1, 2, 3 can run in parallel.
Tasks 8, 9, 10 are sequential.
Tasks 6+12 and 7+13 can run in parallel with the modal work.
