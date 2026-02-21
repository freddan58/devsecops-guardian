"""
DevSecOps Guardian - API Pydantic Schemas
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------- Enums ----------

class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    SCANNING = "SCANNING"
    ANALYZING = "ANALYZING"
    FIXING = "FIXING"
    PROFILING = "PROFILING"
    COMPLIANCE_CHECK = "COMPLIANCE_CHECK"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class FixStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    DRY_RUN = "DRY_RUN"
    PENDING = "PENDING"
    FIX_GENERATED = "FIX_GENERATED"
    PARTIAL = "PARTIAL"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


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


# ---------- Requests ----------

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


# ---------- Responses ----------

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


class ScanDetail(ScanSummary):
    scanner_output: Optional[dict[str, Any]] = None
    analyzer_output: Optional[dict[str, Any]] = None
    fixer_output: Optional[dict[str, Any]] = None
    risk_profile_output: Optional[dict[str, Any]] = None
    compliance_output: Optional[dict[str, Any]] = None
    stages: dict[str, str] = Field(default_factory=dict)
    comparison: Optional[dict[str, Any]] = None


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


class FindingsResponse(BaseModel):
    scan_id: str
    total: int
    confirmed: int
    false_positives: int
    fixed: int
    findings: list[Finding]


class ComplianceRequirement(BaseModel):
    requirement_id: str
    requirement_title: str
    relevance: str = ""
    compliance_status: str = ""
    evidence: str = ""
    remediation_status: str = ""
    remediation_evidence: str = ""


class ComplianceFinding(BaseModel):
    scan_id: str
    vulnerability: str
    cwe: str
    severity: str
    pci_dss_requirements: list[ComplianceRequirement]
    risk_rating: str = ""
    risk_justification: str = ""
    regulatory_impact: str = ""


class ComplianceResponse(BaseModel):
    scan_id: str
    framework: str = "PCI-DSS 4.0"
    overall_risk_rating: str = ""
    compliant_count: int = 0
    non_compliant_count: int = 0
    executive_summary: str = ""
    findings: list[ComplianceFinding]
    recommendations: list[str] = Field(default_factory=list)


class OWASPCategory(BaseModel):
    category: str
    score: int = 0
    findings_count: int = 0
    description: str = ""


class RiskProfileResponse(BaseModel):
    scan_id: str
    overall_risk_score: int = 0
    risk_level: str = "UNKNOWN"
    owasp_top_10: list[OWASPCategory] = Field(default_factory=list)
    attack_surface: dict[str, Any] = Field(default_factory=dict)
    executive_summary: str = ""


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


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    agents: dict[str, str] = Field(default_factory=dict)
