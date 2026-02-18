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


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


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


class ScanDetail(ScanSummary):
    scanner_output: Optional[dict[str, Any]] = None
    analyzer_output: Optional[dict[str, Any]] = None
    fixer_output: Optional[dict[str, Any]] = None
    risk_profile_output: Optional[dict[str, Any]] = None
    compliance_output: Optional[dict[str, Any]] = None
    stages: dict[str, str] = Field(default_factory=dict)


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


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"
    agents: dict[str, str] = Field(default_factory=dict)
