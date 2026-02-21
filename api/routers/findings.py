"""
DevSecOps Guardian - Findings Router

Merged view of analyzer findings + fixer results.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional

from models import scan_store
from schemas import Finding, FindingsResponse

router = APIRouter(prefix="/api/scans", tags=["findings"])


@router.get("/{scan_id}/findings", response_model=FindingsResponse)
async def get_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    verdict: Optional[str] = Query(None, description="Filter by verdict"),
):
    """Get merged findings from Analyzer + Fixer for a scan.

    Combines analyzer verdicts with fixer status to produce a unified
    findings view. Supports filtering by severity and verdict.
    """
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    if not scan.analyzer_output:
        raise HTTPException(
            status_code=400,
            detail="Analyzer has not completed yet"
        )

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

    confirmed = sum(1 for f in findings if f.verdict == "CONFIRMED")
    false_pos = sum(1 for f in findings if f.verdict == "FALSE_POSITIVE")
    fixed = sum(1 for f in findings if f.fix_status == "SUCCESS")

    return FindingsResponse(
        scan_id=scan_id,
        total=len(findings),
        confirmed=confirmed,
        false_positives=false_pos,
        fixed=fixed,
        findings=findings,
    )
