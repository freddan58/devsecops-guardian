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

    # Merge analyzer findings with fixer results
    findings = []
    for f in scan.analyzer_output.get("findings", []):
        scan_ref = f.get("scan_id", "")
        fix = fixer_lookup.get(scan_ref, {})

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
            fix_status=fix.get("status", "PENDING"),
            fix_summary=fix.get("fix_summary"),
            pr_url=fix.get("pr_url"),
            pr_number=fix.get("pr_number"),
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
