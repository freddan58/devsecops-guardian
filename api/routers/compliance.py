"""
DevSecOps Guardian - Compliance Router

PCI-DSS 4.0 compliance assessment data.
"""

import json
import os

from fastapi import APIRouter, HTTPException

from config import REPORTS_DIR
from models import scan_store
from schemas import (
    ComplianceResponse,
    ComplianceFinding,
    ComplianceRequirement,
)

router = APIRouter(prefix="/api/scans", tags=["compliance"])


def _load_from_disk(scan_id: str, filename: str) -> dict | None:
    """Load agent output from disk when Table Storage data is truncated."""
    path = os.path.join(REPORTS_DIR, scan_id, filename)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return None


def _get_output(scan, attr: str, disk_filename: str) -> dict | None:
    """Get agent output, falling back to disk if Table Storage data is truncated."""
    data = getattr(scan, attr, None)
    if data and data.get("_truncated"):
        disk_data = _load_from_disk(scan.id, disk_filename)
        if disk_data:
            return disk_data
    return data


@router.get("/{scan_id}/compliance", response_model=ComplianceResponse)
async def get_compliance(scan_id: str):
    """Get PCI-DSS 4.0 compliance assessment for a scan.

    Returns compliance mapping, risk rating, and remediation status
    for each finding against PCI-DSS 4.0 requirements.
    """
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    data = _get_output(scan, "compliance_output", "compliance-output.json")
    if not data:
        raise HTTPException(
            status_code=400,
            detail="Compliance assessment has not completed yet"
        )

    # Parse compliance findings
    findings = []
    for f in data.get("findings", []):
        reqs = [
            ComplianceRequirement(
                requirement_id=r.get("requirement_id", ""),
                requirement_title=r.get("requirement_title", ""),
                relevance=r.get("relevance", ""),
                compliance_status=r.get("compliance_status", ""),
                evidence=r.get("evidence", ""),
                remediation_status=r.get("remediation_status", ""),
                remediation_evidence=r.get("remediation_evidence", ""),
            )
            for r in f.get("pci_dss_requirements", [])
        ]

        findings.append(ComplianceFinding(
            scan_id=f.get("scan_id", ""),
            vulnerability=f.get("vulnerability", ""),
            cwe=f.get("cwe", ""),
            severity=f.get("severity", ""),
            pci_dss_requirements=reqs,
            risk_rating=f.get("risk_rating", ""),
            risk_justification=f.get("risk_justification", ""),
            regulatory_impact=f.get("regulatory_impact", ""),
        ))

    return ComplianceResponse(
        scan_id=scan_id,
        framework=data.get("framework", "PCI-DSS 4.0"),
        overall_risk_rating=data.get("overall_risk_rating", ""),
        compliant_count=data.get("compliant_count", 0),
        non_compliant_count=data.get("non_compliant_count", 0),
        executive_summary=data.get("executive_summary", ""),
        findings=findings,
        recommendations=data.get("recommendations", []),
    )
