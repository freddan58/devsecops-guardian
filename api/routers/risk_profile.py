"""
DevSecOps Guardian - Risk Profile Router

OWASP Top 10 risk profile data.
"""

from fastapi import APIRouter, HTTPException

from models import scan_store
from schemas import RiskProfileResponse, OWASPCategory

router = APIRouter(prefix="/api/scans", tags=["risk-profile"])


# OWASP Top 10 2021 categories
OWASP_CATEGORIES = [
    "A01:2021 - Broken Access Control",
    "A02:2021 - Cryptographic Failures",
    "A03:2021 - Injection",
    "A04:2021 - Insecure Design",
    "A05:2021 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components",
    "A07:2021 - Identification and Authentication Failures",
    "A08:2021 - Software and Data Integrity Failures",
    "A09:2021 - Security Logging and Monitoring Failures",
    "A10:2021 - Server-Side Request Forgery (SSRF)",
]


@router.get("/{scan_id}/risk-profile", response_model=RiskProfileResponse)
async def get_risk_profile(scan_id: str):
    """Get OWASP Top 10 risk profile for a scan.

    Returns overall risk score, OWASP category breakdown,
    attack surface analysis, and executive summary.
    If the Risk Profiler agent hasn't run, generates a basic profile
    from the analyzer output.
    """
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    # If risk profiler agent output is available, use it directly
    if scan.risk_profile_output:
        data = scan.risk_profile_output
        owasp = []
        for key, val in data.get("owasp_top_10", {}).items():
            if isinstance(val, dict):
                owasp.append(OWASPCategory(
                    category=key.replace("_", " "),
                    score=val.get("score", 0),
                    findings_count=val.get("findings", 0),
                    description=val.get("description", ""),
                ))
            else:
                owasp.append(OWASPCategory(
                    category=key.replace("_", " "),
                    score=val if isinstance(val, int) else 0,
                ))

        return RiskProfileResponse(
            scan_id=scan_id,
            overall_risk_score=data.get("overall_risk_score", 0),
            risk_level=data.get("risk_level", "UNKNOWN"),
            owasp_top_10=owasp,
            attack_surface=data.get("attack_surface", {}),
            executive_summary=data.get("executive_summary", ""),
        )

    # Fallback: generate basic risk profile from analyzer findings
    if not scan.analyzer_output:
        raise HTTPException(
            status_code=400,
            detail="No risk profile or analyzer data available yet"
        )

    return _generate_basic_profile(scan_id, scan.analyzer_output)


def _generate_basic_profile(
    scan_id: str,
    analyzer_output: dict,
) -> RiskProfileResponse:
    """Generate a basic risk profile from analyzer findings.

    Maps CWEs to OWASP Top 10 categories and calculates a risk score.
    Used as a fallback when the Risk Profiler agent hasn't run.
    """
    # CWE to OWASP mapping
    cwe_to_owasp = {
        "CWE-89": "A03:2021 - Injection",
        "CWE-79": "A03:2021 - Injection",
        "CWE-78": "A03:2021 - Injection",
        "CWE-798": "A07:2021 - Identification and Authentication Failures",
        "CWE-862": "A01:2021 - Broken Access Control",
        "CWE-639": "A01:2021 - Broken Access Control",
        "CWE-328": "A02:2021 - Cryptographic Failures",
        "CWE-532": "A09:2021 - Security Logging and Monitoring Failures",
        "CWE-287": "A07:2021 - Identification and Authentication Failures",
        "CWE-306": "A07:2021 - Identification and Authentication Failures",
        "CWE-502": "A08:2021 - Software and Data Integrity Failures",
        "CWE-611": "A05:2021 - Security Misconfiguration",
        "CWE-918": "A10:2021 - Server-Side Request Forgery (SSRF)",
    }

    # Count findings per OWASP category
    owasp_counts: dict[str, int] = {}
    severity_scores = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    total_score = 0

    confirmed = [
        f for f in analyzer_output.get("findings", [])
        if f.get("verdict") == "CONFIRMED"
    ]

    for f in confirmed:
        cwe = f.get("cwe", "")
        category = cwe_to_owasp.get(cwe, "A04:2021 - Insecure Design")
        owasp_counts[category] = owasp_counts.get(category, 0) + 1
        sev = f.get("severity", "MEDIUM").upper()
        total_score += severity_scores.get(sev, 5)

    # Normalize score to 0-100
    risk_score = min(100, total_score)

    # Determine risk level
    if risk_score >= 80:
        risk_level = "CRITICAL"
    elif risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    elif risk_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    # Build OWASP categories list
    owasp_list = []
    for cat in OWASP_CATEGORIES:
        count = owasp_counts.get(cat, 0)
        cat_score = min(100, count * 30) if count > 0 else 0
        owasp_list.append(OWASPCategory(
            category=cat,
            score=cat_score,
            findings_count=count,
        ))

    return RiskProfileResponse(
        scan_id=scan_id,
        overall_risk_score=risk_score,
        risk_level=risk_level,
        owasp_top_10=owasp_list,
        attack_surface={
            "total_findings": len(confirmed),
            "critical_count": sum(
                1 for f in confirmed if f.get("severity", "").upper() == "CRITICAL"
            ),
            "high_count": sum(
                1 for f in confirmed if f.get("severity", "").upper() == "HIGH"
            ),
        },
        executive_summary=(
            f"Scanned service has {len(confirmed)} confirmed vulnerabilities "
            f"with an overall risk score of {risk_score}/100 ({risk_level}). "
            f"Findings span {len(owasp_counts)} OWASP Top 10 categories."
        ),
    )
