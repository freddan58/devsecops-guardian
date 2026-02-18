"""
DevSecOps Guardian - Health Check Router
"""

import os

from fastapi import APIRouter

from config import SCANNER_DIR, ANALYZER_DIR, FIXER_DIR, RISK_PROFILER_DIR, COMPLIANCE_DIR
from schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint - verifies API and agent availability."""
    agents = {
        "scanner": "available" if os.path.exists(
            os.path.join(SCANNER_DIR, "scanner.py")
        ) else "not found",
        "analyzer": "available" if os.path.exists(
            os.path.join(ANALYZER_DIR, "analyzer.py")
        ) else "not found",
        "fixer": "available" if os.path.exists(
            os.path.join(FIXER_DIR, "fixer.py")
        ) else "not found",
        "risk-profiler": "available" if os.path.exists(
            os.path.join(RISK_PROFILER_DIR, "risk_profiler.py")
        ) else "not found",
        "compliance": "available" if os.path.exists(
            os.path.join(COMPLIANCE_DIR, "compliance.py")
        ) else "not found",
    }

    return HealthResponse(
        status="healthy",
        version="1.0.0",
        agents=agents,
    )
