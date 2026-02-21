"""
DevSecOps Guardian - API Gateway
=================================
FastAPI application serving the dashboard frontend.
Orchestrates the multi-agent security pipeline via REST API.

Usage:
    uvicorn main:app --reload --port 8000

Endpoints:
    GET  /api/health                - Health check + agent availability
    POST /api/scans                 - Trigger new scan (returns 202, runs in background)
    GET  /api/scans                 - List all scans
    GET  /api/scans/{id}            - Full scan detail with all agent outputs
    GET  /api/scans/{id}/findings   - Merged findings (analyzer + fixer)
    GET  /api/scans/{id}/compliance - PCI-DSS 4.0 compliance assessment
    GET  /api/scans/{id}/risk-profile - OWASP Top 10 risk profile
"""

import os
import sys

# Add api/ to Python path so imports work when run from api/ directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import CORS_ORIGINS, REPORTS_DIR
from models import scan_store
from schemas import ScanStatus
from routers import health, scans, findings, compliance, risk_profile, practices

# Create FastAPI app
app = FastAPI(
    title="DevSecOps Guardian API",
    description=(
        "Enterprise-grade multi-agent AI security platform for banking "
        "and regulated industries. Orchestrates 5 specialized AI agents "
        "to detect, analyze, fix, profile, and audit code vulnerabilities."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS middleware for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include routers
app.include_router(health.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(compliance.router)
app.include_router(risk_profile.router)
app.include_router(practices.router)


def _recover_orphaned_scans():
    """Mark any RUNNING scans as FAILED on startup.

    BackgroundTasks don't survive container restarts, so any scan
    that was in a running state (SCANNING, ANALYZING, FIXING, etc.)
    when the container restarted is now orphaned and will never complete.
    """
    running_statuses = {
        ScanStatus.SCANNING,
        ScanStatus.ANALYZING,
        ScanStatus.FIXING,
        ScanStatus.PROFILING,
        ScanStatus.COMPLIANCE_CHECK,
    }
    recovered = 0
    try:
        all_scans = scan_store.list_all()
        for scan in all_scans:
            if scan.status in running_statuses:
                scan.set_error("Pipeline interrupted by container restart")
                scan_store.save(scan)
                recovered += 1
                print(f"  [recovery] {scan.id}: {scan.status.value} → FAILED")
    except Exception as e:
        print(f"  [!] Scan recovery error: {e}")

    if recovered:
        print(f"  [recovery] Recovered {recovered} orphaned scan(s)")


@app.on_event("startup")
async def startup():
    """Ensure reports directory exists and recover orphaned scans on startup."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # Recover scans that were running when the container restarted
    _recover_orphaned_scans()

    print(f"\n{'='*60}")
    print("  DevSecOps Guardian - API Gateway")
    print(f"  Reports directory: {REPORTS_DIR}")
    print(f"  CORS origins: {CORS_ORIGINS}")
    print(f"  Docs: http://localhost:8000/api/docs")
    print(f"{'='*60}\n")


@app.get("/")
async def root():
    """Root endpoint - redirect info."""
    return {
        "name": "DevSecOps Guardian API",
        "version": "1.0.0",
        "docs": "/api/docs",
        "health": "/api/health",
    }
