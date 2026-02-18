"""
DevSecOps Guardian - Scans Router

Trigger new scans and retrieve scan status/details.
"""

import asyncio

from fastapi import APIRouter, BackgroundTasks, HTTPException

from models import scan_store
from pipeline import run_pipeline
from schemas import ScanRequest, ScanSummary, ScanDetail

router = APIRouter(prefix="/api/scans", tags=["scans"])


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
    )

    # Launch pipeline in background
    background_tasks.add_task(run_pipeline, scan)

    return ScanSummary(**scan.to_summary())


@router.get("", response_model=list[ScanSummary])
async def list_scans():
    """List all scans, newest first."""
    return [ScanSummary(**s.to_summary()) for s in scan_store.list_all()]


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str):
    """Get full scan detail including all agent outputs."""
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return ScanDetail(**scan.to_detail())
