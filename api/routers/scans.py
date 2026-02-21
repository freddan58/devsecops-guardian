"""
DevSecOps Guardian - Scans Router

Trigger new scans and retrieve scan status/details.
"""

import asyncio

from fastapi import APIRouter, BackgroundTasks, HTTPException

from models import scan_store
from pipeline import run_pipeline
from schemas import ScanRequest, ScanSummary, ScanDetail, ScanStatus

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanSummary, status_code=202)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
):
    """Trigger a new security scan."""
    scan = scan_store.create(
        repository_path=request.repository_path,
        ref=request.ref,
        dry_run=request.dry_run,
        parent_scan_id=request.parent_scan_id,
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


@router.get("/{scan_id}/history", response_model=list[ScanSummary])
async def get_scan_history(scan_id: str):
    """Get the scan history chain for re-scans."""
    history = scan_store.get_history(scan_id)
    if not history:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return [ScanSummary(**s.to_summary()) for s in history]


@router.post("/{scan_id}/cancel", response_model=ScanSummary)
async def cancel_scan(scan_id: str):
    """Cancel a running or stuck scan."""
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    terminal_statuses = {ScanStatus.COMPLETED, ScanStatus.FAILED}
    if scan.status in terminal_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Scan {scan_id} already in terminal state: {scan.status.value}",
        )

    scan.set_error("Cancelled by user")
    scan_store.save(scan)
    return ScanSummary(**scan.to_summary())


@router.post("/{scan_id}/retry", response_model=ScanSummary, status_code=202)
async def retry_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
):
    """Retry a failed scan by creating a new scan with the same configuration."""
    scan = scan_store.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    if scan.status != ScanStatus.FAILED:
        raise HTTPException(
            status_code=400,
            detail=f"Can only retry FAILED scans, current status: {scan.status.value}",
        )

    # Create new scan with same config
    new_scan = scan_store.create(
        repository_path=scan.repository_path,
        ref=scan.ref,
        dry_run=scan.dry_run,
        parent_scan_id=scan.parent_scan_id,
    )

    background_tasks.add_task(run_pipeline, new_scan)
    return ScanSummary(**new_scan.to_summary())
