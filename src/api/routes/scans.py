"""Scan management endpoints."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, UploadFile, File
from typing import Optional

from src.api.models.scan import (
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScanStatusResponse,
    ScanListResponse,
)
from src.api.models.threat import ThreatSummary

router = APIRouter()

# In-memory store for prototype (replace with DB later)
_scans: dict[str, ScanStatusResponse] = {}


@router.post("/scans", response_model=ScanResponse)
async def create_scan(request: ScanRequest):
    """
    Initiate a new threat model scan.

    Accepts a git repo URL and optional SAST/DAST report paths.
    The scan runs asynchronously through the pipeline:
    clone -> analyze -> correlate -> generate DFD -> apply STRIDE -> report
    """
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    scan_status = ScanStatusResponse(
        scan_id=scan_id,
        status=ScanStatus.QUEUED,
        project_name=request.project_name or _extract_project_name(request.repo_url),
        repo_url=request.repo_url,
        branch=request.branch,
        created_at=now,
    )
    _scans[scan_id] = scan_status

    # TODO: Dispatch to Celery worker for async processing
    # For prototype, we'll run synchronously in a background task
    # task = run_scan_pipeline.delay(scan_id, request.model_dump())

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.QUEUED,
        message="Scan queued successfully. Use GET /scans/{scan_id} to check status.",
        created_at=now,
    )


@router.post("/scans/{scan_id}/reports/sast")
async def upload_sast_report(scan_id: str, file: UploadFile = File(...)):
    """Upload a SAST report (SARIF format) for an existing scan."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    content = await file.read()
    # TODO: Save to storage and associate with scan
    # For now, store path reference
    return {
        "scan_id": scan_id,
        "report_type": "SAST",
        "filename": file.filename,
        "size_bytes": len(content),
        "message": "SAST report uploaded successfully",
    }


@router.post("/scans/{scan_id}/reports/dast")
async def upload_dast_report(scan_id: str, file: UploadFile = File(...)):
    """Upload a DAST report (ZAP XML or SARIF) for an existing scan."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    content = await file.read()
    # TODO: Save to storage and associate with scan
    return {
        "scan_id": scan_id,
        "report_type": "DAST",
        "filename": file.filename,
        "size_bytes": len(content),
        "message": "DAST report uploaded successfully",
    }


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(limit: int = 20, offset: int = 0):
    """List all scans with pagination."""
    all_scans = list(_scans.values())
    paginated = all_scans[offset : offset + limit]
    return ScanListResponse(scans=paginated, total=len(all_scans))


@router.get("/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Get current status and summary of a scan."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return _scans[scan_id]


@router.get("/scans/{scan_id}/threats", response_model=ThreatSummary)
async def get_scan_threats(scan_id: str):
    """Get all identified threats for a completed scan."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    scan = _scans[scan_id]
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not complete. Current status: {scan.status}",
        )

    # TODO: Retrieve from storage
    return ThreatSummary(
        scan_id=scan_id,
        total_threats=0,
        by_severity={},
        by_stride_category={},
        risk_score=0.0,
        threats=[],
    )


@router.get("/scans/{scan_id}/dfd")
async def get_scan_dfd(scan_id: str, format: str = "json"):
    """
    Get the Data Flow Diagram for a completed scan.

    Formats: json (DFD model), svg, png
    """
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    # TODO: Return actual DFD data/image
    return {
        "scan_id": scan_id,
        "format": format,
        "message": "DFD generation not yet implemented",
    }


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and its artifacts."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    del _scans[scan_id]
    # TODO: Clean up stored artifacts
    return {"message": f"Scan {scan_id} deleted successfully"}


def _extract_project_name(repo_url: str) -> str:
    """Extract a project name from a git URL."""
    # Handle both HTTPS and SSH URLs
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name
