"""Pydantic models for scan requests and responses."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl


class ScanStatus(str, Enum):
    """Scan lifecycle status."""

    QUEUED = "queued"
    CLONING = "cloning"
    ANALYZING = "analyzing"
    CORRELATING = "correlating"
    RENDERING = "rendering"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanRequest(BaseModel):
    """Request to initiate a new threat model scan."""

    repo_url: str = Field(..., description="Git repository URL to scan")
    branch: str = Field(default="main", description="Branch to scan")
    token: Optional[str] = Field(default=None, description="Git access token")
    sast_report_path: Optional[str] = Field(
        default=None, description="Path to SAST report file (SARIF format)"
    )
    dast_report_path: Optional[str] = Field(
        default=None, description="Path to DAST report file (ZAP XML or SARIF)"
    )
    project_name: Optional[str] = Field(
        default=None, description="Human-readable project name"
    )


class ScanResponse(BaseModel):
    """Response after creating a scan."""

    scan_id: str
    status: ScanStatus
    message: str
    created_at: datetime


class ScanStatusResponse(BaseModel):
    """Current status of a scan."""

    scan_id: str
    status: ScanStatus
    project_name: Optional[str] = None
    repo_url: str
    branch: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    components_found: int = 0
    threats_found: int = 0
    critical_threats: int = 0


class ScanListResponse(BaseModel):
    """List of scans."""

    scans: list[ScanStatusResponse]
    total: int
