"""Pydantic models for threat-related responses."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class StrideCategory(str, Enum):
    """STRIDE threat categories."""

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class Severity(str, Enum):
    """Threat severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class EvidenceSource(str, Enum):
    """Source of evidence for a threat."""

    SAST = "SAST"
    DAST = "DAST"
    CODE_ANALYSIS = "Code Analysis"
    CAUSAL_INFERENCE = "Causal Inference"
    DOMAIN_RULE = "Domain Rule"


class ThreatEvidence(BaseModel):
    """Evidence supporting a threat finding."""

    source: EvidenceSource
    tool: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    url: Optional[str] = None
    cwe_id: Optional[str] = None
    description: str


class ThreatFinding(BaseModel):
    """A single threat finding with STRIDE classification."""

    threat_id: str
    stride_category: StrideCategory
    title: str
    description: str
    severity: Severity
    component_id: str
    component_name: str
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0-1")
    evidence: list[ThreatEvidence] = []
    attack_path: Optional[list[str]] = None
    mitigations: list[str] = []
    is_confirmed_exploitable: bool = False
    causal_severity_adjustment: Optional[str] = None


class ThreatSummary(BaseModel):
    """Summary of all threats for a scan."""

    scan_id: str
    total_threats: int
    by_severity: dict[str, int]
    by_stride_category: dict[str, int]
    top_attack_paths: list[list[str]] = []
    risk_score: float = Field(ge=0.0, le=10.0)
    threats: list[ThreatFinding]
