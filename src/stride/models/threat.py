"""Threat models for STRIDE classification results."""

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


class ThreatSeverity(str, Enum):
    """Threat severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class ThreatSource(str, Enum):
    """Where the threat was identified from."""

    RULE_ENGINE = "Rule Engine"
    SAST_CORRELATION = "SAST Correlation"
    DAST_CORRELATION = "DAST Correlation"
    CAUSAL_INFERENCE = "Causal Inference"
    COMBINED = "Combined (SAST+DAST)"


class Threat(BaseModel):
    """A single STRIDE threat finding."""

    id: str
    rule_id: str
    category: StrideCategory
    title: str
    description: str
    severity: ThreatSeverity
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)
    element_id: str
    element_name: str
    element_type: str
    source: ThreatSource = ThreatSource.RULE_ENGINE
    evidence: list[str] = []
    mitigations: list[str] = []
    cwe_ids: list[str] = []
    attack_vector: Optional[str] = None
    prerequisites: list[str] = []
    affected_data: list[str] = []
    is_confirmed: bool = False
    causal_severity_score: Optional[float] = None


class ThreatModelResult(BaseModel):
    """Complete threat model output from STRIDE analysis."""

    total_threats: int = 0
    threats: list[Threat] = []
    by_category: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_element: dict[str, int] = Field(default_factory=dict)
    risk_score: float = 0.0

    def add_threat(self, threat: Threat) -> None:
        """Add a threat and update summary counts."""
        self.threats.append(threat)
        self.total_threats += 1
        self.by_category[threat.category.value] = (
            self.by_category.get(threat.category.value, 0) + 1
        )
        self.by_severity[threat.severity.value] = (
            self.by_severity.get(threat.severity.value, 0) + 1
        )
        self.by_element[threat.element_id] = (
            self.by_element.get(threat.element_id, 0) + 1
        )

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-10) based on threats."""
        if not self.threats:
            self.risk_score = 0.0
            return 0.0

        severity_weights = {
            ThreatSeverity.CRITICAL: 10.0,
            ThreatSeverity.HIGH: 7.0,
            ThreatSeverity.MEDIUM: 4.0,
            ThreatSeverity.LOW: 2.0,
            ThreatSeverity.INFORMATIONAL: 0.5,
        }

        total_weight = sum(
            severity_weights.get(t.severity, 1.0) * t.confidence
            for t in self.threats
        )

        # Normalize to 0-10 scale (cap at 10)
        self.risk_score = min(10.0, total_weight / max(len(self.threats), 1) * 1.5)
        return self.risk_score
