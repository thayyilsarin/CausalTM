"""
CausalTM v3 Data Models — Pydantic schemas for the 8-layer architecture.

Separation of concerns:
  - Evidence (raw findings)        → NormalizedEvidence
  - Boundary Posture (local)       → BoundaryPosture
  - Fused Posture (architectural)  → FusedPosture
  - Threat (STRIDE classification) → StrideThreat
  - Causal Effect (propagation)    → CausalEffect

These concepts remain separate throughout the pipeline.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════════════════


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class SourceType(str, Enum):
    SAST = "sast"
    DAST = "dast"
    IAC = "iac"
    REPO = "repo"
    SBOM = "sbom"  # Future


class ControlCategory(str, Enum):
    AUTH = "auth"
    CRYPTO = "crypto"
    VALIDATION = "validation"
    LOGGING = "logging"


class StrideCategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class ThreatClassificationMethod(str, Enum):
    RULE_MATCHED = "rule_matched"
    POSTURE_DERIVED = "posture_derived"


class RemediationType(str, Enum):
    ARCHITECTURE = "architecture"
    CODE = "code"
    CONFIG = "config"


class BoundaryAssignmentPriority(str, Enum):
    DIRECT_MATCH = "P1_direct_match"
    PATTERN_INFERENCE = "P2_pattern_inference"
    UNRESOLVED = "P3_unresolved"


class FusionStatus(str, Enum):
    CORROBORATED = "corroborated"       # Multiple sources agree
    SINGLE_SOURCE = "single_source"      # Only one source observed
    UNCERTAIN_DIVERGENCE = "uncertain_divergence"  # Sources disagree


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER B: NORMALIZED EVIDENCE
# ═══════════════════════════════════════════════════════════════════════════════


class BoundaryAssignment(BaseModel):
    """How a finding was assigned to a boundary."""
    boundary_id: str
    component_id: str
    priority: BoundaryAssignmentPriority
    confidence: float = Field(ge=0.0, le=1.0)
    match_reason: str = ""  # e.g., "file_path 'routes/search.ts' matched component source_paths"


class NormalizedEvidence(BaseModel):
    """
    Layer B output: A single finding normalized from any source adapter.
    
    This is the common schema that ALL sources produce after normalization.
    It carries boundary context but makes NO architectural conclusions.
    """
    # Identity
    id: str
    title: str
    description: str = ""

    # Classification
    severity: Severity = Severity.MEDIUM
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    source_type: SourceType
    control_category: Optional[ControlCategory] = None  # Classified in Layer C

    # CWE / Rule
    cwe_id: Optional[str] = None
    rule_id: Optional[str] = None

    # Boundary context (assigned in Layer B — always present, even if P3_unresolved)
    boundary_assignment: BoundaryAssignment

    # Location
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    url: Optional[str] = None  # For DAST findings

    # Traceability
    tool_name: str = ""
    original_finding_ref: str = ""  # Link back to original tool output

    # Coverage metadata (recorded, minimal MVP influence)
    coverage_context: Optional[str] = None  # e.g., "endpoint tested", "file scanned"


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER C: BOUNDARY POSTURE (Sub-DAG Output)
# ═══════════════════════════════════════════════════════════════════════════════


class BoundaryPosture(BaseModel):
    """
    Layer C output: Posture for ONE control category at ONE boundary,
    from ONE sub-DAG (source).
    
    This is the LOCAL assessment — "at this boundary, from this source's
    perspective, control X has Y% coverage."
    """
    # Identity
    boundary_id: str
    component_id: str
    control_category: ControlCategory
    source_type: SourceType  # Which sub-DAG produced this

    # Posture score
    posture: float = Field(ge=0.0, le=1.0)  # 1.0 = full coverage, 0.0 = no coverage
    causal_strength: float = Field(ge=0.0, le=1.0)  # How much to trust this source

    # Evidence
    contributing_evidence_ids: list[str] = Field(default_factory=list)
    evidence_count: int = 0
    weighted_deficit: float = 0.0  # Sum of severity weights that produced this posture

    # Confidence
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    boundary_assignment_priority: BoundaryAssignmentPriority = BoundaryAssignmentPriority.DIRECT_MATCH

    # Coverage metadata
    coverage_fraction: Optional[float] = None  # 0-1, what fraction of this boundary was assessed

    # Descriptive
    evidence_summary: list[str] = Field(default_factory=list)
    # e.g., ["3 High validation findings at API boundary", "CWE-89, CWE-79, CWE-22"]


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER D: FUSED POSTURE (Fusion Layer Output)
# ═══════════════════════════════════════════════════════════════════════════════


class FusedBoundaryPosture(BaseModel):
    """
    Intermediate fusion result: posture at one boundary, merged across sources.
    This exists between per-source boundary posture and architectural posture.
    """
    boundary_id: str
    control_category: ControlCategory
    fused_posture: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    fusion_status: FusionStatus
    contributing_sources: list[SourceType] = Field(default_factory=list)
    source_postures: dict[str, float] = Field(default_factory=dict)  # source_type → posture


class BoundaryCriticality(BaseModel):
    """Criticality assessment of a boundary for aggregation weighting."""
    boundary_id: str
    criticality: float = Field(ge=0.0, le=1.0)
    is_external_facing: bool = False
    crosses_trust_boundary: bool = False
    handles_sensitive_data: bool = False
    privilege_level: float = Field(default=0.0, ge=0.0, le=1.0)


class FusedArchitecturalPosture(BaseModel):
    """
    Layer D final output: System-wide posture per control category.
    
    This is what the Master DAG operates on.
    Computed via: α × weighted_avg + (1-α) × worst_critical_boundary
    """
    control_category: ControlCategory
    posture: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)

    # Aggregation details
    weighted_average: float = 0.0
    worst_critical_boundary: float = 1.0
    worst_critical_boundary_id: str = ""
    alpha: float = 0.6  # Aggregation balance parameter

    # Traceability
    boundary_count: int = 0
    high_criticality_boundary_count: int = 0
    fusion_statuses: dict[str, int] = Field(default_factory=dict)  # status → count


class FusionLayerOutput(BaseModel):
    """Complete output of the Fusion Layer (Layer D) to the Master DAG."""
    postures: list[FusedArchitecturalPosture] = Field(default_factory=list)
    boundary_postures: list[FusedBoundaryPosture] = Field(default_factory=list)  # Retained for traceability
    boundary_criticalities: list[BoundaryCriticality] = Field(default_factory=list)

    def get_posture(self, category: ControlCategory) -> Optional[FusedArchitecturalPosture]:
        """Get fused posture for a specific control category."""
        for p in self.postures:
            if p.control_category == category:
                return p
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER E: MASTER DAG (Cross-Layer Reasoning)
# ═══════════════════════════════════════════════════════════════════════════════


class CrossLayerRule(BaseModel):
    """A dependency rule in the Master DAG with explicit assumptions."""
    id: str
    trigger_variable: str          # e.g., "arch.auth_posture"
    trigger_condition: str         # e.g., "improves"
    effect_variable: str           # e.g., "arch.runtime_auth"
    strength: float = Field(ge=0.0, le=1.0)
    assumptions: list[str] = Field(default_factory=list)
    applicability: str = ""        # When does this rule apply?


class CausalEffect(BaseModel):
    """Predicted effect of an intervention (what-if result)."""
    intervention_variable: str
    intervention_value: float
    affected_variable: str
    predicted_change: float  # Delta
    new_predicted_value: float
    rule_applied: str  # Which cross-layer rule
    assumptions_required: list[str] = Field(default_factory=list)


class WhatIfResult(BaseModel):
    """Complete what-if analysis result."""
    description: str
    intervention_variable: str
    old_value: float
    new_value: float
    direct_effects: list[CausalEffect] = Field(default_factory=list)
    propagated_effects: list[CausalEffect] = Field(default_factory=list)
    risk_before: float = 0.0
    risk_after: float = 0.0
    stride_changes: dict[str, float] = Field(default_factory=dict)  # category → new posture


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER F: STRIDE THREATS
# ═══════════════════════════════════════════════════════════════════════════════


class ThreatEvidence(BaseModel):
    """Evidence chain for a single STRIDE threat."""
    source_type: SourceType
    boundary_id: str
    boundary_posture: float
    contributing_cwes: list[str] = Field(default_factory=list)
    finding_count: int = 0
    summary: str = ""

    # Traceability metadata (enriched for research provenance)
    boundary_assignment_confidence: float = 0.0
    boundary_assignment_priority: BoundaryAssignmentPriority = BoundaryAssignmentPriority.DIRECT_MATCH
    fusion_status: Optional[FusionStatus] = None
    source_confidence: float = 0.0


class StrideThreat(BaseModel):
    """
    Layer F output: A classified STRIDE threat with full traceability.
    
    The path from raw finding to this threat traverses 4 layers:
    finding (A-B) → boundary posture (C) → fused posture (D) → threat (F)
    """
    # Identity
    id: str
    category: StrideCategory
    title: str
    description: str

    # Severity & Confidence
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    classification_method: ThreatClassificationMethod

    # Posture that triggered this threat
    triggering_posture_category: ControlCategory
    triggering_posture_value: float
    posture_threshold_used: float  # Which threshold was crossed

    # Evidence (multi-layer)
    evidence: list[ThreatEvidence] = Field(default_factory=list)
    layers_contributing: int = 0  # How many sub-DAGs agree
    traced_cwes: list[str] = Field(default_factory=list)

    # Affected architecture
    affected_boundaries: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    affected_flows: list[str] = Field(default_factory=list)

    # Remediation
    remediation_architecture: str = ""
    remediation_code: str = ""
    remediation_config: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER G: REMEDIATION
# ═══════════════════════════════════════════════════════════════════════════════


class RemediationStep(BaseModel):
    """A single step in the sequenced remediation roadmap."""
    step_number: int
    name: str
    remediation_type: RemediationType

    # What to fix
    target_posture_category: ControlCategory
    target_boundary_id: str
    target_boundary_name: str = ""
    current_posture: float
    target_posture: float  # After fix

    # Impact
    direct_stride_improvement: float  # Risk reduction from this fix alone
    cross_layer_effects: list[CausalEffect] = Field(default_factory=list)
    total_risk_reduction: float = 0.0

    # Traceability — which findings to address
    findings_to_fix: list[str] = Field(default_factory=list)  # NormalizedEvidence IDs
    fix_description: str = ""

    # Assumptions
    assumptions: list[str] = Field(default_factory=list)


class RemediationRoadmap(BaseModel):
    """Complete sequenced roadmap output."""
    steps: list[RemediationStep] = Field(default_factory=list)
    initial_risk: float = 0.0
    projected_final_risk: float = 0.0
    total_steps: int = 0
    cross_layer_effects_triggered: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
# COMPLETE ENGINE OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════


class CausalTMv3Result(BaseModel):
    """Complete output from CausalTM v3 engine."""

    # STRIDE Threats
    threats: list[StrideThreat] = Field(default_factory=list)
    total_threats: int = 0

    # Posture (fused architectural level)
    fused_postures: list[FusedArchitecturalPosture] = Field(default_factory=list)
    stride_posture_per_category: dict[str, float] = Field(default_factory=dict)

    # Risk
    overall_risk: float = 0.0
    risk_rating: str = ""

    # Remediation
    roadmap: Optional[RemediationRoadmap] = None

    # Attack paths (from graph traversal, queried post-analysis)
    attack_paths: list[dict] = Field(default_factory=list)

    # DFD model (for rendering, queried post-analysis)
    dfd_model: Optional[dict] = None

    # Layer summaries
    evidence_count: int = 0
    boundary_count: int = 0
    boundaries_assessed: list[str] = Field(default_factory=list)

    # Confidence
    average_confidence: float = 0.0
    uncertain_divergences: int = 0  # How many fusion conflicts occurred
