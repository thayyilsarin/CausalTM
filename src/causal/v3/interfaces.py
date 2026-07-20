"""
CausalTM v3 Module Interfaces — Abstract base classes defining what each layer accepts/returns.

Each layer has a strict contract:
  - Defined input types (what it consumes)
  - Defined output types (what it produces)
  - "Must not do" constraints (what it is forbidden from doing)

Implementation classes inherit from these and provide concrete logic.
"""

from abc import ABC, abstractmethod
from typing import Optional

from src.causal.v3.models import (
    BoundaryCriticality,
    BoundaryPosture,
    CausalEffect,
    ControlCategory,
    CrossLayerRule,
    CausalTMv3Result,
    FusedArchitecturalPosture,
    FusedBoundaryPosture,
    FusionLayerOutput,
    NormalizedEvidence,
    RemediationRoadmap,
    RemediationStep,
    SourceType,
    StrideThreat,
    WhatIfResult,
)


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER A: SOURCE ADAPTERS
# ═══════════════════════════════════════════════════════════════════════════════


class SourceAdapter(ABC):
    """
    Layer A: Parses tool-specific output formats into raw finding dicts.

    Accepts: File path or raw content (tool-specific format)
    Returns: List of raw finding dicts (not yet normalized)

    Must NOT: score, classify into STRIDE, assign boundaries, or infer posture.
    """

    @abstractmethod
    def parse(self, source_path: str) -> list[dict]:
        """
        Parse a source file into raw findings.

        Args:
            source_path: Path to the tool output file (SARIF, XML, HCL, etc.)

        Returns:
            List of raw finding dictionaries with tool-specific fields preserved.
        """
        ...

    @abstractmethod
    def source_type(self) -> SourceType:
        """Return the source type this adapter handles."""
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER B: NORMALIZATION & EVIDENCE LAYER
# ═══════════════════════════════════════════════════════════════════════════════


class NormalizationLayer(ABC):
    """
    Layer B: Converts raw findings into NormalizedEvidence with boundary assignment.

    Accepts: Raw finding dicts from Layer A + component graph (for boundary matching)
    Returns: List of NormalizedEvidence with boundary_assignment populated

    Must NOT: make architectural conclusions, perform cross-source reasoning, compute posture.
    """

    @abstractmethod
    def normalize(
        self,
        raw_findings: list[dict],
        source_type: SourceType,
        component_graph: dict,
    ) -> list[NormalizedEvidence]:
        """
        Normalize raw findings and assign boundaries.

        Args:
            raw_findings: Output from a SourceAdapter
            source_type: Which source produced these findings
            component_graph: Architecture model with components, boundaries, source_paths

        Returns:
            List of NormalizedEvidence with boundary_assignment set.
            Findings that cannot be assigned get P3_unresolved priority.
        """
        ...

    @abstractmethod
    def assign_boundary(
        self,
        finding: dict,
        source_type: SourceType,
        component_graph: dict,
    ) -> Optional[dict]:
        """
        Determine which boundary a finding belongs to.

        Priority 1: Direct file_path → component.source_paths match
        Priority 2: Pattern inference (for repo/IaC)
        Priority 3: Unresolved → global/unresolved bucket

        Returns:
            BoundaryAssignment dict or None if completely unmatchable.
        """
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER C: FEDERATED CAUSAL SUB-DAGs
# ═══════════════════════════════════════════════════════════════════════════════


class CausalSubDAG(ABC):
    """
    Layer C: Computes boundary-specific posture from normalized evidence.

    Accepts: List of NormalizedEvidence (already boundary-assigned, from one source type)
    Returns: List of BoundaryPosture (one per boundary per control category)

    Must NOT:
      - Claim knowledge beyond its domain (SAST must not make runtime claims)
      - Produce global/architectural posture (that's Layer D's job)
      - Consume raw findings (only NormalizedEvidence)
    """

    @abstractmethod
    def build(self, evidence: list[NormalizedEvidence]) -> None:
        """
        Build the sub-DAG's internal causal model from evidence.

        Classifies evidence into control categories (if not already classified),
        groups by boundary, and prepares for posture computation.
        """
        ...

    @abstractmethod
    def compute_boundary_postures(self) -> list[BoundaryPosture]:
        """
        Compute posture for each boundary × control category.

        Formula per (boundary B, category C):
          coverage_gap(B, C) = Σ w(severity_i) / K
          boundary_posture(B, C) = max(0, 1 - coverage_gap(B, C))

        Returns:
            List of BoundaryPosture objects (one per boundary per control category
            where evidence exists). Boundaries with no evidence are NOT included
            (absence of evidence ≠ evidence of absence).
        """
        ...

    @abstractmethod
    def source_type(self) -> SourceType:
        """Return which source type this sub-DAG handles."""
        ...

    @abstractmethod
    def causal_strength(self) -> float:
        """
        Return this sub-DAG's default causal strength.

        SAST: 0.60-0.75 (code patterns, may not be exploitable)
        DAST: 0.85-0.90 (observed runtime behavior for tested paths)
        Repo: 0.50-0.65 (structural properties, design-level)
        """
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER D: FUSION / INTERFACE LAYER
# ═══════════════════════════════════════════════════════════════════════════════


class FusionLayer(ABC):
    """
    Layer D: Fuses boundary-specific postures into architectural posture.

    Accepts: BoundaryPosture lists from ALL sub-DAGs + boundary criticality info
    Returns: FusionLayerOutput (fused architectural postures + metadata)

    Must NOT:
      - Introduce new causal semantics
      - Emit threats directly
      - Consume raw findings (only BoundaryPosture from sub-DAGs)
    """

    @abstractmethod
    def fuse(
        self,
        boundary_postures: list[BoundaryPosture],
        boundary_criticalities: list[BoundaryCriticality],
    ) -> FusionLayerOutput:
        """
        Fuse all boundary postures into architectural posture.

        Steps:
          1. Group by (boundary_id, control_category)
          2. For each group, merge across sources (corroboration/conflict/single-source)
          3. Aggregate boundary → architecture using:
             arch_posture(C) = α × weighted_avg + (1-α) × worst_critical

        Args:
            boundary_postures: All BoundaryPosture from all sub-DAGs
            boundary_criticalities: Criticality scores for each boundary

        Returns:
            FusionLayerOutput with fused architectural postures and traceability.
        """
        ...

    @abstractmethod
    def resolve_conflict(
        self,
        postures_for_same_boundary: list[BoundaryPosture],
    ) -> FusedBoundaryPosture:
        """
        Resolve conflicting evidence at a single boundary.

        Rules:
          - Both agree (within 0.3): weighted average, confidence boost
          - Both disagree (>0.3): bias toward higher-coverage/confidence source,
            flag as uncertain_divergence
          - Single source: use value, apply 0.7 confidence penalty
        """
        ...

    @abstractmethod
    def compute_criticality(self, boundary: dict, component_graph: dict) -> BoundaryCriticality:
        """
        Compute criticality for a boundary.

        Formula:
          criticality(B) = 0.35 × is_external_facing
                         + 0.25 × crosses_trust_boundary
                         + 0.25 × handles_sensitive_data
                         + 0.15 × privilege_level_normalized
        """
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER E: MASTER CAUSAL DAG
# ═══════════════════════════════════════════════════════════════════════════════


class MasterCausalDAG(ABC):
    """
    Layer E: Cross-domain causal reasoning over fused posture variables.

    Accepts: FusionLayerOutput (fused architectural postures)
    Returns: STRIDE posture per category, overall risk, what-if results

    Must NOT:
      - Consume raw findings directly
      - Become source-specific
      - Replace sub-DAGs' local reasoning
    """

    @abstractmethod
    def build(self, fusion_output: FusionLayerOutput) -> None:
        """
        Build the master DAG graph from fused posture variables.

        Creates nodes for each fused posture variable, STRIDE category posture
        nodes, and overall risk node. Connects them via cross-layer rules.
        """
        ...

    @abstractmethod
    def compute_stride_postures(self) -> dict[str, float]:
        """
        Compute STRIDE posture per category from fused architectural postures.

        Returns:
            Dict mapping StrideCategory → posture score [0,1]
        """
        ...

    @abstractmethod
    def compute_overall_risk(self) -> float:
        """
        Compute overall system risk from STRIDE postures.

        Returns:
            Float [0,1] where 0 = no risk, 1 = maximum risk.
        """
        ...

    @abstractmethod
    def what_if(
        self,
        variable: str,
        new_value: float,
        description: str = "",
    ) -> WhatIfResult:
        """
        Run a what-if analysis: "If we change this posture, what happens?"

        Propagates effects through cross-layer rules (with assumptions check).

        Args:
            variable: Which fused posture variable to change
            new_value: Target value
            description: Human description of the intervention

        Returns:
            WhatIfResult with before/after states and all effects.
        """
        ...

    @abstractmethod
    def get_cross_layer_rules(self) -> list[CrossLayerRule]:
        """Return all cross-layer dependency rules with their assumptions."""
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER F: STRIDE THREAT LAYER
# ═══════════════════════════════════════════════════════════════════════════════


class StrideLayer(ABC):
    """
    Layer F: Hybrid STRIDE threat classification (rules + posture-derived).

    Accepts: STRIDE posture per category (from Master DAG) + component graph + fusion metadata
    Returns: List of StrideThreat with full evidence chains

    Must NOT:
      - Bypass the causal model with direct CWE→STRIDE mapping
      - Generate threats without evidence traceability
      - Use STRIDE as a scoring engine
    """

    @abstractmethod
    def evaluate(
        self,
        stride_postures: dict[str, float],
        fusion_output: FusionLayerOutput,
        component_graph: dict,
    ) -> list[StrideThreat]:
        """
        Evaluate STRIDE threats using hybrid approach.

        1. Rule-based: Check known patterns (weak auth + exposed boundary → Spoofing)
        2. Posture-derived: Check thresholds (posture < 0.7 → Medium threat)
        3. Attach evidence chains tracing back through fusion → boundaries → findings

        Args:
            stride_postures: Per-category posture from Master DAG
            fusion_output: Full fusion output for traceability
            component_graph: Architecture for context (flows, boundaries)

        Returns:
            List of classified STRIDE threats.
        """
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER G: REMEDIATION PLANNER
# ═══════════════════════════════════════════════════════════════════════════════


class RemediationPlanner(ABC):
    """
    Layer G: Sequences fixes by cross-layer impact with boundary traceability.

    Accepts: Fused postures + Master DAG (for propagation) + boundary details
    Returns: RemediationRoadmap with ordered steps

    Must NOT:
      - Invent new findings
      - Overwrite evidence provenance
      - Recommend fixes without traceability to specific boundaries and findings
    """

    @abstractmethod
    def generate_roadmap(
        self,
        fusion_output: FusionLayerOutput,
        master_dag: MasterCausalDAG,
        evidence: list[NormalizedEvidence],
    ) -> RemediationRoadmap:
        """
        Generate sequenced remediation roadmap.

        Algorithm:
          1. Find posture variable with highest deficit × criticality
          2. Simulate fix → propagate cross-layer effects
          3. Record step with boundary-level traceability
          4. Mark fixed; repeat until deficit < 0.05

        Each step traces to:
          - Which boundary to fix
          - Which specific findings to address
          - What cross-layer effects are predicted (with assumptions)

        Returns:
            Ordered RemediationRoadmap.
        """
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR (Engine)
# ═══════════════════════════════════════════════════════════════════════════════


class CausalTMv3Engine(ABC):
    """
    Top-level orchestrator that wires all layers together.

    This is the entry point for callers. It coordinates:
      A → B → C → D → E → F → G → H
    """

    @abstractmethod
    def analyze(
        self,
        component_graph: dict,
        sast_findings: list[dict],
        dast_findings: list[dict],
        iac_findings: Optional[list[dict]] = None,
    ) -> CausalTMv3Result:
        """
        Run complete v3 analysis pipeline.

        Args:
            component_graph: Architecture model (components, flows, boundaries)
            sast_findings: Raw SAST findings (from source adapter)
            dast_findings: Raw DAST findings (from source adapter)
            iac_findings: Optional IaC findings (from source adapter)

        Returns:
            Complete CausalTMv3Result with threats, postures, roadmap.
        """
        ...

    @abstractmethod
    def what_if(self, variable: str, new_value: float) -> WhatIfResult:
        """Run a what-if query after analysis is complete."""
        ...

    @abstractmethod
    def get_attack_paths(self, max_paths: int = 10) -> list[dict]:
        """
        Compute attack paths through the component graph.

        DFS from external/public-facing entry points to data stores.
        Scored by boundary crossings, encryption gaps, auth gaps, data sensitivity.
        """
        ...

    @abstractmethod
    def get_dfd_model(self) -> dict:
        """Generate DFD-compatible model for rendering."""
        ...
