"""Data models for the causal inference engine."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CausalNodeType(str, Enum):
    """Types of nodes in the causal graph."""

    COMPONENT = "component"         # Service, API, process
    DATA_STORE = "data_store"       # Database, cache, file system
    EXTERNAL_ENTITY = "external_entity"  # User, third-party API
    VULNERABILITY = "vulnerability"  # From SAST/DAST
    CONDITION = "condition"          # Contextual factor (exposure, auth)
    IMPACT = "impact"               # Business consequence
    MITIGATION = "mitigation"       # Applied control


class CausalEdgeType(str, Enum):
    """Types of causal relationships."""

    CONNECTS_TO = "connects_to"     # Structural: A communicates with B
    DEPENDS_ON = "depends_on"       # Structural: A requires B
    ENABLES = "enables"             # Vulnerability enables attack on component
    CAUSES = "causes"               # Attack causes impact
    INFLUENCES = "influences"       # Condition influences exploitability (confounder)
    MITIGATES = "mitigates"         # Control reduces/blocks threat
    LEADS_TO = "leads_to"           # General causal chain link


class CausalNode(BaseModel):
    """A node in the causal threat graph."""

    id: str
    name: str
    node_type: CausalNodeType
    metadata: dict[str, str] = Field(default_factory=dict)


class CausalEdge(BaseModel):
    """A directed edge (causal relationship) in the graph."""

    source_id: str
    target_id: str
    edge_type: CausalEdgeType
    weight: float = 0.5
    metadata: dict[str, str] = Field(default_factory=dict)


class AttackPath(BaseModel):
    """A causal chain from entry point to impact."""

    path_nodes: list[str]
    entry_point: str
    target: str
    score: float = Field(ge=0.0, le=1.0)
    length: int
    crosses_trust_boundary: bool = False
    node_names: list[str] = []


class ConfounderResult(BaseModel):
    """A detected confounder in the causal graph."""

    confounder_id: str
    confounder_name: str
    relationship: tuple[str, str]
    implication: str


class MediatorResult(BaseModel):
    """A detected mediator (mitigation/intervention point)."""

    mediator_id: str
    mediator_name: str
    paths_affected: int
    node_type: str
    intervention_suggestion: str
    effectiveness_score: float = Field(ge=0.0, le=1.0)


class CounterfactualResult(BaseModel):
    """Result of a counterfactual analysis (what-if mitigation)."""

    intervention_node: str
    intervention_name: str
    paths_before: int
    paths_after: int
    paths_blocked: int
    effectiveness: float = Field(ge=0.0, le=1.0)
    recommendation: str


class CausalAnalysisResult(BaseModel):
    """Complete output from the causal analysis engine."""

    attack_paths: list[AttackPath] = []
    confounders: list[ConfounderResult] = []
    mediators: list[MediatorResult] = []
    impact_scores: dict[str, float] = Field(default_factory=dict)
    counterfactuals: list[CounterfactualResult] = []
    element_scores: dict[str, dict] = Field(default_factory=dict)
    confirmed_exploitable: list[str] = []
    graph_stats: dict[str, int] = Field(default_factory=dict)

    def to_pipeline_output(self) -> dict:
        """
        Convert to the format expected by the scan pipeline.

        Returns dict with keys used by StrideEngine for causal enrichment:
        - attack_paths: per-element attack path scores
        - confirmed_exploitable: component IDs confirmed via DAST
        - confounder_adjustments: severity adjustments from confounders
        - high_risk_flows: flow IDs on high-risk attack paths
        """
        # Build attack path scores per element
        attack_path_output = {}
        for node_id, data in self.element_scores.items():
            attack_path_output[node_id] = {
                "score": data.get("score", 0.0),
                "paths_through": data.get("paths_through", 0),
            }

        # Build confounder adjustments
        confounder_adjustments = {}
        for conf in self.confounders:
            for node_id in conf.relationship:
                confounder_adjustments[node_id] = {
                    "reduce_severity": True,
                    "reason": conf.implication,
                }

        return {
            "attack_paths": attack_path_output,
            "confirmed_exploitable": self.confirmed_exploitable,
            "confounder_adjustments": confounder_adjustments,
            "high_risk_flows": [],
            "mediators": [m.model_dump() for m in self.mediators],
            "counterfactuals": [c.model_dump() for c in self.counterfactuals],
            "graph_stats": self.graph_stats,
            "threat_counts_by_element": {},
        }
