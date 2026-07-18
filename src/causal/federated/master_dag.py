"""
Master DAG — Cross-Layer Causal Reasoning.

The Master DAG is the top-level causal graph that:
1. Receives edge nodes from all sub-graphs (SAST, DAST, Repo)
2. Defines CROSS-LAYER causal relationships
3. Computes overall risk through causal propagation
4. Performs STRATEGIC counterfactual analysis
5. Identifies cross-layer confounders and mediators

Architecture:
    Edge nodes (inputs)  →  Intermediate causal variables  →  Impact/Risk (outputs)

    [sast.vulnerability_density] ──┐
    [sast.injection_risk] ─────────┼──▶ [exploitability] ──┐
    [dast.confirmed_exploitable] ──┘                       │
                                                           ├──▶ [overall_risk]
    [repo.public_exposure] ────────┐                       │
    [repo.trust_boundary_crossings]┼──▶ [exposure] ────────┘
    [dast.attack_surface] ─────────┘         │
                                             │
    [repo.data_sensitivity] ──────────▶ [impact_severity] ──▶ [business_impact]
    [sast.affected_components] ───────▶ [blast_radius] ─────▶ [business_impact]
    
    [repo.defense_depth] ─────────────▶ [mitigation_posture] (reduces risk)
    [sast.auth_coverage] ─────────────▶ [mitigation_posture]
    [dast.tls_posture] ───────────────▶ [mitigation_posture]
"""

import logging
from typing import Optional

import networkx as nx
from pydantic import BaseModel, Field

from src.causal.federated.base import EdgeNode, TacticalCounterfactual

logger = logging.getLogger(__name__)


# ──── MASTER DAG OUTPUT MODELS ───────────────────────────────────────────────


class StrategicCounterfactual(BaseModel):
    """Result of a strategic (cross-layer) counterfactual analysis."""

    intervention: str
    description: str
    layers_affected: list[str]
    risk_before: float = 0.0
    risk_after: float = 0.0
    risk_reduction: float = 0.0
    risk_reduction_pct: float = 0.0
    intermediate_effects: dict[str, float] = Field(default_factory=dict)
    recommendation: str = ""
    cost_effectiveness: str = ""


class CrossLayerConfounder(BaseModel):
    """A confounder that spans multiple layers."""

    confounder_node: str
    confounder_name: str
    layers_involved: list[str]
    affected_paths: list[str]
    implication: str


class MasterDAGResult(BaseModel):
    """Complete output from the Master DAG analysis."""

    # Risk scores
    overall_risk: float = Field(ge=0.0, le=1.0, default=0.0)
    exploitability_score: float = Field(ge=0.0, le=1.0, default=0.0)
    exposure_score: float = Field(ge=0.0, le=1.0, default=0.0)
    impact_severity_score: float = Field(ge=0.0, le=1.0, default=0.0)
    blast_radius_score: float = Field(ge=0.0, le=1.0, default=0.0)
    mitigation_posture_score: float = Field(ge=0.0, le=1.0, default=0.0)

    # Causal analysis
    strategic_counterfactuals: list[StrategicCounterfactual] = []
    cross_layer_confounders: list[CrossLayerConfounder] = []
    critical_paths: list[dict] = []
    layer_contributions: dict[str, float] = Field(default_factory=dict)

    # Metadata
    edge_nodes_received: int = 0
    intermediate_nodes: int = 0
    causal_edges: int = 0


# ──── MASTER DAG IMPLEMENTATION ──────────────────────────────────────────────


class MasterDAG:
    """
    The Master DAG performs cross-layer causal reasoning.

    It is a SMALL graph (20-30 nodes) that receives aggregated
    edge nodes from sub-graphs and reasons about:
    - How vulnerabilities (SAST) + confirmation (DAST) + exposure (Repo) combine
    - What the overall risk posture is
    - Which strategic interventions have the highest impact
    - What cross-layer confounders exist
    """

    # ──── INTERMEDIATE NODE DEFINITIONS ──────────────────────────────────
    # These are the causal concepts that emerge from COMBINING edge nodes

    INTERMEDIATE_NODES = {
        "exploitability": {
            "name": "Exploitability Level",
            "description": "How easily can vulnerabilities be exploited?",
            "inputs": ["sast.vulnerability_density", "sast.injection_risk",
                       "dast.confirmed_exploitable", "dast.severity_score"],
            "weights": [0.25, 0.3, 0.35, 0.1],
        },
        "exposure": {
            "name": "System Exposure",
            "description": "How exposed is the system to external threats?",
            "inputs": ["repo.public_exposure", "repo.trust_boundary_crossings",
                       "dast.attack_surface"],
            "weights": [0.4, 0.3, 0.3],
        },
        "impact_severity": {
            "name": "Impact Severity",
            "description": "How severe would a successful attack be?",
            "inputs": ["repo.data_sensitivity", "sast.affected_components",
                       "repo.single_point_of_failure"],
            "weights": [0.4, 0.3, 0.3],
        },
        "blast_radius": {
            "name": "Blast Radius",
            "description": "How far would compromise spread?",
            "inputs": ["repo.dependency_depth", "repo.single_point_of_failure",
                       "sast.affected_components"],
            "weights": [0.35, 0.35, 0.3],
        },
        "mitigation_posture": {
            "name": "Mitigation Posture",
            "description": "How well is the system defended? (higher = better defended)",
            "inputs": ["repo.defense_depth", "sast.auth_coverage",
                       "sast.crypto_usage", "dast.tls_posture", "repo.segmentation"],
            "weights": [0.25, 0.2, 0.15, 0.2, 0.2],
        },
    }

    # How intermediate nodes combine into overall risk
    RISK_FORMULA = {
        "overall_risk": {
            "inputs": ["exploitability", "exposure", "impact_severity"],
            "weights": [0.4, 0.3, 0.3],
            "mitigator": "mitigation_posture",  # Reduces the result
            "mitigation_strength": 0.4,  # How much mitigation can reduce risk (max 40%)
        },
    }

    def __init__(self):
        self.graph = nx.DiGraph()
        self._edge_nodes: dict[str, EdgeNode] = {}
        self._intermediate_values: dict[str, float] = {}
        self._overall_risk: float = 0.0

    def build(self, edge_nodes: list[EdgeNode]) -> None:
        """
        Build the master DAG from sub-graph edge nodes.

        Args:
            edge_nodes: All edge nodes from all sub-graphs
        """
        logger.info(f"Building Master DAG from {len(edge_nodes)} edge nodes")

        # Store edge nodes
        self._edge_nodes = {en.id: en for en in edge_nodes}

        # Build graph structure
        self._build_graph_structure()

        # Compute intermediate values (forward propagation)
        self._compute_intermediate_values()

        # Compute overall risk
        self._compute_overall_risk()

        logger.info(
            f"Master DAG built: risk={self._overall_risk:.3f}, "
            f"exploitability={self._intermediate_values.get('exploitability', 0):.3f}, "
            f"exposure={self._intermediate_values.get('exposure', 0):.3f}"
        )

    def analyze(self) -> MasterDAGResult:
        """Run full master DAG analysis."""
        # Strategic counterfactuals
        counterfactuals = self._compute_strategic_counterfactuals()

        # Cross-layer confounders
        confounders = self._identify_cross_layer_confounders()

        # Critical paths through master
        critical_paths = self._identify_critical_paths()

        # Layer contributions (which layer contributes most to risk)
        contributions = self._compute_layer_contributions()

        return MasterDAGResult(
            overall_risk=self._overall_risk,
            exploitability_score=self._intermediate_values.get("exploitability", 0),
            exposure_score=self._intermediate_values.get("exposure", 0),
            impact_severity_score=self._intermediate_values.get("impact_severity", 0),
            blast_radius_score=self._intermediate_values.get("blast_radius", 0),
            mitigation_posture_score=self._intermediate_values.get("mitigation_posture", 0),
            strategic_counterfactuals=counterfactuals,
            cross_layer_confounders=confounders,
            critical_paths=critical_paths,
            layer_contributions=contributions,
            edge_nodes_received=len(self._edge_nodes),
            intermediate_nodes=len(self.INTERMEDIATE_NODES),
            causal_edges=self.graph.number_of_edges(),
        )

    def strategic_counterfactual(
        self, intervention: str, modified_edge_nodes: dict[str, float]
    ) -> StrategicCounterfactual:
        """
        Perform a strategic counterfactual: modify edge nodes and observe risk change.

        This is the DO-operator: do(edge_node = new_value) → observe(overall_risk)

        Args:
            intervention: Name of the intervention
            modified_edge_nodes: {edge_node_id: new_value} after intervention
        """
        risk_before = self._overall_risk

        # Temporarily modify edge node values
        original_values = {}
        for node_id, new_value in modified_edge_nodes.items():
            if node_id in self._edge_nodes:
                original_values[node_id] = self._edge_nodes[node_id].value
                self._edge_nodes[node_id].value = new_value

        # Recompute
        self._compute_intermediate_values()
        self._compute_overall_risk()
        risk_after = self._overall_risk

        # Capture intermediate effects
        intermediate_effects = dict(self._intermediate_values)

        # Restore original values
        for node_id, original_value in original_values.items():
            self._edge_nodes[node_id].value = original_value
        self._compute_intermediate_values()
        self._compute_overall_risk()

        # Determine affected layers
        layers_affected = list(set(
            self._edge_nodes[nid].layer for nid in modified_edge_nodes if nid in self._edge_nodes
        ))

        risk_reduction = risk_before - risk_after
        risk_reduction_pct = (risk_reduction / max(risk_before, 0.001)) * 100

        return StrategicCounterfactual(
            intervention=intervention,
            description=f"Strategic intervention: {intervention}",
            layers_affected=layers_affected,
            risk_before=risk_before,
            risk_after=risk_after,
            risk_reduction=risk_reduction,
            risk_reduction_pct=risk_reduction_pct,
            intermediate_effects=intermediate_effects,
            recommendation=(
                f"Intervention '{intervention}' would reduce overall risk from "
                f"{risk_before:.2f} to {risk_after:.2f} ({risk_reduction_pct:.0f}% reduction)"
            ),
        )

    def recalculate_with_tactical(
        self, layer: str, new_edge_values: dict[str, float]
    ) -> float:
        """
        Recalculate master risk after a tactical counterfactual in a sub-graph.

        This is how tactical counterfactuals PROPAGATE to the master:
        1. Sub-graph performs internal intervention
        2. Sub-graph recomputes its edge nodes
        3. New edge values are passed here
        4. Master recalculates overall risk

        Returns new overall risk score.
        """
        # Temporarily update edge node values
        original = {}
        for node_id, value in new_edge_values.items():
            if node_id in self._edge_nodes:
                original[node_id] = self._edge_nodes[node_id].value
                self._edge_nodes[node_id].value = value

        # Recompute
        self._compute_intermediate_values()
        self._compute_overall_risk()
        new_risk = self._overall_risk

        # Restore
        for node_id, value in original.items():
            self._edge_nodes[node_id].value = value
        self._compute_intermediate_values()
        self._compute_overall_risk()

        return new_risk

    # ──── INTERNAL COMPUTATION ───────────────────────────────────────────

    def _build_graph_structure(self) -> None:
        """Build the master DAG graph structure."""
        self.graph.clear()

        # Add edge nodes as source nodes
        for en_id, en in self._edge_nodes.items():
            self.graph.add_node(en_id, node_type="edge_node", layer=en.layer, value=en.value)

        # Add intermediate nodes
        for node_id, config in self.INTERMEDIATE_NODES.items():
            self.graph.add_node(node_id, node_type="intermediate", name=config["name"])

            # Add edges from inputs to intermediate
            for input_id in config["inputs"]:
                if input_id in self._edge_nodes:
                    self.graph.add_edge(input_id, node_id, edge_type="contributes_to")

        # Add overall risk node
        self.graph.add_node("overall_risk", node_type="output", name="Overall Risk Score")
        for input_id in self.RISK_FORMULA["overall_risk"]["inputs"]:
            self.graph.add_edge(input_id, "overall_risk", edge_type="determines")

        # Mitigation reduces risk
        mitigator = self.RISK_FORMULA["overall_risk"]["mitigator"]
        self.graph.add_edge(mitigator, "overall_risk", edge_type="mitigates")

    def _compute_intermediate_values(self) -> None:
        """Forward propagation: compute intermediate node values from edge nodes."""
        for node_id, config in self.INTERMEDIATE_NODES.items():
            inputs = config["inputs"]
            weights = config["weights"]

            # Weighted sum of input edge node values
            total = 0.0
            total_weight = 0.0
            for input_id, weight in zip(inputs, weights):
                if input_id in self._edge_nodes:
                    value = self._edge_nodes[input_id].value
                    # Weight also by causal strength of the edge node
                    strength = self._edge_nodes[input_id].causal_strength
                    total += value * weight * strength
                    total_weight += weight * strength

            # Normalize
            self._intermediate_values[node_id] = (
                total / max(total_weight, 0.001)
            )

    def _compute_overall_risk(self) -> None:
        """Compute overall risk from intermediate values (with mitigation reduction)."""
        formula = self.RISK_FORMULA["overall_risk"]
        inputs = formula["inputs"]
        weights = formula["weights"]
        mitigator = formula["mitigator"]
        mitigation_strength = formula["mitigation_strength"]

        # Base risk (weighted combination of intermediates)
        base_risk = 0.0
        for input_id, weight in zip(inputs, weights):
            value = self._intermediate_values.get(input_id, 0.0)
            base_risk += value * weight

        # Apply mitigation reduction
        mitigation = self._intermediate_values.get(mitigator, 0.0)
        reduction_factor = 1.0 - (mitigation * mitigation_strength)

        self._overall_risk = min(1.0, max(0.0, base_risk * reduction_factor))

    def _compute_strategic_counterfactuals(self) -> list[StrategicCounterfactual]:
        """Compute standard strategic counterfactuals."""
        counterfactuals = []

        # Scenario 1: "What if all SAST critical issues are fixed?"
        cf = self.strategic_counterfactual(
            "Fix all critical SAST findings",
            {"sast.vulnerability_density": 0.0, "sast.injection_risk": 0.0},
        )
        counterfactuals.append(cf)

        # Scenario 2: "What if DAST-confirmed exploits are all remediated?"
        cf = self.strategic_counterfactual(
            "Remediate all DAST-confirmed exploitable findings",
            {"dast.confirmed_exploitable": 0.0, "dast.severity_score": 0.0},
        )
        counterfactuals.append(cf)

        # Scenario 3: "What if architecture is hardened (gateway + segmentation)?"
        cf = self.strategic_counterfactual(
            "Harden architecture (API gateway + network segmentation)",
            {
                "repo.public_exposure": 0.1,
                "repo.segmentation": 0.9,
                "repo.defense_depth": 0.9,
            },
        )
        counterfactuals.append(cf)

        # Scenario 4: "What if authentication is fully implemented?"
        cf = self.strategic_counterfactual(
            "Implement full authentication coverage",
            {
                "sast.auth_coverage": 1.0,
                "dast.auth_bypass_evidence": 0.0,
            },
        )
        counterfactuals.append(cf)

        # Scenario 5: "What if all encryption is properly implemented?"
        cf = self.strategic_counterfactual(
            "Implement full encryption (TLS + at-rest)",
            {
                "sast.crypto_usage": 1.0,
                "dast.tls_posture": 1.0,
                "repo.trust_boundary_crossings": 0.0,
            },
        )
        counterfactuals.append(cf)

        # Sort by effectiveness
        counterfactuals.sort(key=lambda c: c.risk_reduction, reverse=True)
        return counterfactuals

    def _identify_cross_layer_confounders(self) -> list[CrossLayerConfounder]:
        """
        Identify cross-layer confounders.

        A cross-layer confounder exists when a variable from one layer
        influences the interpretation of variables in another layer.

        Example: repo.public_exposure (Repo layer) confounds the relationship
        between sast.vulnerability_density (SAST) and actual risk — because
        a vulnerability in a non-exposed component is less dangerous.
        """
        confounders = []

        # Known cross-layer confounders (from domain knowledge)
        known_confounders = [
            {
                "node": "repo.public_exposure",
                "name": "Public Exposure",
                "layers": ["repo", "sast"],
                "paths": ["sast.vulnerability_density → exploitability", "repo.public_exposure → exposure"],
                "implication": (
                    "Public exposure confounds vulnerability severity. "
                    "A Critical SAST finding in a non-exposed internal service is "
                    "significantly less dangerous than the same finding in a public-facing service. "
                    "Adjust SAST severity interpretation based on actual exposure."
                ),
            },
            {
                "node": "dast.confirmed_exploitable",
                "name": "DAST Confirmation",
                "layers": ["dast", "sast"],
                "paths": ["sast.vulnerability_density → exploitability", "dast.confirmed_exploitable → exploitability"],
                "implication": (
                    "DAST confirmation confounds SAST severity. "
                    "SAST findings that are NOT confirmed by DAST may be false positives "
                    "or unexploitable in practice. DAST-confirmed findings should receive "
                    "elevated priority regardless of SAST severity."
                ),
            },
            {
                "node": "repo.defense_depth",
                "name": "Defense-in-Depth",
                "layers": ["repo", "dast"],
                "paths": ["dast.attack_surface → exposure", "repo.defense_depth → mitigation"],
                "implication": (
                    "Defense-in-depth confounds attack surface risk. "
                    "A large attack surface with strong defense layers (WAF, rate limiting, auth) "
                    "may be LESS risky than a small surface with no defenses. "
                    "Consider defense posture when interpreting attack surface size."
                ),
            },
        ]

        for conf in known_confounders:
            # Only include if the relevant edge nodes exist and have non-zero values
            node_id = conf["node"]
            if node_id in self._edge_nodes and self._edge_nodes[node_id].value > 0:
                confounders.append(CrossLayerConfounder(
                    confounder_node=node_id,
                    confounder_name=conf["name"],
                    layers_involved=conf["layers"],
                    affected_paths=conf["paths"],
                    implication=conf["implication"],
                ))

        return confounders

    def _identify_critical_paths(self) -> list[dict]:
        """Identify the critical causal paths through the master DAG."""
        paths = []

        # Find all paths from edge nodes to overall_risk
        for en_id in self._edge_nodes:
            if self.graph.has_node(en_id) and self.graph.has_node("overall_risk"):
                try:
                    for path in nx.all_simple_paths(self.graph, en_id, "overall_risk"):
                        # Score = edge node value × causal strength
                        en = self._edge_nodes[en_id]
                        score = en.value * en.causal_strength
                        paths.append({
                            "path": path,
                            "path_names": [self._get_node_name(n) for n in path],
                            "source_layer": en.layer,
                            "score": score,
                        })
                except nx.NetworkXError:
                    continue

        # Sort by score (highest contribution to risk first)
        paths.sort(key=lambda p: p["score"], reverse=True)
        return paths[:15]

    def _compute_layer_contributions(self) -> dict[str, float]:
        """
        Compute how much each layer contributes to overall risk.

        This answers: "Is risk driven by code vulns (SAST), confirmed exploits (DAST),
        or architectural weakness (Repo)?"
        """
        contributions: dict[str, float] = {}

        for en_id, en in self._edge_nodes.items():
            layer = en.layer
            contribution = en.value * en.causal_strength
            contributions[layer] = contributions.get(layer, 0.0) + contribution

        # Normalize to percentages
        total = sum(contributions.values())
        if total > 0:
            contributions = {k: v / total for k, v in contributions.items()}

        return contributions

    def _get_node_name(self, node_id: str) -> str:
        """Get human-readable name for a node."""
        if node_id in self._edge_nodes:
            return self._edge_nodes[node_id].name
        if node_id in self.INTERMEDIATE_NODES:
            return self.INTERMEDIATE_NODES[node_id]["name"]
        if node_id == "overall_risk":
            return "Overall Risk"
        return node_id
