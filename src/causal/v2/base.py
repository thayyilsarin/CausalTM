"""
Base classes for CausalTM v2 sub-DAGs.

Edge nodes in v2 represent ARCHITECTURAL POSTURE, not vulnerability metrics.
Each edge node answers: "What is the state of this security control in the architecture?"
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional

import networkx as nx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ArchitecturalEdgeNode(BaseModel):
    """
    An edge node representing the EFFECT of base variables on architectural posture.

    In v2, edge nodes answer questions like:
      "How complete is authentication coverage?" (not "how many auth vulns exist")
      "Is encryption working at runtime?" (not "how many TLS issues found")

    The value represents POSTURE (0 = no control, 1 = fully controlled):
      0.0 = Security control completely absent
      0.5 = Partially implemented (gaps exist)
      1.0 = Fully implemented and verified

    Causal direction:
      Base variables (individual findings) → CAUSE → This edge node (architectural effect)
      This edge node → FEEDS → Master DAG → FEEDS → STRIDE layer
    """

    id: str
    name: str
    layer: str  # "sast", "dast", "repo"
    value: float = Field(ge=0.0, le=1.0, default=0.0)
    causal_strength: float = Field(ge=0.0, le=1.0, default=0.5)

    # What this posture means for STRIDE
    stride_relevance: list[str] = Field(default_factory=list)
    # e.g., ["Spoofing", "Elevation of Privilege"] for auth_posture

    # Base variables that CAUSE this edge node's value
    base_variables: list[str] = Field(default_factory=list)
    # e.g., ["CWE-287 in login.js", "CWE-306 in api.js"]

    # Evidence supporting the posture assessment
    evidence: list[str] = Field(default_factory=list)

    # Is this based on actual observation or not yet measured?
    observed: bool = True

    metadata: dict[str, str] = Field(default_factory=dict)


class CrossLayerEffect(BaseModel):
    """Describes how a change in one layer affects another layer's edge node."""

    trigger_layer: str
    trigger_edge_node: str
    trigger_change: str  # "increase" or "decrease"
    affected_layer: str
    affected_edge_node: str
    effect_direction: str  # "increase" or "decrease"
    strength: float = Field(ge=0.0, le=1.0, default=0.5)
    reason: str = ""


class ArchitecturalSubDAG(ABC):
    """
    Base class for v2 sub-DAGs.

    Each sub-DAG:
    1. Receives raw input data (findings or repo files)
    2. Builds internal causal graph (base variables → effects)
    3. Computes edge nodes representing ARCHITECTURAL POSTURE
    4. Supports forward propagation (base change → edge node recalculates)
    5. Supports backward query (target posture → what base vars must change)
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self._base_variables: dict[str, dict] = {}  # Individual findings/facts
        self._edge_nodes: dict[str, ArchitecturalEdgeNode] = {}
        self._built = False

    @property
    @abstractmethod
    def layer_name(self) -> str:
        """Layer identifier: 'sast', 'dast', 'repo'"""
        ...

    @abstractmethod
    def build(self, data: dict) -> None:
        """Build the sub-DAG from input data."""
        ...

    @abstractmethod
    def compute_edge_nodes(self) -> list[ArchitecturalEdgeNode]:
        """Compute architectural posture edge nodes."""
        ...

    def get_edge_nodes(self) -> list[ArchitecturalEdgeNode]:
        """Return current edge nodes."""
        if not self._edge_nodes:
            nodes = self.compute_edge_nodes()
            self._edge_nodes = {en.id: en for en in nodes}
        return list(self._edge_nodes.values())

    def forward_propagate(self, removed_base_var: str) -> dict[str, float]:
        """
        Forward propagation: if a base variable is removed/fixed,
        how do edge nodes change?

        Args:
            removed_base_var: ID of the base variable being fixed

        Returns:
            New edge node values after the fix
        """
        # Remove the base variable and recompute
        original_values = {en.id: en.value for en in self.get_edge_nodes()}

        # Simulate removal
        if removed_base_var in self._base_variables:
            saved = self._base_variables.pop(removed_base_var)
            self._edge_nodes = {}  # Force recompute
            new_values = {en.id: en.value for en in self.get_edge_nodes()}
            self._base_variables[removed_base_var] = saved  # Restore
            self._edge_nodes = {}  # Force recompute back
            _ = self.get_edge_nodes()  # Restore original
            return new_values

        return original_values

    def backward_query(self, target_edge_node: str, target_value: float) -> list[dict]:
        """
        Backward propagation: what base variables must be fixed to achieve
        the target posture value?

        Args:
            target_edge_node: Which edge node to target
            target_value: Desired value (e.g., 1.0 for full coverage)

        Returns:
            List of fix recommendations (which base vars to address)
        """
        recommendations = []
        edge_node = self._edge_nodes.get(target_edge_node)
        if not edge_node:
            return recommendations

        current_value = edge_node.value
        if current_value >= target_value:
            return [{"action": "none", "reason": f"Already at {current_value:.2f} (target: {target_value:.2f})"}]

        # Identify which base variables contribute to this edge node's deficit
        for base_id in edge_node.base_variables:
            base_var = self._base_variables.get(base_id, {})
            recommendations.append({
                "base_variable": base_id,
                "description": base_var.get("description", base_id),
                "severity": base_var.get("severity", "Medium"),
                "fix_action": base_var.get("fix_action", f"Resolve {base_id}"),
                "estimated_posture_improvement": self._estimate_improvement(
                    target_edge_node, base_id
                ),
            })

        # Sort by estimated improvement (highest first)
        recommendations.sort(
            key=lambda r: r.get("estimated_posture_improvement", 0), reverse=True
        )
        return recommendations

    def _estimate_improvement(self, edge_node_id: str, base_var_id: str) -> float:
        """Estimate how much fixing one base variable improves the edge node."""
        edge_node = self._edge_nodes.get(edge_node_id)
        if not edge_node or not edge_node.base_variables:
            return 0.0
        # Simple model: each base variable contributes equally to the deficit
        deficit = 1.0 - edge_node.value
        contribution = deficit / max(len(edge_node.base_variables), 1)
        return contribution

    def _add_base_variable(self, var_id: str, **attrs) -> None:
        """Register a base variable (individual finding/fact)."""
        self._base_variables[var_id] = attrs
        self.graph.add_node(var_id, node_type="base_variable", **attrs)

    def _add_edge_node_connection(self, base_var_id: str, edge_node_id: str, weight: float = 0.5) -> None:
        """Connect a base variable to its effect (edge node)."""
        self.graph.add_edge(base_var_id, edge_node_id, weight=weight, edge_type="causes")
