"""
Base class for all causal sub-graphs in the Federated SCM.

Each sub-graph:
1. Operates on its own domain (SAST, DAST, Architecture, etc.)
2. Performs internal causal reasoning (within-layer)
3. Produces "edge nodes" — aggregated causal variables that represent
   this layer's contribution to the master DAG
4. Supports tactical-level counterfactuals (within-layer interventions)
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional

import networkx as nx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ──── EDGE NODE MODELS ───────────────────────────────────────────────────────


class EdgeNode(BaseModel):
    """
    An edge node is a variable promoted from a sub-graph to the master DAG.

    It represents an aggregated causal summary of what the sub-graph
    found — abstracting away internal complexity while preserving
    causal semantics.

    Properties:
    - id: Unique identifier (prefixed by layer, e.g., "sast.critical_count")
    - name: Human-readable name
    - layer: Which sub-graph produced it
    - value: Current computed value (float 0-1 normalized, or categorical)
    - causal_strength: How strongly this variable influences downstream nodes
    - metadata: Supporting evidence for the value
    """

    id: str
    name: str
    layer: str
    value: float = Field(ge=0.0, le=1.0, default=0.0)
    causal_strength: float = Field(ge=0.0, le=1.0, default=0.5)
    evidence: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    # For counterfactual: what value would this take under intervention?
    counterfactual_value: Optional[float] = None


class SubGraphSummary(BaseModel):
    """Summary statistics from a sub-graph's internal analysis."""

    layer: str
    total_nodes: int = 0
    total_edges: int = 0
    internal_paths_found: int = 0
    confounders_found: int = 0
    mediators_found: list[str] = Field(default_factory=list)
    key_findings: list[str] = Field(default_factory=list)


class TacticalCounterfactual(BaseModel):
    """Result of a within-layer counterfactual analysis."""

    layer: str
    intervention: str
    intervention_description: str
    edge_nodes_before: dict[str, float] = Field(default_factory=dict)
    edge_nodes_after: dict[str, float] = Field(default_factory=dict)
    delta: dict[str, float] = Field(default_factory=dict)
    effectiveness: float = Field(ge=0.0, le=1.0, default=0.0)
    recommendation: str = ""


# ──── BASE SUB-GRAPH CLASS ───────────────────────────────────────────────────


class CausalSubGraph(ABC):
    """
    Abstract base class for domain-specific causal sub-graphs.

    Each sub-graph encapsulates causal reasoning for a single data source:
    - SAST findings (code-level)
    - DAST findings (runtime-level)
    - Repository architecture (structure-level)
    - Infrastructure config (deployment-level)

    The sub-graph:
    1. Receives raw data from its domain
    2. Constructs internal causal nodes and edges
    3. Performs within-layer analysis (paths, confounders, mediators)
    4. Produces edge nodes for the master DAG
    5. Supports tactical counterfactual queries
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self._nodes: dict[str, dict] = {}
        self._edge_nodes: dict[str, EdgeNode] = {}
        self._built = False

    @property
    @abstractmethod
    def layer_name(self) -> str:
        """Unique identifier for this layer (e.g., 'sast', 'dast', 'repo')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """What this sub-graph reasons about."""
        ...

    @abstractmethod
    def build(self, data: dict) -> None:
        """
        Construct the internal causal graph from raw input data.

        Args:
            data: Layer-specific input data (findings, components, etc.)
        """
        ...

    @abstractmethod
    def compute_edge_nodes(self) -> list[EdgeNode]:
        """
        Compute and return edge nodes for the master DAG.

        This is the INTERFACE between the sub-graph and the master.
        Each edge node is an aggregated causal variable that summarizes
        this layer's contribution to overall risk.

        Returns:
            List of EdgeNode objects to promote to master DAG
        """
        ...

    @abstractmethod
    def tactical_counterfactual(self, intervention: str, params: dict) -> TacticalCounterfactual:
        """
        Perform a within-layer counterfactual analysis.

        "If intervention X is applied within this layer,
         how do the edge nodes change?"

        Args:
            intervention: Type of intervention (e.g., "fix_critical_vulns")
            params: Intervention parameters

        Returns:
            TacticalCounterfactual with before/after edge node values
        """
        ...

    # ──── SHARED METHODS ─────────────────────────────────────────────────

    def get_edge_nodes(self) -> list[EdgeNode]:
        """Get the current edge nodes (call compute_edge_nodes first)."""
        if not self._edge_nodes:
            self._edge_nodes = {en.id: en for en in self.compute_edge_nodes()}
        return list(self._edge_nodes.values())

    def get_edge_node(self, node_id: str) -> Optional[EdgeNode]:
        """Get a specific edge node by ID."""
        return self._edge_nodes.get(node_id)

    def get_summary(self) -> SubGraphSummary:
        """Get summary statistics for this sub-graph."""
        return SubGraphSummary(
            layer=self.layer_name,
            total_nodes=self.graph.number_of_nodes(),
            total_edges=self.graph.number_of_edges(),
            internal_paths_found=self._count_internal_paths(),
            confounders_found=self._count_confounders(),
            mediators_found=self._get_top_mediators(),
            key_findings=self._get_key_findings(),
        )

    def reset(self) -> None:
        """Clear the sub-graph for recomputation."""
        self.graph.clear()
        self._nodes.clear()
        self._edge_nodes.clear()
        self._built = False

    # ──── INTERNAL GRAPH OPERATIONS ──────────────────────────────────────

    def _add_node(self, node_id: str, **attrs) -> None:
        """Add a node to the internal graph."""
        self._nodes[node_id] = attrs
        self.graph.add_node(node_id, **attrs)

    def _add_edge(self, source: str, target: str, **attrs) -> None:
        """Add an edge to the internal graph (only if both nodes exist)."""
        if source in self._nodes and target in self._nodes:
            self.graph.add_edge(source, target, **attrs)

    def _count_internal_paths(self) -> int:
        """Count significant causal paths within this sub-graph."""
        # Find source nodes (no incoming edges) and sink nodes (no outgoing)
        sources = [n for n in self.graph.nodes if self.graph.in_degree(n) == 0]
        sinks = [n for n in self.graph.nodes if self.graph.out_degree(n) == 0]

        count = 0
        for s in sources:
            for t in sinks:
                if s != t and nx.has_path(self.graph, s, t):
                    count += 1
        return count

    def _count_confounders(self) -> int:
        """Count potential confounders (nodes with 2+ outgoing to related nodes)."""
        count = 0
        for node in self.graph.nodes:
            successors = list(self.graph.successors(node))
            if len(successors) >= 2:
                # Check if any pair of successors is also connected
                for i, a in enumerate(successors):
                    for b in successors[i + 1:]:
                        if self.graph.has_edge(a, b) or self.graph.has_edge(b, a):
                            count += 1
                            break
        return count

    def _get_top_mediators(self) -> list[str]:
        """Find top mediator nodes (highest betweenness centrality)."""
        if self.graph.number_of_nodes() < 3:
            return []
        try:
            centrality = nx.betweenness_centrality(self.graph)
            sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
            return [node_id for node_id, score in sorted_nodes[:5] if score > 0]
        except Exception:
            return []

    def _get_key_findings(self) -> list[str]:
        """Summarize key findings from the sub-graph (override in subclasses)."""
        findings = []
        if self.graph.number_of_nodes() > 0:
            findings.append(f"{self.graph.number_of_nodes()} nodes analyzed")
        if self.graph.number_of_edges() > 0:
            findings.append(f"{self.graph.number_of_edges()} causal relationships identified")
        return findings

    def _normalize(self, value: float, max_value: float) -> float:
        """Normalize a value to 0-1 range."""
        if max_value <= 0:
            return 0.0
        return min(1.0, value / max_value)
