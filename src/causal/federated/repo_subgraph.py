"""
Repository/Architecture Sub-Graph — Structure-Level Causal Reasoning.

This sub-graph reasons about the discovered system architecture:
- Service topology and dependencies
- Trust boundary structure
- Data flow patterns and sensitivity
- Public exposure surface
- Defense-in-depth indicators

Internal causal relationships:
  service → connects_to → database → stores(PII)
  service → exposed_to → internet (trust boundary crossing)
  service_A → depends_on → service_B (dependency chain)
  no_segmentation → enables → lateral_movement

Edge nodes promoted to master:
  - repo.public_exposure: ratio of public-facing components
  - repo.trust_boundary_crossings: density of cross-boundary flows
  - repo.data_sensitivity: highest sensitivity level in flows
  - repo.dependency_depth: max service dependency chain length
  - repo.defense_depth: layered security indicators
  - repo.single_point_of_failure: components critical to many flows
"""

import logging
from collections import Counter
from typing import Optional

import networkx as nx

from src.causal.federated.base import (
    CausalSubGraph,
    EdgeNode,
    TacticalCounterfactual,
)

logger = logging.getLogger(__name__)


class RepoSubGraph(CausalSubGraph):
    """
    Causal sub-graph for repository/architecture structure.

    Reasons about how the system is DESIGNED — topology, boundaries,
    data sensitivity, and structural risk factors. This is independent
    of specific vulnerabilities (handled by SAST/DAST layers).
    """

    @property
    def layer_name(self) -> str:
        return "repo"

    @property
    def description(self) -> str:
        return "Structure-level causal reasoning from repository architecture analysis"

    def build(self, data: dict) -> None:
        """
        Build the architecture sub-graph from the component graph.

        Args:
            data: {
                "component_graph": full ComponentGraph dict from analyzer engine
            }
        """
        component_graph = data.get("component_graph", {})
        components = component_graph.get("components", [])
        flows = component_graph.get("data_flows", [])
        boundaries = component_graph.get("trust_boundaries", [])

        logger.info(f"Building Repo sub-graph from {len(components)} components, {len(flows)} flows")

        self._components = [c for c in components if c.get("metadata", {}).get("type") != "metadata"]
        self._flows = flows
        self._boundaries = boundaries

        # Build structural nodes
        self._add_component_nodes()
        self._add_flow_edges()
        self._add_boundary_structure()
        self._add_exposure_analysis()
        self._add_data_sensitivity_analysis()
        self._add_dependency_chains()

        self._built = True
        logger.info(
            f"Repo sub-graph built: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )

    def compute_edge_nodes(self) -> list[EdgeNode]:
        """Compute edge nodes representing architectural risk factors."""
        edge_nodes = []
        total_components = max(len(self._components), 1)

        # 1. Public Exposure Ratio
        public_count = sum(1 for c in self._components if c.get("is_public_facing"))
        exposure_ratio = public_count / total_components
        edge_nodes.append(EdgeNode(
            id="repo.public_exposure",
            name="Architecture Public Exposure",
            layer=self.layer_name,
            value=exposure_ratio,
            causal_strength=0.8,
            evidence=[
                f"Public-facing components: {public_count}/{total_components}",
                f"Exposure ratio: {exposure_ratio:.0%}",
            ],
            metadata={"public_count": str(public_count)},
        ))

        # 2. Trust Boundary Crossing Density
        crossing_count = sum(1 for f in self._flows if f.get("crosses_trust_boundary"))
        total_flows = max(len(self._flows), 1)
        crossing_density = crossing_count / total_flows
        edge_nodes.append(EdgeNode(
            id="repo.trust_boundary_crossings",
            name="Architecture Trust Boundary Crossing Density",
            layer=self.layer_name,
            value=crossing_density,
            causal_strength=0.85,
            evidence=[
                f"Cross-boundary flows: {crossing_count}/{total_flows}",
                f"Boundaries defined: {len(self._boundaries)}",
            ],
        ))

        # 3. Data Sensitivity Level
        sensitivity_score = self._compute_data_sensitivity()
        edge_nodes.append(EdgeNode(
            id="repo.data_sensitivity",
            name="Architecture Data Sensitivity",
            layer=self.layer_name,
            value=sensitivity_score,
            causal_strength=0.75,
            evidence=[f"Data sensitivity score: {sensitivity_score:.2f}"],
        ))

        # 4. Dependency Depth (longest chain)
        dep_depth = self._compute_dependency_depth()
        edge_nodes.append(EdgeNode(
            id="repo.dependency_depth",
            name="Architecture Dependency Depth",
            layer=self.layer_name,
            value=self._normalize(dep_depth, 10),
            causal_strength=0.5,
            evidence=[f"Maximum dependency chain length: {dep_depth}"],
        ))

        # 5. Defense-in-Depth Score
        defense_score = self._compute_defense_depth()
        edge_nodes.append(EdgeNode(
            id="repo.defense_depth",
            name="Architecture Defense-in-Depth",
            layer=self.layer_name,
            value=defense_score,
            causal_strength=0.7,
            evidence=[f"Defense-in-depth score: {defense_score:.2f}"],
        ))

        # 6. Single Point of Failure (component on most paths)
        spof_score = self._compute_spof_risk()
        edge_nodes.append(EdgeNode(
            id="repo.single_point_of_failure",
            name="Architecture Single Point of Failure Risk",
            layer=self.layer_name,
            value=spof_score,
            causal_strength=0.65,
            evidence=[f"SPOF risk score: {spof_score:.2f}"],
        ))

        # 7. Network Segmentation
        segmentation_score = self._compute_segmentation()
        edge_nodes.append(EdgeNode(
            id="repo.segmentation",
            name="Architecture Network Segmentation",
            layer=self.layer_name,
            value=segmentation_score,
            causal_strength=0.6,
            evidence=[f"Segmentation score: {segmentation_score:.2f}"],
        ))

        self._edge_nodes = {en.id: en for en in edge_nodes}
        return edge_nodes

    def tactical_counterfactual(self, intervention: str, params: dict) -> TacticalCounterfactual:
        """
        Tactical counterfactual within the Architecture layer.

        Supported interventions:
        - "add_gateway": What if an API gateway is added before public services?
        - "add_segmentation": What if network segmentation is added?
        - "encrypt_flows": What if all cross-boundary flows are encrypted?
        - "reduce_exposure": What if public exposure is reduced by X%?
        """
        before = {en.id: en.value for en in self.get_edge_nodes()}

        if intervention == "add_gateway":
            after = before.copy()
            # Gateway reduces exposure and adds defense layer
            after["repo.public_exposure"] = before["repo.public_exposure"] * 0.3
            after["repo.defense_depth"] = min(1.0, before["repo.defense_depth"] + 0.3)
            description = "Add API gateway as single entry point for all external traffic"

        elif intervention == "add_segmentation":
            after = before.copy()
            after["repo.segmentation"] = min(1.0, before["repo.segmentation"] + 0.4)
            after["repo.single_point_of_failure"] = before["repo.single_point_of_failure"] * 0.5
            description = "Implement network segmentation between service tiers"

        elif intervention == "encrypt_flows":
            after = before.copy()
            after["repo.trust_boundary_crossings"] = before["repo.trust_boundary_crossings"] * 0.4
            description = "Encrypt all data flows that cross trust boundaries"

        elif intervention == "reduce_exposure":
            reduction = params.get("reduction_pct", 50) / 100.0
            after = before.copy()
            after["repo.public_exposure"] = before["repo.public_exposure"] * (1 - reduction)
            description = f"Reduce public-facing components by {params.get('reduction_pct', 50)}%"

        else:
            after = before.copy()
            description = f"Unknown intervention: {intervention}"

        delta = {k: before[k] - after.get(k, before[k]) for k in before}
        total_delta = sum(abs(d) for d in delta.values())
        effectiveness = min(1.0, total_delta / max(len(delta), 1))

        return TacticalCounterfactual(
            layer=self.layer_name,
            intervention=intervention,
            intervention_description=description,
            edge_nodes_before=before,
            edge_nodes_after=after,
            delta=delta,
            effectiveness=effectiveness,
            recommendation=(
                f"Applying '{description}' would reduce architectural risk by "
                f"{effectiveness:.0%} on average."
            ),
        )

    # ──── INTERNAL GRAPH CONSTRUCTION ────────────────────────────────────

    def _add_component_nodes(self) -> None:
        """Add architecture component nodes."""
        for comp in self._components:
            self._add_node(
                comp["id"],
                node_type=comp.get("type", "process"),
                name=comp.get("name", ""),
                is_public=comp.get("is_public_facing", False),
                has_auth=comp.get("has_authentication", False),
                has_encryption=comp.get("has_encryption", False),
                technology=comp.get("technology", ""),
            )

    def _add_flow_edges(self) -> None:
        """Add data flow edges between components."""
        for flow in self._flows:
            source = flow.get("source_id", "")
            target = flow.get("target_id", "")
            if source in self._nodes and target in self._nodes:
                self._add_edge(
                    source, target,
                    edge_type="data_flow",
                    protocol=flow.get("protocol", ""),
                    encrypted=flow.get("is_encrypted", False),
                    crosses_boundary=flow.get("crosses_trust_boundary", False),
                    sensitivity=str(flow.get("data_sensitivity", [])),
                )

    def _add_boundary_structure(self) -> None:
        """Add trust boundary nodes and containment relationships."""
        for boundary in self._boundaries:
            boundary_id = f"boundary_{boundary['id']}"
            self._add_node(
                boundary_id,
                node_type="trust_boundary",
                name=boundary.get("name", ""),
                trust_level=boundary.get("trust_level", "unknown"),
            )

    def _add_exposure_analysis(self) -> None:
        """Add exposure analysis nodes."""
        exposure_node = "analysis_exposure"
        self._add_node(exposure_node, node_type="analysis", analysis_type="exposure")

        for comp in self._components:
            if comp.get("is_public_facing"):
                if comp["id"] in self._nodes:
                    self._add_edge(comp["id"], exposure_node, edge_type="contributes_to")

    def _add_data_sensitivity_analysis(self) -> None:
        """Add data sensitivity analysis based on flow content."""
        sensitivity_node = "analysis_data_sensitivity"
        self._add_node(sensitivity_node, node_type="analysis", analysis_type="data_sensitivity")

        for flow in self._flows:
            sensitivity = flow.get("data_sensitivity", [])
            if sensitivity:
                source = flow.get("source_id", "")
                if source in self._nodes:
                    self._add_edge(
                        source, sensitivity_node,
                        edge_type="handles_sensitive_data",
                        sensitivity_types=str(sensitivity),
                    )

    def _add_dependency_chains(self) -> None:
        """Analyze and record dependency chains between services."""
        # Already captured through flow edges — this adds metadata
        pass

    # ──── COMPUTATION HELPERS ────────────────────────────────────────────

    def _compute_data_sensitivity(self) -> float:
        """Compute overall data sensitivity score."""
        sensitivity_weights = {
            "credentials": 1.0,
            "secret": 1.0,
            "financial": 0.9,
            "pii": 0.8,
            "confidential": 0.7,
            "internal": 0.3,
            "public": 0.0,
        }

        max_sensitivity = 0.0
        for flow in self._flows:
            for sens in flow.get("data_sensitivity", []):
                sens_lower = sens.lower() if isinstance(sens, str) else str(sens).lower()
                weight = sensitivity_weights.get(sens_lower, 0.3)
                max_sensitivity = max(max_sensitivity, weight)

        return max_sensitivity

    def _compute_dependency_depth(self) -> int:
        """Compute the longest dependency chain in the architecture."""
        if self.graph.number_of_nodes() == 0:
            return 0
        try:
            return nx.dag_longest_path_length(self.graph)
        except (nx.NetworkXError, nx.NetworkXUnfeasible):
            # Graph may have cycles — use shortest paths instead
            try:
                lengths = dict(nx.all_pairs_shortest_path_length(self.graph))
                max_len = 0
                for source_lengths in lengths.values():
                    for length in source_lengths.values():
                        max_len = max(max_len, length)
                return max_len
            except Exception:
                return 0

    def _compute_defense_depth(self) -> float:
        """
        Compute defense-in-depth score.

        Higher = more layered defenses:
        - Has authentication on services
        - Has encryption on flows
        - Has multiple trust boundaries
        - Has non-direct path from external to data stores
        """
        scores = []

        # Auth coverage
        auth_count = sum(1 for c in self._components if c.get("has_authentication"))
        scores.append(auth_count / max(len(self._components), 1))

        # Encryption on cross-boundary flows
        cross_flows = [f for f in self._flows if f.get("crosses_trust_boundary")]
        encrypted_cross = sum(1 for f in cross_flows if f.get("is_encrypted"))
        scores.append(encrypted_cross / max(len(cross_flows), 1) if cross_flows else 0.5)

        # Multiple trust boundaries (more = better segmentation)
        scores.append(min(1.0, len(self._boundaries) / 3.0))

        # Indirection: data stores not directly reachable from external entities
        data_stores = [c for c in self._components if c.get("type") == "data_store"]
        external = [c for c in self._components if c.get("type") == "external_entity"]
        direct_access = 0
        for ext in external:
            for ds in data_stores:
                if self.graph.has_edge(ext["id"], ds["id"]):
                    direct_access += 1
        indirect_score = 1.0 - (direct_access / max(len(data_stores) * len(external), 1))
        scores.append(indirect_score)

        return sum(scores) / max(len(scores), 1)

    def _compute_spof_risk(self) -> float:
        """Compute single-point-of-failure risk using betweenness centrality."""
        if self.graph.number_of_nodes() < 3:
            return 0.0
        try:
            centrality = nx.betweenness_centrality(self.graph)
            if not centrality:
                return 0.0
            max_centrality = max(centrality.values())
            return min(1.0, max_centrality * 2)  # Scale: 0.5 centrality = 1.0 risk
        except Exception:
            return 0.0

    def _compute_segmentation(self) -> float:
        """
        Compute network segmentation quality.

        Higher = better segmented:
        - Multiple trust boundaries
        - Components properly grouped
        - Limited cross-boundary flows relative to total
        """
        if not self._boundaries:
            return 0.0

        # Ratio of boundaries to components (more boundaries per component = better)
        boundary_ratio = min(1.0, len(self._boundaries) / max(len(self._components) / 3, 1))

        # Inverse of cross-boundary flow ratio (fewer crossings = better segmented)
        total_flows = max(len(self._flows), 1)
        crossings = sum(1 for f in self._flows if f.get("crosses_trust_boundary"))
        crossing_ratio = 1.0 - (crossings / total_flows)

        return (boundary_ratio + crossing_ratio) / 2.0
