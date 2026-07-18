"""
Causal Threat Engine — the core intelligence layer.

Uses a Structural Causal Model (SCM) represented as a directed graph
to reason about:
- Attack paths (causal chains from entry to impact)
- Impact propagation (if X compromised, what else is affected?)
- Confounders (factors that inflate/deflate apparent risk)
- Mediators (intervention points that break attack chains)
- Counterfactual mitigation analysis (if we fix X, does threat Y vanish?)
"""

import logging
from typing import Optional

import networkx as nx

from src.causal.models import (
    AttackPath,
    CausalAnalysisResult,
    CausalEdge,
    CausalEdgeType,
    CausalNode,
    CausalNodeType,
    ConfounderResult,
    CounterfactualResult,
    MediatorResult,
)
from src.core.config import get_config

logger = logging.getLogger(__name__)


class CausalThreatEngine:
    """
    Builds and reasons over a causal graph for threat modeling.

    The causal graph captures cause-effect relationships between:
    - Architecture components (services, databases, external entities)
    - Vulnerabilities (from SAST/DAST findings)
    - Conditions (exposure, auth status, encryption status)
    - Threats (STRIDE categories)
    - Impacts (business consequences)

    This enables:
    - Attack path enumeration
    - Impact propagation (blast radius analysis)
    - Confounder detection (what inflates perceived risk?)
    - Mediator identification (where to intervene?)
    - Counterfactual reasoning (if we fix X, does Y go away?)
    """

    def __init__(self):
        config = get_config()
        self.graph = nx.DiGraph()
        self.max_path_depth = config.causal.max_attack_path_depth
        self.severity_weights = config.causal.severity_weights
        self._nodes: dict[str, CausalNode] = {}
        self._edges: list[CausalEdge] = []

    def build_graph(
        self,
        component_graph: dict,
        sast_findings: list,
        dast_findings: list,
    ) -> None:
        """
        Construct the causal graph from multiple data sources.

        Args:
            component_graph: Discovered architecture (ComponentGraph dict)
            sast_findings: Normalized SAST findings
            dast_findings: Normalized DAST findings
        """
        logger.info("Building causal threat graph...")

        # Layer 1: Structural edges from architecture
        self._add_structural_nodes(component_graph)

        # Layer 2: Vulnerability nodes from SAST
        self._add_sast_findings(sast_findings, component_graph)

        # Layer 3: Vulnerability nodes from DAST
        self._add_dast_findings(dast_findings, component_graph)

        # Layer 4: Domain knowledge edges (CWE → impact mappings)
        self._add_domain_knowledge_edges()

        # Layer 5: Contextual condition nodes
        self._add_contextual_conditions(component_graph)

        logger.info(
            f"Causal graph built: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )

    def analyze(self) -> dict:
        """
        Run the full causal analysis and return results.

        Returns:
            CausalAnalysisResult as dictionary
        """
        logger.info("Running causal analysis...")

        # 1. Enumerate attack paths
        attack_paths = self._enumerate_attack_paths()

        # 2. Identify confounders
        confounders = self._identify_confounders()

        # 3. Identify mediators (intervention points)
        mediators = self._identify_mediators()

        # 4. Propagate impact (blast radius)
        impact_scores = self._propagate_impact()

        # 5. Run counterfactual analysis
        counterfactuals = self._counterfactual_analysis()

        # 6. Build per-element scoring
        attack_path_scores = self._score_elements_by_attack_paths(attack_paths)
        confirmed_exploitable = self._get_confirmed_exploitable()

        result = CausalAnalysisResult(
            attack_paths=attack_paths,
            confounders=confounders,
            mediators=mediators,
            impact_scores=impact_scores,
            counterfactuals=counterfactuals,
            element_scores=attack_path_scores,
            confirmed_exploitable=confirmed_exploitable,
            graph_stats={
                "total_nodes": self.graph.number_of_nodes(),
                "total_edges": self.graph.number_of_edges(),
                "vulnerability_nodes": len([
                    n for n in self._nodes.values()
                    if n.node_type == CausalNodeType.VULNERABILITY
                ]),
                "attack_paths_found": len(attack_paths),
                "mediators_found": len(mediators),
                "confounders_found": len(confounders),
            },
        )

        logger.info(
            f"Causal analysis complete: {len(attack_paths)} attack paths, "
            f"{len(mediators)} mediators, {len(confounders)} confounders"
        )

        return result.to_pipeline_output()

    # ──── GRAPH CONSTRUCTION ─────────────────────────────────────────────

    def _add_structural_nodes(self, component_graph: dict) -> None:
        """Add nodes and edges from the discovered architecture."""
        components = component_graph.get("components", [])
        flows = component_graph.get("data_flows", [])

        # Add component nodes
        for comp in components:
            if comp.get("metadata", {}).get("type") == "metadata":
                continue

            node_type = self._map_component_to_node_type(comp.get("type", ""))
            node = CausalNode(
                id=comp["id"],
                name=comp.get("name", comp["id"]),
                node_type=node_type,
                metadata={
                    "technology": comp.get("technology", ""),
                    "is_public": str(comp.get("is_public_facing", False)),
                    "has_auth": str(comp.get("has_authentication", False)),
                    "has_encryption": str(comp.get("has_encryption", False)),
                },
            )
            self._add_node(node)

        # Add structural edges from data flows
        for flow in flows:
            edge = CausalEdge(
                source_id=flow["source_id"],
                target_id=flow["target_id"],
                edge_type=CausalEdgeType.CONNECTS_TO,
                weight=1.0,
                metadata={
                    "protocol": flow.get("protocol", ""),
                    "encrypted": str(flow.get("is_encrypted", False)),
                    "crosses_boundary": str(flow.get("crosses_trust_boundary", False)),
                },
            )
            self._add_edge(edge)

    def _add_sast_findings(self, findings: list, component_graph: dict) -> None:
        """Add SAST vulnerability nodes and map them to components."""
        for finding in findings:
            vuln_id = f"vuln-sast-{finding.get('id', 'unknown')}"
            node = CausalNode(
                id=vuln_id,
                name=finding.get("title", "SAST Finding"),
                node_type=CausalNodeType.VULNERABILITY,
                metadata={
                    "source": "SAST",
                    "cwe": finding.get("cwe_id", ""),
                    "severity": finding.get("severity", "Medium"),
                    "file": finding.get("file_path", ""),
                    "line": str(finding.get("line_number", 0)),
                },
            )
            self._add_node(node)

            # Map finding to component (by file path)
            component_id = self._map_finding_to_component(finding, component_graph)
            if component_id:
                edge = CausalEdge(
                    source_id=vuln_id,
                    target_id=component_id,
                    edge_type=CausalEdgeType.ENABLES,
                    weight=self._severity_to_weight(finding.get("severity", "Medium")),
                )
                self._add_edge(edge)

    def _add_dast_findings(self, findings: list, component_graph: dict) -> None:
        """Add DAST vulnerability nodes and map them to components."""
        for finding in findings:
            vuln_id = f"vuln-dast-{finding.get('id', 'unknown')}"
            node = CausalNode(
                id=vuln_id,
                name=finding.get("title", "DAST Finding"),
                node_type=CausalNodeType.VULNERABILITY,
                metadata={
                    "source": "DAST",
                    "cwe": finding.get("cwe_id", ""),
                    "severity": finding.get("severity", "Medium"),
                    "url": finding.get("url", ""),
                    "confirmed_exploitable": "true",
                },
            )
            self._add_node(node)

            # Map DAST finding to component (by URL/endpoint)
            component_id = self._map_dast_to_component(finding, component_graph)
            if component_id:
                edge = CausalEdge(
                    source_id=vuln_id,
                    target_id=component_id,
                    edge_type=CausalEdgeType.ENABLES,
                    weight=self._severity_to_weight(finding.get("severity", "Medium")),
                    metadata={"confirmed": "true"},
                )
                self._add_edge(edge)

    def _add_domain_knowledge_edges(self) -> None:
        """
        Add causal edges based on security domain knowledge.

        Maps vulnerability types (CWE) to their consequences:
        - CWE-89 (SQLi) → enables → unauthorized data access
        - CWE-287 (Auth bypass) → enables → spoofing
        - CWE-311 (Missing encryption) → enables → information disclosure
        """
        # Create impact nodes
        impacts = {
            "impact-data-breach": "Data Breach",
            "impact-unauthorized-access": "Unauthorized Access",
            "impact-service-disruption": "Service Disruption",
            "impact-privilege-escalation": "Privilege Escalation",
            "impact-data-tampering": "Data Tampering",
        }

        for impact_id, impact_name in impacts.items():
            node = CausalNode(
                id=impact_id,
                name=impact_name,
                node_type=CausalNodeType.IMPACT,
            )
            self._add_node(node)

        # Map CWE categories to impacts
        cwe_impact_map = {
            "CWE-89": ["impact-data-breach", "impact-unauthorized-access"],  # SQLi
            "CWE-79": ["impact-data-breach"],  # XSS
            "CWE-287": ["impact-unauthorized-access", "impact-privilege-escalation"],  # Auth
            "CWE-311": ["impact-data-breach"],  # Missing encryption
            "CWE-319": ["impact-data-breach"],  # Cleartext transmission
            "CWE-269": ["impact-privilege-escalation"],  # Improper privilege
            "CWE-400": ["impact-service-disruption"],  # Resource exhaustion
            "CWE-770": ["impact-service-disruption"],  # Unrestricted resource allocation
        }

        # Connect vulnerability nodes to impact nodes via domain knowledge
        for node_id, node in self._nodes.items():
            if node.node_type != CausalNodeType.VULNERABILITY:
                continue

            cwe = node.metadata.get("cwe", "")
            if cwe in cwe_impact_map:
                for impact_id in cwe_impact_map[cwe]:
                    edge = CausalEdge(
                        source_id=node_id,
                        target_id=impact_id,
                        edge_type=CausalEdgeType.CAUSES,
                        weight=0.7,
                        metadata={"source": "domain_knowledge"},
                    )
                    self._add_edge(edge)

    def _add_contextual_conditions(self, component_graph: dict) -> None:
        """
        Add contextual condition nodes that act as confounders.

        These are factors that influence both vulnerability exploitability
        and impact severity:
        - Internet exposure
        - Data sensitivity
        - Authentication presence
        """
        components = component_graph.get("components", [])

        for comp in components:
            if comp.get("metadata", {}).get("type") == "metadata":
                continue

            comp_id = comp["id"]

            # Internet exposure as a confounder
            if comp.get("is_public_facing"):
                condition_id = f"condition-exposed-{comp_id}"
                node = CausalNode(
                    id=condition_id,
                    name=f"Internet Exposed ({comp.get('name', '')})",
                    node_type=CausalNodeType.CONDITION,
                    metadata={"type": "exposure", "component": comp_id},
                )
                self._add_node(node)

                # Exposure increases exploitability of associated vulns
                edge = CausalEdge(
                    source_id=condition_id,
                    target_id=comp_id,
                    edge_type=CausalEdgeType.INFLUENCES,
                    weight=0.8,
                    metadata={"effect": "increases_exploitability"},
                )
                self._add_edge(edge)

    # ──── CAUSAL ANALYSIS OPERATIONS ─────────────────────────────────────

    def _enumerate_attack_paths(self) -> list[AttackPath]:
        """
        Find all causal chains from vulnerability/entry nodes to impact nodes.

        An attack path is: Entry → Vulnerability → Component → ... → Impact
        """
        attack_paths = []

        # Find entry points (external entities, public-facing components)
        entry_nodes = [
            n_id for n_id, n in self._nodes.items()
            if n.node_type in [CausalNodeType.EXTERNAL_ENTITY, CausalNodeType.VULNERABILITY]
        ]

        # Find impact nodes
        impact_nodes = [
            n_id for n_id, n in self._nodes.items()
            if n.node_type == CausalNodeType.IMPACT
        ]

        for entry in entry_nodes:
            for impact in impact_nodes:
                try:
                    paths = list(nx.all_simple_paths(
                        self.graph, entry, impact,
                        cutoff=self.max_path_depth,
                    ))
                    for path in paths:
                        score = self._score_path(path)
                        attack_path = AttackPath(
                            path_nodes=path,
                            entry_point=entry,
                            target=impact,
                            score=score,
                            length=len(path),
                            crosses_trust_boundary=self._path_crosses_boundary(path),
                            node_names=[
                                self._nodes[n].name for n in path if n in self._nodes
                            ],
                        )
                        attack_paths.append(attack_path)
                except nx.NetworkXError:
                    continue

        # Sort by score (highest risk first)
        attack_paths.sort(key=lambda p: p.score, reverse=True)

        # Limit to top paths
        return attack_paths[:50]

    def _identify_confounders(self) -> list[ConfounderResult]:
        """
        Identify confounders in the causal graph.

        A confounder C for relationship A→B exists when:
        - C → A (C influences A)
        - C → B (C influences B)
        - C is NOT on the direct path A → B

        Example: "Internet exposure" confounds the relationship between
        "has vulnerability" and "is actually exploitable."
        """
        confounders = []
        condition_nodes = [
            n_id for n_id, n in self._nodes.items()
            if n.node_type == CausalNodeType.CONDITION
        ]

        for condition_id in condition_nodes:
            # Find all nodes this condition influences
            influenced = set(self.graph.successors(condition_id))

            # Check pairs of influenced nodes for potential confounding
            influenced_list = list(influenced)
            for i, node_a in enumerate(influenced_list):
                for node_b in influenced_list[i + 1:]:
                    # Check if there's a direct or indirect edge between A and B
                    if self.graph.has_edge(node_a, node_b) or self.graph.has_edge(node_b, node_a):
                        confounder = ConfounderResult(
                            confounder_id=condition_id,
                            confounder_name=self._nodes[condition_id].name,
                            relationship=(node_a, node_b),
                            implication=(
                                f"'{self._nodes[condition_id].name}' influences both "
                                f"'{self._nodes.get(node_a, CausalNode(id='', name=node_a, node_type=CausalNodeType.COMPONENT)).name}' "
                                f"and '{self._nodes.get(node_b, CausalNode(id='', name=node_b, node_type=CausalNodeType.COMPONENT)).name}'. "
                                f"Control for this factor when assessing true causal impact."
                            ),
                        )
                        confounders.append(confounder)

        return confounders

    def _identify_mediators(self) -> list[MediatorResult]:
        """
        Identify mediators — nodes on attack paths where intervention can break the chain.

        A mediator M on path A→B exists when:
        - A → M → B (M is on the causal path)
        - Blocking M would break the A→B causal chain

        These are your MITIGATION POINTS.
        """
        mediators = []
        mediator_frequency: dict[str, int] = {}

        # Find mediators on attack paths
        entry_nodes = [
            n_id for n_id, n in self._nodes.items()
            if n.node_type == CausalNodeType.VULNERABILITY
        ]
        impact_nodes = [
            n_id for n_id, n in self._nodes.items()
            if n.node_type == CausalNodeType.IMPACT
        ]

        for entry in entry_nodes:
            for impact in impact_nodes:
                try:
                    paths = list(nx.all_simple_paths(
                        self.graph, entry, impact, cutoff=self.max_path_depth
                    ))
                    for path in paths:
                        # Intermediate nodes (excluding entry and target) are mediators
                        for node_id in path[1:-1]:
                            mediator_frequency[node_id] = mediator_frequency.get(node_id, 0) + 1
                except nx.NetworkXError:
                    continue

        # Build mediator results sorted by frequency (most critical first)
        for node_id, frequency in sorted(
            mediator_frequency.items(), key=lambda x: x[1], reverse=True
        ):
            if node_id not in self._nodes:
                continue
            node = self._nodes[node_id]
            mediator = MediatorResult(
                mediator_id=node_id,
                mediator_name=node.name,
                paths_affected=frequency,
                node_type=node.node_type.value,
                intervention_suggestion=self._suggest_intervention(node),
                effectiveness_score=min(1.0, frequency / max(len(entry_nodes), 1)),
            )
            mediators.append(mediator)

        return mediators[:20]  # Top 20 mediators

    def _propagate_impact(self) -> dict[str, float]:
        """
        Calculate blast radius — if each component is compromised, what's affected?

        Uses BFS from each component node, weighted by edge weights.
        """
        impact_scores = {}

        component_nodes = [
            n_id for n_id, n in self._nodes.items()
            if n.node_type == CausalNodeType.COMPONENT
        ]

        for comp_id in component_nodes:
            # BFS to find reachable impact
            try:
                reachable = nx.single_source_shortest_path_length(
                    self.graph, comp_id, cutoff=self.max_path_depth
                )
                # Score based on how many impact nodes are reachable and distance
                score = 0.0
                for node_id, distance in reachable.items():
                    if node_id in self._nodes:
                        node = self._nodes[node_id]
                        if node.node_type == CausalNodeType.IMPACT:
                            score += 1.0 / (distance + 1)

                impact_scores[comp_id] = min(1.0, score)
            except nx.NetworkXError:
                impact_scores[comp_id] = 0.0

        return impact_scores

    def _counterfactual_analysis(self) -> list[CounterfactualResult]:
        """
        Counterfactual reasoning: "If mitigation X were applied, does threat Y vanish?"

        For each mediator, remove it from the graph temporarily and check
        if attack paths still exist.
        """
        counterfactuals = []

        # Get top mediators as candidates for intervention
        mediators = self._identify_mediators()

        for mediator in mediators[:10]:  # Analyze top 10
            # Temporarily remove the mediator node
            if not self.graph.has_node(mediator.mediator_id):
                continue

            # Count paths before removal
            paths_before = self._count_attack_paths()

            # Remove node temporarily
            edges_backup = list(self.graph.edges(mediator.mediator_id, data=True))
            in_edges_backup = list(self.graph.in_edges(mediator.mediator_id, data=True))
            self.graph.remove_node(mediator.mediator_id)

            # Count paths after removal
            paths_after = self._count_attack_paths()

            # Restore node
            self.graph.add_node(mediator.mediator_id)
            for u, v, data in edges_backup:
                self.graph.add_edge(u, v, **data)
            for u, v, data in in_edges_backup:
                self.graph.add_edge(u, v, **data)

            # Calculate effectiveness
            paths_blocked = paths_before - paths_after
            effectiveness = paths_blocked / max(paths_before, 1)

            counterfactual = CounterfactualResult(
                intervention_node=mediator.mediator_id,
                intervention_name=mediator.mediator_name,
                paths_before=paths_before,
                paths_after=paths_after,
                paths_blocked=paths_blocked,
                effectiveness=effectiveness,
                recommendation=(
                    f"Securing '{mediator.mediator_name}' would block "
                    f"{paths_blocked}/{paths_before} attack paths "
                    f"({effectiveness:.0%} reduction)"
                ),
            )
            counterfactuals.append(counterfactual)

        # Sort by effectiveness
        counterfactuals.sort(key=lambda c: c.effectiveness, reverse=True)
        return counterfactuals

    # ──── SCORING HELPERS ────────────────────────────────────────────────

    def _score_path(self, path: list[str]) -> float:
        """Score an attack path based on edge weights and path properties."""
        if len(path) < 2:
            return 0.0

        total_weight = 0.0
        for i in range(len(path) - 1):
            edge_data = self.graph.get_edge_data(path[i], path[i + 1], default={})
            total_weight += edge_data.get("weight", 0.5)

        # Normalize by path length (shorter paths = higher risk)
        normalized = total_weight / len(path)

        # Bonus for crossing trust boundaries
        if self._path_crosses_boundary(path):
            normalized *= 1.3

        return min(1.0, normalized)

    def _path_crosses_boundary(self, path: list[str]) -> bool:
        """Check if any edge in the path crosses a trust boundary."""
        for i in range(len(path) - 1):
            edge_data = self.graph.get_edge_data(path[i], path[i + 1], default={})
            if edge_data.get("crosses_boundary") == "true":
                return True
        return False

    def _count_attack_paths(self) -> int:
        """Count total attack paths in current graph state."""
        count = 0
        entry_nodes = [
            n_id for n_id in self.graph.nodes
            if n_id in self._nodes and self._nodes[n_id].node_type == CausalNodeType.VULNERABILITY
        ]
        impact_nodes = [
            n_id for n_id in self.graph.nodes
            if n_id in self._nodes and self._nodes[n_id].node_type == CausalNodeType.IMPACT
        ]

        for entry in entry_nodes:
            for impact in impact_nodes:
                try:
                    if nx.has_path(self.graph, entry, impact):
                        count += 1
                except nx.NetworkXError:
                    continue
        return count

    def _score_elements_by_attack_paths(self, attack_paths: list[AttackPath]) -> dict:
        """Build per-element attack path scores."""
        scores = {}
        for path in attack_paths:
            for node_id in path.path_nodes:
                if node_id not in scores:
                    scores[node_id] = {"score": 0.0, "paths_through": 0}
                scores[node_id]["score"] = max(scores[node_id]["score"], path.score)
                scores[node_id]["paths_through"] += 1
        return scores

    def _get_confirmed_exploitable(self) -> list[str]:
        """Get component IDs confirmed exploitable via DAST."""
        confirmed = []
        for node_id, node in self._nodes.items():
            if node.node_type == CausalNodeType.VULNERABILITY:
                if node.metadata.get("confirmed_exploitable") == "true":
                    # Find the component this vuln is connected to
                    for successor in self.graph.successors(node_id):
                        if successor in self._nodes:
                            if self._nodes[successor].node_type == CausalNodeType.COMPONENT:
                                confirmed.append(successor)
        return list(set(confirmed))

    def _suggest_intervention(self, node: CausalNode) -> str:
        """Suggest a mitigation intervention for a mediator node."""
        if node.node_type == CausalNodeType.COMPONENT:
            if node.metadata.get("has_auth") == "False":
                return f"Add authentication to '{node.name}'"
            if node.metadata.get("is_public") == "True":
                return f"Restrict external access to '{node.name}' via API gateway"
            return f"Harden '{node.name}' (access controls, input validation)"
        if node.node_type == CausalNodeType.VULNERABILITY:
            return f"Remediate vulnerability: {node.name}"
        return f"Secure or isolate '{node.name}'"

    def _severity_to_weight(self, severity: str) -> float:
        """Convert severity string to edge weight."""
        weights = {"Critical": 1.0, "High": 0.8, "Medium": 0.5, "Low": 0.3}
        return weights.get(severity, 0.5)

    # ──── NODE/EDGE MANAGEMENT ───────────────────────────────────────────

    def _add_node(self, node: CausalNode) -> None:
        """Add a node to the causal graph."""
        self._nodes[node.id] = node
        self.graph.add_node(node.id, **node.metadata)

    def _add_edge(self, edge: CausalEdge) -> None:
        """Add an edge to the causal graph."""
        # Only add if both nodes exist
        if edge.source_id in self._nodes and edge.target_id in self._nodes:
            self._edges.append(edge)
            self.graph.add_edge(
                edge.source_id,
                edge.target_id,
                weight=edge.weight,
                edge_type=edge.edge_type.value,
                **edge.metadata,
            )

    def _map_component_to_node_type(self, comp_type: str) -> CausalNodeType:
        """Map architecture component type to causal node type."""
        mapping = {
            "process": CausalNodeType.COMPONENT,
            "data_store": CausalNodeType.DATA_STORE,
            "external_entity": CausalNodeType.EXTERNAL_ENTITY,
        }
        return mapping.get(comp_type, CausalNodeType.COMPONENT)

    def _map_finding_to_component(self, finding: dict, component_graph: dict) -> Optional[str]:
        """Map a SAST finding to its parent component by file path."""
        file_path = finding.get("file_path", "")
        if not file_path:
            return None

        # Check which component owns this file
        for comp in component_graph.get("components", []):
            source_paths = comp.get("source_paths", [])
            for src_path in source_paths:
                if file_path.startswith(src_path) or src_path in file_path:
                    return comp["id"]

        # Fallback: find by directory matching
        components = component_graph.get("components", [])
        if components:
            # Return first non-metadata component as fallback
            for comp in components:
                if comp.get("metadata", {}).get("type") != "metadata":
                    return comp["id"]

        return None

    def _map_dast_to_component(self, finding: dict, component_graph: dict) -> Optional[str]:
        """Map a DAST finding to its component by URL/endpoint."""
        url = finding.get("url", "")
        if not url:
            return None

        # Find public-facing components
        for comp in component_graph.get("components", []):
            if comp.get("is_public_facing"):
                return comp["id"]

        return None
