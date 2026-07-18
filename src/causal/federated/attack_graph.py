"""
Causal Attack Graph — Concrete component-level attack path reasoning.

This module reconstructs the CONCRETE attack graph by composing
information from all sub-graphs. Unlike the Master DAG (which reasons
about aggregated risk), this produces actual attacker-movement paths:

    [Attacker] → [Entry Point] → [Exploit Vuln] → [Pivot] → [Target] → [Impact]

The attack graph answers: "HOW does an attacker get from outside to a data breach?"

Architecture:
    - Repo sub-graph provides: topology (who connects to whom)
    - SAST sub-graph provides: which components have vulns (exploitable steps)
    - DAST sub-graph provides: which entry points are confirmed reachable

    Combined: a full attack graph with concrete component names and
    verified exploit steps.

This is the graph that gets RENDERED visually alongside the DFD.
"""

import logging
from typing import Optional

import networkx as nx
from pydantic import BaseModel, Field

from src.causal.federated.base import CausalSubGraph

logger = logging.getLogger(__name__)


# ──── ATTACK GRAPH MODELS ────────────────────────────────────────────────────


class AttackNode(BaseModel):
    """A node in the concrete attack graph."""

    id: str
    name: str
    node_type: str  # "entry_point", "component", "vulnerability", "pivot", "target", "impact"
    layer_source: str  # Which sub-graph contributed this info
    severity: Optional[str] = None
    is_confirmed: bool = False  # DAST-confirmed?
    metadata: dict[str, str] = Field(default_factory=dict)


class AttackEdge(BaseModel):
    """A directed edge in the attack graph (attacker movement)."""

    source_id: str
    target_id: str
    label: str  # "exploits", "connects_to", "pivots_to", "causes", "accesses"
    edge_type: str  # "structural", "exploit", "lateral_movement", "impact"
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)
    is_confirmed: bool = False  # proven by DAST?
    crosses_boundary: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)


class ConcreteAttackPath(BaseModel):
    """A single end-to-end attack path through the system."""

    id: str
    path_nodes: list[str]  # Node IDs in order
    path_names: list[str]  # Human-readable names in order
    entry_point: str
    target: str
    impact: str
    score: float = Field(ge=0.0, le=1.0, default=0.0)
    length: int = 0
    crosses_trust_boundary: bool = False
    has_confirmed_steps: bool = False  # Any step confirmed by DAST?
    confirmed_step_count: int = 0
    exploit_chain: list[str] = []  # CWEs/vulns used in this path
    narrative: str = ""  # Human-readable description of the attack


class AttackGraphResult(BaseModel):
    """Complete attack graph output."""

    nodes: list[AttackNode] = []
    edges: list[AttackEdge] = []
    paths: list[ConcreteAttackPath] = []
    total_paths: int = 0
    confirmed_paths: int = 0  # Paths with at least one DAST-confirmed step
    max_path_score: float = 0.0
    entry_points: list[str] = []
    high_value_targets: list[str] = []
    critical_choke_points: list[str] = []  # Components on most paths (mediators)
    stats: dict[str, int] = Field(default_factory=dict)


# ──── ATTACK GRAPH BUILDER ───────────────────────────────────────────────────


class CausalAttackGraph:
    """
    Builds the concrete attack graph by composing sub-graph knowledge.

    This is NOT the master DAG. It's a separate analytical output that
    shows actual attacker-traversable paths through the system.

    Composition logic:
    1. Start with Repo topology (structural connections between components)
    2. Overlay SAST vulnerabilities (mark which components are exploitable)
    3. Overlay DAST confirmations (mark which entry points are proven reachable)
    4. Add impact nodes (what happens if attacker reaches target)
    5. Enumerate all paths from entry → exploit → target → impact
    6. Score and rank paths
    7. Identify choke points (components that block the most paths if secured)
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self._nodes: dict[str, AttackNode] = {}
        self._edges: list[AttackEdge] = []

    def build(
        self,
        repo_subgraph: CausalSubGraph,
        sast_subgraph: CausalSubGraph,
        dast_subgraph: CausalSubGraph,
        component_graph: dict,
    ) -> AttackGraphResult:
        """
        Build the concrete attack graph from all sub-graph data.

        Args:
            repo_subgraph: Built repository sub-graph
            sast_subgraph: Built SAST sub-graph
            dast_subgraph: Built DAST sub-graph
            component_graph: Raw component graph from analyzer

        Returns:
            AttackGraphResult with paths, nodes, edges, and analysis
        """
        logger.info("Building Concrete Causal Attack Graph...")

        # Step 1: Add structural topology from architecture
        self._add_architecture_topology(component_graph)

        # Step 2: Add entry points (external entities, public-facing)
        self._add_entry_points(component_graph)

        # Step 3: Overlay SAST vulnerabilities as exploitable steps
        self._add_sast_vulnerabilities(sast_subgraph)

        # Step 4: Overlay DAST confirmations
        self._add_dast_confirmations(dast_subgraph)

        # Step 5: Add impact nodes (consequences)
        self._add_impact_nodes(component_graph)

        # Step 6: Enumerate attack paths
        paths = self._enumerate_attack_paths()

        # Step 7: Identify choke points
        choke_points = self._identify_choke_points(paths)

        # Build result
        result = AttackGraphResult(
            nodes=list(self._nodes.values()),
            edges=self._edges,
            paths=paths,
            total_paths=len(paths),
            confirmed_paths=sum(1 for p in paths if p.has_confirmed_steps),
            max_path_score=max((p.score for p in paths), default=0.0),
            entry_points=[n.id for n in self._nodes.values() if n.node_type == "entry_point"],
            high_value_targets=[n.id for n in self._nodes.values() if n.node_type == "target"],
            critical_choke_points=choke_points,
            stats={
                "total_nodes": len(self._nodes),
                "total_edges": len(self._edges),
                "total_paths": len(paths),
                "confirmed_paths": sum(1 for p in paths if p.has_confirmed_steps),
                "entry_points": sum(1 for n in self._nodes.values() if n.node_type == "entry_point"),
                "exploitable_components": sum(
                    1 for n in self._nodes.values()
                    if n.node_type == "vulnerability"
                ),
            },
        )

        logger.info(
            f"Attack graph built: {len(self._nodes)} nodes, {len(self._edges)} edges, "
            f"{len(paths)} paths ({result.confirmed_paths} confirmed)"
        )

        return result

    # ──── GRAPH CONSTRUCTION ─────────────────────────────────────────────

    def _add_architecture_topology(self, component_graph: dict) -> None:
        """Add structural connections from the architecture."""
        components = component_graph.get("components", [])
        flows = component_graph.get("data_flows", [])

        # Add component nodes
        for comp in components:
            if comp.get("metadata", {}).get("type") == "metadata":
                continue

            comp_type = comp.get("type", "process")
            is_public = comp.get("is_public_facing", False)

            # Determine attack graph node type
            if comp_type == "external_entity":
                node_type = "entry_point"
            elif comp_type == "data_store":
                node_type = "target"  # Data stores are high-value targets
            else:
                node_type = "component"

            node = AttackNode(
                id=comp["id"],
                name=comp.get("name", comp["id"]),
                node_type=node_type,
                layer_source="repo",
                metadata={
                    "technology": comp.get("technology", ""),
                    "is_public": str(is_public),
                    "has_auth": str(comp.get("has_authentication", False)),
                },
            )
            self._nodes[node.id] = node
            self.graph.add_node(node.id, **node.model_dump())

        # Add structural edges (data flows = attacker movement paths)
        for flow in flows:
            source = flow.get("source_id", "")
            target = flow.get("target_id", "")

            if source not in self._nodes or target not in self._nodes:
                continue

            edge = AttackEdge(
                source_id=source,
                target_id=target,
                label=flow.get("protocol", "connects_to"),
                edge_type="structural",
                confidence=0.6,
                crosses_boundary=flow.get("crosses_trust_boundary", False),
                metadata={"protocol": flow.get("protocol", "")},
            )
            self._edges.append(edge)
            self.graph.add_edge(
                source, target,
                label=edge.label,
                edge_type="structural",
                weight=0.6,
                crosses_boundary=edge.crosses_boundary,
            )

    def _add_entry_points(self, component_graph: dict) -> None:
        """Mark or add attacker entry points."""
        # Add a generic "Attacker" node as the universal entry
        attacker_node = AttackNode(
            id="attacker",
            name="External Attacker",
            node_type="entry_point",
            layer_source="domain_knowledge",
        )
        self._nodes[attacker_node.id] = attacker_node
        self.graph.add_node(attacker_node.id)

        # Connect attacker to all external entities and public-facing services
        for node_id, node in self._nodes.items():
            if node_id == "attacker":
                continue
            is_public = node.metadata.get("is_public", "False") == "True"
            is_external = node.node_type == "entry_point"

            if is_public or is_external:
                edge = AttackEdge(
                    source_id="attacker",
                    target_id=node_id,
                    label="targets",
                    edge_type="entry",
                    confidence=0.8 if is_public else 0.5,
                    crosses_boundary=True,
                )
                self._edges.append(edge)
                self.graph.add_edge("attacker", node_id, edge_type="entry", weight=0.8)

    def _add_sast_vulnerabilities(self, sast_subgraph: CausalSubGraph) -> None:
        """Overlay SAST vulnerabilities onto components."""
        # Get vulnerability nodes from SAST sub-graph
        for node_id, attrs in sast_subgraph._nodes.items():
            if attrs.get("node_type") != "vulnerability":
                continue

            cwe = attrs.get("cwe", "")
            severity = attrs.get("severity", "Medium")
            file_path = attrs.get("file_path", "")

            vuln_node = AttackNode(
                id=f"vuln_{node_id}",
                name=f"{cwe or 'Vulnerability'} ({severity})",
                node_type="vulnerability",
                layer_source="sast",
                severity=severity,
                is_confirmed=False,  # SAST = unconfirmed
                metadata={"cwe": cwe, "file": file_path, "severity": severity},
            )
            self._nodes[vuln_node.id] = vuln_node
            self.graph.add_node(vuln_node.id, severity=severity)

            # Find which component this vuln affects (from SAST sub-graph edges)
            for successor in sast_subgraph.graph.successors(node_id):
                if successor.startswith("component_"):
                    # Extract the actual component ID
                    comp_id = sast_subgraph._nodes.get(successor, {}).get("component_id", "")
                    if comp_id and comp_id in self._nodes:
                        # Component → Vulnerability (attacker exploits the vuln to compromise component)
                        edge = AttackEdge(
                            source_id=comp_id,
                            target_id=vuln_node.id,
                            label=f"exploits {cwe}",
                            edge_type="exploit",
                            confidence=self._severity_to_confidence(severity),
                            metadata={"cwe": cwe},
                        )
                        self._edges.append(edge)
                        self.graph.add_edge(
                            comp_id, vuln_node.id,
                            edge_type="exploit",
                            weight=self._severity_to_confidence(severity),
                        )

                        # Vulnerability → compromised state (enables further movement)
                        # Connect vuln to all downstream components from the affected one
                        for downstream in self.graph.successors(comp_id):
                            if downstream != vuln_node.id and downstream in self._nodes:
                                pivot_edge = AttackEdge(
                                    source_id=vuln_node.id,
                                    target_id=downstream,
                                    label="enables access to",
                                    edge_type="lateral_movement",
                                    confidence=self._severity_to_confidence(severity) * 0.8,
                                )
                                self._edges.append(pivot_edge)
                                self.graph.add_edge(
                                    vuln_node.id, downstream,
                                    edge_type="lateral_movement",
                                    weight=self._severity_to_confidence(severity) * 0.8,
                                )

    def _add_dast_confirmations(self, dast_subgraph: CausalSubGraph) -> None:
        """Mark DAST-confirmed vulnerabilities and entry points."""
        for node_id, attrs in dast_subgraph._nodes.items():
            if attrs.get("node_type") != "confirmed_vulnerability":
                continue

            url = attrs.get("url", "")
            severity = attrs.get("severity", "Medium")
            category = attrs.get("category", "")

            # Find matching attack graph nodes and mark as confirmed
            # DAST confirms entry points are reachable
            for ag_node_id, ag_node in self._nodes.items():
                if ag_node.metadata.get("is_public") == "True":
                    ag_node.is_confirmed = True

            # Also boost confidence of related vulnerability edges
            for edge in self._edges:
                if edge.edge_type == "exploit":
                    # If DAST found something in the same category, boost confidence
                    edge_cwe = edge.metadata.get("cwe", "")
                    if self._cwe_matches_dast_category(edge_cwe, category):
                        edge.is_confirmed = True
                        edge.confidence = min(1.0, edge.confidence + 0.2)

    def _add_impact_nodes(self, component_graph: dict) -> None:
        """Add impact/consequence nodes that attacks lead to."""
        impacts = {
            "impact-data-breach": "Data Breach (Confidentiality Loss)",
            "impact-data-tampering": "Data Tampering (Integrity Loss)",
            "impact-service-disruption": "Service Disruption (Availability Loss)",
            "impact-privilege-escalation": "Privilege Escalation",
            "impact-compliance-violation": "Compliance Violation",
        }

        for impact_id, impact_name in impacts.items():
            node = AttackNode(
                id=impact_id,
                name=impact_name,
                node_type="impact",
                layer_source="domain_knowledge",
            )
            self._nodes[impact_id] = node
            self.graph.add_node(impact_id, node_type="impact")

        # Connect data stores → data breach
        for node_id, node in self._nodes.items():
            if node.node_type == "target":  # Data stores
                edge = AttackEdge(
                    source_id=node_id,
                    target_id="impact-data-breach",
                    label="compromised leads to",
                    edge_type="impact",
                    confidence=0.85,
                )
                self._edges.append(edge)
                self.graph.add_edge(node_id, "impact-data-breach", edge_type="impact", weight=0.85)

                edge2 = AttackEdge(
                    source_id=node_id,
                    target_id="impact-data-tampering",
                    label="compromised leads to",
                    edge_type="impact",
                    confidence=0.7,
                )
                self._edges.append(edge2)
                self.graph.add_edge(node_id, "impact-data-tampering", edge_type="impact", weight=0.7)

        # Connect vulnerabilities → privilege escalation
        for node_id, node in self._nodes.items():
            if node.node_type == "vulnerability":
                cwe = node.metadata.get("cwe", "")
                if cwe in {"CWE-89", "CWE-78", "CWE-269", "CWE-287"}:
                    edge = AttackEdge(
                        source_id=node_id,
                        target_id="impact-privilege-escalation",
                        label="exploited leads to",
                        edge_type="impact",
                        confidence=0.7,
                    )
                    self._edges.append(edge)
                    self.graph.add_edge(
                        node_id, "impact-privilege-escalation",
                        edge_type="impact", weight=0.7,
                    )

    # ──── PATH ENUMERATION ───────────────────────────────────────────────

    def _enumerate_attack_paths(self) -> list[ConcreteAttackPath]:
        """Find all concrete attack paths from entry to impact."""
        paths = []
        path_id = 0

        # Entry: "attacker" node
        # Target: "impact-*" nodes
        impact_nodes = [n_id for n_id, n in self._nodes.items() if n.node_type == "impact"]

        if "attacker" not in self.graph:
            return paths

        for impact_id in impact_nodes:
            if not self.graph.has_node(impact_id):
                continue

            try:
                all_paths = list(nx.all_simple_paths(
                    self.graph, "attacker", impact_id, cutoff=8
                ))

                for path in all_paths:
                    path_id += 1
                    concrete_path = self._build_concrete_path(path, impact_id, path_id)
                    if concrete_path:
                        paths.append(concrete_path)

            except nx.NetworkXError:
                continue

        # Sort by score (highest risk first)
        paths.sort(key=lambda p: p.score, reverse=True)

        # Limit to top 50 paths
        return paths[:50]

    def _build_concrete_path(
        self, path: list[str], impact_id: str, path_id: int
    ) -> Optional[ConcreteAttackPath]:
        """Build a ConcreteAttackPath from a raw node list."""
        if len(path) < 3:  # Need at least: attacker → something → impact
            return None

        path_names = []
        exploit_chain = []
        has_confirmed = False
        confirmed_count = 0
        crosses_boundary = False

        for node_id in path:
            node = self._nodes.get(node_id)
            if node:
                # Use the human-readable name from the AttackNode
                path_names.append(node.name)
                if node.node_type == "vulnerability":
                    cwe = node.metadata.get("cwe", "")
                    if cwe:
                        exploit_chain.append(cwe)
                if node.is_confirmed:
                    has_confirmed = True
                    confirmed_count += 1
            else:
                # Fallback: clean up the raw node ID to be readable
                clean_name = node_id.replace("process-", "").replace("data_store-", "")
                clean_name = clean_name.replace("ext-", "").replace("vuln_", "Vuln: ")
                clean_name = clean_name.replace("-", " ").replace("_", " ").title()
                path_names.append(clean_name)

        # Check boundary crossings
        for i in range(len(path) - 1):
            edge_data = self.graph.get_edge_data(path[i], path[i + 1], default={})
            if edge_data.get("crosses_boundary"):
                crosses_boundary = True

        # Score the path
        score = self._score_attack_path(path, has_confirmed, crosses_boundary)

        # Generate narrative
        narrative = self._generate_path_narrative(path, path_names, exploit_chain)

        return ConcreteAttackPath(
            id=f"attack-path-{path_id:03d}",
            path_nodes=path,
            path_names=path_names,
            entry_point=path[0],
            target=path[-2] if len(path) > 2 else path[-1],  # Component before impact
            impact=impact_id,
            score=score,
            length=len(path),
            crosses_trust_boundary=crosses_boundary,
            has_confirmed_steps=has_confirmed,
            confirmed_step_count=confirmed_count,
            exploit_chain=exploit_chain,
            narrative=narrative,
        )

    def _score_attack_path(
        self, path: list[str], has_confirmed: bool, crosses_boundary: bool
    ) -> float:
        """Score an attack path based on edge weights and properties."""
        if len(path) < 2:
            return 0.0

        # Base score: average edge weight
        total_weight = 0.0
        for i in range(len(path) - 1):
            edge_data = self.graph.get_edge_data(path[i], path[i + 1], default={})
            total_weight += edge_data.get("weight", 0.5)

        avg_weight = total_weight / (len(path) - 1)

        # Shorter paths are more dangerous (fewer steps needed)
        length_factor = 1.0 / (len(path) * 0.3)

        # DAST confirmation boosts score significantly
        confirmation_boost = 1.4 if has_confirmed else 1.0

        # Boundary crossing increases severity
        boundary_boost = 1.2 if crosses_boundary else 1.0

        score = avg_weight * length_factor * confirmation_boost * boundary_boost
        return min(1.0, score)

    def _generate_path_narrative(
        self, path: list[str], names: list[str], exploits: list[str]
    ) -> str:
        """Generate a human-readable narrative for an attack path."""
        if len(names) < 3:
            return " → ".join(names)

        parts = []
        parts.append(f"Attacker targets {names[1]}")

        for i in range(2, len(names) - 1):
            node = self._nodes.get(path[i])
            if node and node.node_type == "vulnerability":
                parts.append(f"exploits {node.metadata.get('cwe', 'vulnerability')}")
            elif node and node.node_type == "target":
                parts.append(f"accesses {names[i]}")
            else:
                parts.append(f"moves to {names[i]}")

        parts.append(f"resulting in {names[-1]}")

        return ", ".join(parts) + "."

    # ──── CHOKE POINT ANALYSIS ───────────────────────────────────────────

    def _identify_choke_points(self, paths: list[ConcreteAttackPath]) -> list[str]:
        """
        Find choke points — components that appear on the most attack paths.

        These are MEDIATORS in causal terms: securing them blocks the most attacks.
        """
        frequency: dict[str, int] = {}

        for path in paths:
            # Exclude entry point (attacker) and impact from choke point analysis
            for node_id in path.path_nodes[1:-1]:
                node = self._nodes.get(node_id)
                if node and node.node_type in ("component", "target"):
                    frequency[node_id] = frequency.get(node_id, 0) + 1

        # Sort by frequency (most paths through = most critical choke point)
        sorted_chokes = sorted(frequency.items(), key=lambda x: x[1], reverse=True)

        return [node_id for node_id, _ in sorted_chokes[:5]]

    # ──── HELPERS ────────────────────────────────────────────────────────

    def _severity_to_confidence(self, severity: str) -> float:
        """Map severity to exploit confidence."""
        return {"Critical": 0.95, "High": 0.8, "Medium": 0.6, "Low": 0.4}.get(severity, 0.5)

    def _cwe_matches_dast_category(self, cwe: str, dast_category: str) -> bool:
        """Check if a CWE matches a DAST finding category."""
        cwe_category_map = {
            "CWE-89": "injection",
            "CWE-79": "xss",
            "CWE-78": "injection",
            "CWE-287": "authentication",
            "CWE-306": "authentication",
            "CWE-311": "cryptography",
            "CWE-319": "cryptography",
        }
        return cwe_category_map.get(cwe, "") == dast_category
