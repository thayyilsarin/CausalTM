"""
Repo Sub-DAG v2 — Extracts STRUCTURAL DESIGN posture from repository.

This answers: "What is the architectural design?"
  - What components exist and how are they connected?
  - Where are trust boundaries?
  - How sensitive is the data flowing through?
  - What defense layers exist?

Edge nodes represent DESIGN STATE:
  - topology_exposure: How much of the system is externally reachable?
  - data_sensitivity: How sensitive is the data the system handles?
  - trust_boundary_integrity: Are boundaries properly defined and controlled?
  - defense_depth: How many layers of defense exist?
"""

import logging

import networkx as nx

from src.causal.v2.base import ArchitecturalEdgeNode, ArchitecturalSubDAG

logger = logging.getLogger(__name__)


class RepoSubDAG(ArchitecturalSubDAG):
    """
    Extracts architectural structure and security design from repository.

    Unlike SAST/DAST which find problems, Repo reveals the DESIGN ITSELF.
    It doesn't need vulnerabilities to identify threats — the architecture
    alone is sufficient to determine where STRIDE threats exist.
    """

    @property
    def layer_name(self) -> str:
        return "repo"

    def build(self, data: dict) -> None:
        """
        Build sub-DAG from component graph.

        Args:
            data: {"component_graph": dict}
        """
        component_graph = data.get("component_graph", {})
        components = [
            c for c in component_graph.get("components", [])
            if c.get("metadata", {}).get("type") != "metadata"
        ]
        flows = component_graph.get("data_flows", [])
        boundaries = component_graph.get("trust_boundaries", [])

        logger.info(f"[Repo v2] Building structural posture from {len(components)} components, {len(flows)} flows")

        self._components = components
        self._flows = flows
        self._boundaries = boundaries

        # Register each architectural fact as a base variable
        for comp in components:
            var_id = f"component_{comp['id']}"
            self._add_base_variable(
                var_id,
                name=comp.get("name", ""),
                type=comp.get("type", "process"),
                is_public=comp.get("is_public_facing", False),
                has_auth=comp.get("has_authentication", False),
                has_encryption=comp.get("has_encryption", False),
                description=f"Component: {comp.get('name', '')} ({comp.get('type', '')})",
            )

        for flow in flows:
            var_id = f"flow_{flow['id']}"
            self._add_base_variable(
                var_id,
                source=flow.get("source_id", ""),
                target=flow.get("target_id", ""),
                encrypted=flow.get("is_encrypted", False),
                authenticated=flow.get("is_authenticated", False),
                crosses_boundary=flow.get("crosses_trust_boundary", False),
                sensitivity=flow.get("data_sensitivity", []),
                description=f"Flow: {flow.get('source_id', '')} → {flow.get('target_id', '')}",
            )

        self._built = True

    def compute_edge_nodes(self) -> list[ArchitecturalEdgeNode]:
        """Compute structural design posture edge nodes."""
        edge_nodes = []
        total_components = max(len(self._components), 1)
        total_flows = max(len(self._flows), 1)

        # 1. Topology Exposure (how much is externally reachable)
        # Higher = MORE exposed (inverse of protection)
        public_count = sum(1 for c in self._components if c.get("is_public_facing"))
        exposure = public_count / total_components
        public_vars = [
            f"component_{c['id']}" for c in self._components if c.get("is_public_facing")
        ]
        edge_nodes.append(ArchitecturalEdgeNode(
            id="repo.topology_exposure",
            name="Topology Exposure",
            layer=self.layer_name,
            value=exposure,
            causal_strength=0.8,
            stride_relevance=["Spoofing", "Denial of Service", "Information Disclosure"],
            base_variables=public_vars,
            evidence=[
                f"Public-facing: {public_count}/{total_components} ({exposure:.0%})",
            ],
            observed=True,
        ))

        # 2. Data Sensitivity (how sensitive is the data in the system)
        # Higher = MORE sensitive (higher risk if breached)
        sensitivity_weights = {
            "credentials": 1.0, "secret": 1.0, "financial": 0.9,
            "pii": 0.8, "confidential": 0.7, "internal": 0.3,
        }
        max_sensitivity = 0.0
        sensitive_flows = []
        for flow in self._flows:
            for sens in flow.get("data_sensitivity", []):
                s_lower = sens.lower() if isinstance(sens, str) else str(sens).lower()
                weight = sensitivity_weights.get(s_lower, 0.3)
                if weight > max_sensitivity:
                    max_sensitivity = weight
                if weight > 0.5:
                    sensitive_flows.append(f"flow_{flow['id']}")

        edge_nodes.append(ArchitecturalEdgeNode(
            id="repo.data_sensitivity",
            name="Data Sensitivity Level",
            layer=self.layer_name,
            value=max_sensitivity,
            causal_strength=0.75,
            stride_relevance=["Information Disclosure", "Tampering"],
            base_variables=list(set(sensitive_flows)),
            evidence=[
                f"Highest sensitivity: {max_sensitivity:.0%}",
                f"Sensitive data flows: {len(sensitive_flows)}",
            ],
            observed=True,
        ))

        # 3. Trust Boundary Integrity (are boundaries properly controlled?)
        # Posture = what fraction of cross-boundary flows have controls
        cross_boundary_flows = [f for f in self._flows if f.get("crosses_trust_boundary")]
        controlled_crossings = sum(
            1 for f in cross_boundary_flows
            if f.get("is_encrypted") or f.get("is_authenticated")
        )

        # If no boundaries defined at all (sparse detection), posture should be LOW
        # because we can't confirm boundaries exist
        if not self._boundaries:
            boundary_integrity = 0.3  # Unknown = assume weak
        elif not cross_boundary_flows:
            boundary_integrity = 0.7  # Boundaries exist but no flows cross them = partial
        else:
            boundary_integrity = controlled_crossings / len(cross_boundary_flows)

        uncontrolled_vars = [
            f"flow_{f['id']}" for f in cross_boundary_flows
            if not f.get("is_encrypted") and not f.get("is_authenticated")
        ]
        edge_nodes.append(ArchitecturalEdgeNode(
            id="repo.trust_boundary_integrity",
            name="Trust Boundary Integrity",
            layer=self.layer_name,
            value=boundary_integrity,
            causal_strength=0.85,
            stride_relevance=["Spoofing", "Tampering", "Information Disclosure", "Elevation of Privilege"],
            base_variables=uncontrolled_vars,
            evidence=[
                f"Cross-boundary flows: {len(cross_boundary_flows)}",
                f"Controlled: {controlled_crossings}/{len(cross_boundary_flows)}",
                f"Integrity: {boundary_integrity:.0%}",
            ],
            observed=True,
        ))

        # 4. Defense Depth (layered defenses)
        # Factors: auth on services, encryption on flows, multiple boundaries, indirection
        scores = []

        # Auth coverage across components
        auth_count = sum(1 for c in self._components if c.get("has_authentication"))
        scores.append(auth_count / total_components)

        # Encryption on sensitive flows
        encrypted_sensitive = sum(
            1 for f in self._flows
            if f.get("is_encrypted") and f.get("data_sensitivity")
        )
        sensitive_count = sum(1 for f in self._flows if f.get("data_sensitivity"))
        scores.append(encrypted_sensitive / max(sensitive_count, 1))

        # Multiple trust boundaries (more = better segmentation)
        scores.append(min(1.0, len(self._boundaries) / 3.0))

        defense_depth = sum(scores) / max(len(scores), 1)

        edge_nodes.append(ArchitecturalEdgeNode(
            id="repo.defense_depth",
            name="Defense-in-Depth",
            layer=self.layer_name,
            value=defense_depth,
            causal_strength=0.7,
            stride_relevance=["Spoofing", "Tampering", "Denial of Service", "Elevation of Privilege"],
            base_variables=[],  # Structural — not individual findings
            evidence=[
                f"Auth coverage: {auth_count}/{total_components}",
                f"Encrypted sensitive flows: {encrypted_sensitive}/{sensitive_count}",
                f"Trust boundaries: {len(self._boundaries)}",
                f"Defense depth: {defense_depth:.0%}",
            ],
            observed=True,
        ))

        # Register edge nodes in graph AND connect base variables
        for en in edge_nodes:
            self.graph.add_node(en.id, node_type="edge_node")
            for var_id in en.base_variables:
                if var_id in self._base_variables:
                    self._add_edge_node_connection(var_id, en.id, weight=0.7)

        # Ensure ALL component base variables connect to at least one edge node
        # (so the graph is never empty for the renderer)
        for var_id, var_data in self._base_variables.items():
            # Check if this base var is already connected
            if self.graph.out_degree(var_id) == 0:
                # Connect to the most relevant edge node
                if var_data.get("is_public"):
                    self._add_edge_node_connection(var_id, "repo.topology_exposure", weight=0.5)
                elif var_data.get("type") == "data_store":
                    self._add_edge_node_connection(var_id, "repo.data_sensitivity", weight=0.5)
                elif var_data.get("crosses_boundary"):
                    self._add_edge_node_connection(var_id, "repo.trust_boundary_integrity", weight=0.5)
                else:
                    # Default: connect to defense_depth
                    self._add_edge_node_connection(var_id, "repo.defense_depth", weight=0.3)

        self._edge_nodes = {en.id: en for en in edge_nodes}
        return edge_nodes
