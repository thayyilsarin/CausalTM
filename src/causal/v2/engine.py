"""
CausalTM v2 Engine — Orchestrator for the complete 5-layer stack.

Layer 5: STRIDE (cream) → Layer 4: Master DAG → Layer 3: Sub-DAGs → Layer 2: Ingestors → Layer 1: Inputs
"""

import logging
from typing import Optional

from pydantic import BaseModel, Field

from src.causal.v2.sast_subdag import SASTSubDAG
from src.causal.v2.dast_subdag import DASTSubDAG
from src.causal.v2.repo_subdag import RepoSubDAG
from src.causal.v2.master_dag import MasterDAGV2, WhatIfResult
from src.causal.v2.stride_layer import StrideLayerV2, StrideThreatModelV2

logger = logging.getLogger(__name__)


class CausalTMv2Result(BaseModel):
    """Complete output from CausalTM v2 engine."""

    # STRIDE Threat Model (the cream layer output)
    threat_model: Optional[StrideThreatModelV2] = None

    # Remediation roadmap
    roadmap: list[dict] = Field(default_factory=list)

    # Architecture posture scores
    posture: dict[str, float] = Field(default_factory=dict)

    # Layer contribution summary
    layer_summary: dict[str, dict] = Field(default_factory=dict)

    # Overall risk (0 = secure, 1 = fully threatened)
    overall_risk: float = 0.0
    risk_rating: str = ""


class CausalTMv2Engine:
    """
    CausalTM v2 Engine — complete 5-layer stack orchestrator.

    Usage:
        engine = CausalTMv2Engine()
        engine.build(component_graph, sast_findings, dast_findings)
        result = engine.analyze()
        roadmap = engine.roadmap_to_zero()
        what_if = engine.what_if("sast", "sast.auth_posture", 1.0)
    """

    def __init__(self):
        self.sast_subdag = SASTSubDAG()
        self.dast_subdag = DASTSubDAG()
        self.repo_subdag = RepoSubDAG()
        self.master_dag = MasterDAGV2()
        self.stride_layer = StrideLayerV2()
        self._component_graph: Optional[dict] = None
        self._result: Optional[CausalTMv2Result] = None

    def build(
        self,
        component_graph: dict,
        sast_findings: list[dict],
        dast_findings: list[dict],
    ) -> None:
        """
        Build the complete 5-layer model.

        Args:
            component_graph: Architecture from repo analysis
            sast_findings: Normalized SAST findings (list of dicts)
            dast_findings: Normalized DAST findings (list of dicts)
        """
        self._component_graph = component_graph

        logger.info("=" * 60)
        logger.info("CausalTM v2 Engine: Building 5-layer model")
        logger.info("=" * 60)

        # Pre-process: Ensure component graph has minimum required structure for v2
        component_graph = self._ensure_minimum_architecture(component_graph)
        self._component_graph = component_graph

        # Layer 3: Build sub-DAGs
        logger.info("[Layer 3] Building sub-DAGs...")

        self.sast_subdag.build({
            "findings": sast_findings,
            "component_graph": component_graph,
        })

        self.dast_subdag.build({
            "findings": dast_findings,
            "component_graph": component_graph,
        })

        self.repo_subdag.build({
            "component_graph": component_graph,
        })

        # Extract edge nodes from each sub-DAG
        sast_edges = self.sast_subdag.get_edge_nodes()
        dast_edges = self.dast_subdag.get_edge_nodes()
        repo_edges = self.repo_subdag.get_edge_nodes()
        all_edges = sast_edges + dast_edges + repo_edges

        logger.info(f"  SAST edge nodes: {len(sast_edges)}")
        logger.info(f"  DAST edge nodes: {len(dast_edges)}")
        logger.info(f"  Repo edge nodes: {len(repo_edges)}")
        for en in all_edges:
            observed_str = "" if en.observed else " (not observed)"
            logger.info(f"    {en.id}: {en.value:.2f}{observed_str}")

        # Layer 4: Build Master DAG
        logger.info("[Layer 4] Building Master DAG with cross-layer rules...")
        self.master_dag.build(all_edges)

        logger.info("=" * 60)
        logger.info("CausalTM v2: Model built successfully")
        logger.info("=" * 60)

    def analyze(self) -> CausalTMv2Result:
        """
        Run the complete analysis: Master DAG reasoning → STRIDE evaluation.

        Returns:
            CausalTMv2Result with threat model, posture, and risk
        """
        logger.info("[Analysis] Running Master DAG + STRIDE evaluation...")

        # Layer 4: Master DAG analysis
        master_result = self.master_dag.analyze()

        # Layer 5: STRIDE cream layer
        threat_model = self.stride_layer.evaluate(
            master_result,
            self._component_graph or {},
            sub_dags={"sast": self.sast_subdag, "dast": self.dast_subdag, "repo": self.repo_subdag},
        )

        # Build result
        result = CausalTMv2Result(
            threat_model=threat_model,
            posture=master_result.architecture_scores,
            overall_risk=threat_model.overall_risk,
            risk_rating=self._risk_to_rating(threat_model.overall_risk),
            layer_summary={
                "sast": {
                    "edge_nodes": len(self.sast_subdag.get_edge_nodes()),
                    "base_variables": len(self.sast_subdag._base_variables),
                    "posture_values": {
                        en.id: en.value for en in self.sast_subdag.get_edge_nodes()
                    },
                },
                "dast": {
                    "edge_nodes": len(self.dast_subdag.get_edge_nodes()),
                    "base_variables": len(self.dast_subdag._base_variables),
                    "observed": any(en.observed for en in self.dast_subdag.get_edge_nodes()),
                    "posture_values": {
                        en.id: en.value for en in self.dast_subdag.get_edge_nodes()
                    },
                },
                "repo": {
                    "edge_nodes": len(self.repo_subdag.get_edge_nodes()),
                    "base_variables": len(self.repo_subdag._base_variables),
                    "posture_values": {
                        en.id: en.value for en in self.repo_subdag.get_edge_nodes()
                    },
                },
            },
        )

        self._result = result

        logger.info(
            f"[Result] Overall risk: {result.overall_risk:.3f} ({result.risk_rating}) | "
            f"Threats: {threat_model.total_threats} | "
            f"STRIDE posture: {threat_model.posture_per_category}"
        )

        return result

    def roadmap_to_zero(self) -> list[dict]:
        """
        Generate the sequenced remediation roadmap to 0% risk.

        Returns:
            Ordered list of fix steps with cross-layer effects
        """
        logger.info("[Roadmap] Computing optimal fix sequence to 0% risk...")

        sub_dags = {
            "sast": self.sast_subdag,
            "dast": self.dast_subdag,
            "repo": self.repo_subdag,
        }

        roadmap = self.master_dag.roadmap_to_zero(sub_dags)

        logger.info(f"[Roadmap] Generated {len(roadmap)} steps to reach near-zero risk")
        for step in roadmap:
            logger.info(
                f"  Step {step['step']}: Fix {step['name']} ({step['layer']} layer) "
                f"| {step['current_value']:.2f} → {step['target_value']:.2f} "
                f"| STRIDE improvement: {step['stride_improvement']:.3f}"
            )

        if self._result:
            self._result.roadmap = roadmap

        return roadmap

    def what_if(self, layer: str, edge_node_id: str, new_value: float, description: str = "") -> WhatIfResult:
        """
        Run a what-if analysis: "If I change this posture, what happens everywhere?"

        Args:
            layer: Which layer
            edge_node_id: Which edge node to modify
            new_value: Target value
            description: Human description

        Returns:
            WhatIfResult with before/after states and cross-layer effects
        """
        return self.master_dag.what_if(layer, edge_node_id, new_value, description)

    def get_dfd_model(self) -> dict:
        """
        Generate a DFD-compatible model directly from the enriched component graph.
        
        This bypasses Pydantic ComponentGraph validation which may reject
        enriched data formats. Returns a dict ready for Graphviz rendering.
        
        This is the GENERIC method — any caller can use it instead of
        manually building DFD models or relying on DFDBuilder.
        """
        graph = self._component_graph or {}
        components = [c for c in graph.get("components", []) if c.get("metadata", {}).get("type") != "metadata"]
        elem_type_map = {"process": "process", "data_store": "data_store", "external_entity": "external_entity"}

        elements = []
        for c in components:
            elements.append({
                "id": c["id"],
                "name": c.get("name", c["id"]),
                "element_type": elem_type_map.get(c.get("type"), "process"),
                "description": c.get("technology", ""),
                "technology": c.get("technology"),
                "trust_level": c.get("trust_level"),
                "is_public_facing": c.get("is_public_facing", False),
                "has_authentication": c.get("has_authentication", False),
                "has_encryption": c.get("has_encryption", False),
                "metadata": c.get("metadata", {}),
                "layer": 0,
                "group": None,
            })

        flows = []
        for f in graph.get("data_flows", []):
            flows.append({
                "id": f["id"],
                "source_id": f["source_id"],
                "target_id": f["target_id"],
                "label": f.get("description", f.get("protocol", "data")),
                "protocol": f.get("protocol"),
                "data_types": f.get("data_types", []),
                "data_sensitivity": f.get("data_sensitivity", []),
                "is_encrypted": f.get("is_encrypted", False),
                "is_authenticated": f.get("is_authenticated", False),
                "crosses_trust_boundary": f.get("crosses_trust_boundary", False),
                "is_bidirectional": False,
            })

        boundaries = []
        for b in graph.get("trust_boundaries", []):
            boundaries.append({
                "id": b["id"],
                "name": b["name"],
                "trust_level": b.get("trust_level", "internal"),
                "element_ids": b.get("component_ids", []),
                "color": "#cccccc",
            })

        project_name = graph.get("metadata", {}).get("project_name", "System")
        return {
            "title": f"{project_name} - Data Flow Diagram",
            "level": "level_0",
            "description": f"DFD with {len(elements)} elements and {len(flows)} data flows",
            "elements": elements,
            "data_flows": flows,
            "boundaries": boundaries,
            "metadata": graph.get("metadata", {}),
        }

    def get_attack_paths(self, max_paths: int = 10, max_depth: int = 8) -> list[dict]:
        """
        Compute concrete attack paths through the component graph.

        Uses BFS/DFS graph traversal from external entry points (external entities
        and public-facing components) to high-value targets (data stores with
        sensitive data). Paths are scored by:
          - Length (shorter = more exploitable)
          - Boundary crossings (more crossings = more severe if unprotected)
          - Encryption gaps (unencrypted flows increase score)
          - Authentication gaps (unauthenticated flows increase score)
          - Data sensitivity (paths reaching sensitive data score higher)

        Returns:
            Sorted list of attack path dicts ready for report rendering:
            [{"node_names": [...], "node_ids": [...], "score": float,
              "crosses_trust_boundary": bool, "boundary_crossings": int,
              "unencrypted_hops": int, "unauthenticated_hops": int,
              "target_sensitivity": [...], "description": str}]
        """
        graph = self._component_graph or {}
        components = [c for c in graph.get("components", []) if c.get("metadata", {}).get("type") != "metadata"]
        flows = graph.get("data_flows", [])

        if not components or not flows:
            return []

        # Build lookup maps
        comp_by_id = {c["id"]: c for c in components}

        # Build adjacency list from data flows (directed graph)
        adjacency: dict[str, list[dict]] = {c["id"]: [] for c in components}
        for flow in flows:
            src = flow.get("source_id")
            tgt = flow.get("target_id")
            if src in adjacency and tgt in comp_by_id:
                adjacency[src].append({
                    "target": tgt,
                    "flow": flow,
                })
            # Add reverse edge for bidirectional flows
            if flow.get("is_bidirectional") and tgt in adjacency and src in comp_by_id:
                adjacency[tgt].append({
                    "target": src,
                    "flow": flow,
                })

        # Identify entry points: external entities + public-facing components
        entry_points = [
            c["id"] for c in components
            if c.get("type") == "external_entity" or c.get("is_public_facing", False)
        ]

        # Identify high-value targets: data stores (especially with sensitive data)
        high_value_targets = set()
        for c in components:
            if c.get("type") == "data_store":
                high_value_targets.add(c["id"])

        # Also mark processes that handle sensitive data as intermediate targets
        sensitive_flows = [f for f in flows if any(
            s in (f.get("data_sensitivity") or [])
            for s in ["credentials", "pii", "confidential", "secret"]
        )]
        sensitive_targets = set()
        for f in sensitive_flows:
            sensitive_targets.add(f.get("target_id", ""))
            sensitive_targets.add(f.get("source_id", ""))

        if not entry_points or not high_value_targets:
            # Can't form meaningful paths without both ends
            return []

        # DFS to find all paths from entry points to high-value targets
        all_paths: list[dict] = []
        max_total_paths = max_paths * 5  # Limit total exploration

        def dfs(current: str, target_set: set, visited: set, path_nodes: list, path_flows: list):
            if len(all_paths) >= max_total_paths:
                return
            if len(path_nodes) > max_depth:
                return
            if current in target_set and len(path_nodes) > 1:
                # Found a valid path — score it
                scored = self._score_attack_path(path_nodes, path_flows, comp_by_id)
                all_paths.append(scored)
                # Don't return — keep exploring through data stores to other targets
                if len(path_nodes) > max_depth - 2:
                    return

            for edge in adjacency.get(current, []):
                if len(all_paths) >= max_total_paths:
                    return
                next_node = edge["target"]
                if next_node not in visited:
                    visited.add(next_node)
                    path_nodes.append(next_node)
                    path_flows.append(edge["flow"])
                    dfs(next_node, target_set, visited, path_nodes, path_flows)
                    path_flows.pop()
                    path_nodes.pop()
                    visited.remove(next_node)

        for entry in entry_points:
            visited = {entry}
            dfs(entry, high_value_targets, visited, [entry], [])

        # Also find paths to sensitive intermediate nodes (not just data stores)
        for entry in entry_points:
            intermediate_targets = sensitive_targets - high_value_targets - {entry}
            if intermediate_targets:
                visited = {entry}
                dfs(entry, intermediate_targets, visited, [entry], [])

        # Deduplicate (same node sequence)
        seen_sequences = set()
        unique_paths = []
        for p in all_paths:
            key = tuple(p["node_ids"])
            if key not in seen_sequences:
                seen_sequences.add(key)
                unique_paths.append(p)

        # Sort by score (highest risk first) and limit
        unique_paths.sort(key=lambda p: p["score"], reverse=True)
        return unique_paths[:max_paths]

    def _score_attack_path(
        self, path_nodes: list[str], path_flows: list[dict], comp_by_id: dict
    ) -> dict:
        """
        Score an individual attack path.

        Scoring formula:
            score = (boundary_crossings * 0.3 + unencrypted_hops * 0.25 +
                     unauthenticated_hops * 0.25 + sensitivity_factor * 0.2) *
                    length_factor

        Where length_factor = 1.0 / sqrt(len) — shorter paths are more exploitable.
        """
        import math

        boundary_crossings = 0
        unencrypted_hops = 0
        unauthenticated_hops = 0
        max_sensitivity = 0.0

        sensitivity_weights = {
            "public": 0.1, "internal": 0.3,
            "confidential": 0.7, "credentials": 1.0,
            "pii": 0.9, "secret": 1.0, "financial": 0.8,
        }

        for flow in path_flows:
            if flow.get("crosses_trust_boundary"):
                boundary_crossings += 1
            if not flow.get("is_encrypted"):
                unencrypted_hops += 1
            if not flow.get("is_authenticated"):
                unauthenticated_hops += 1
            for sens in (flow.get("data_sensitivity") or []):
                max_sensitivity = max(max_sensitivity, sensitivity_weights.get(sens, 0.3))

        num_hops = len(path_flows) if path_flows else 1
        # Shorter paths are easier to exploit
        length_factor = 1.0 / math.sqrt(num_hops)

        # Normalize crossing/encryption/auth scores by number of hops
        crossing_score = min(1.0, boundary_crossings / max(num_hops, 1))
        encrypt_score = min(1.0, unencrypted_hops / max(num_hops, 1))
        auth_score = min(1.0, unauthenticated_hops / max(num_hops, 1))

        raw_score = (
            crossing_score * 0.3
            + encrypt_score * 0.25
            + auth_score * 0.25
            + max_sensitivity * 0.2
        )

        final_score = round(raw_score * length_factor, 3)

        # Build human-readable path
        node_names = [comp_by_id[nid].get("name", nid) for nid in path_nodes if nid in comp_by_id]
        node_ids = list(path_nodes)

        # Build description
        target_name = node_names[-1] if node_names else "Unknown"
        entry_name = node_names[0] if node_names else "Unknown"
        description = f"{entry_name} → {'→ '.join(node_names[1:])} (Score: {final_score:.2f})"

        # Collect target sensitivity
        target_sensitivity = []
        if path_flows:
            last_flow = path_flows[-1]
            target_sensitivity = last_flow.get("data_sensitivity", [])

        return {
            "node_names": node_names,
            "node_ids": node_ids,
            "score": final_score,
            "crosses_trust_boundary": boundary_crossings > 0,
            "boundary_crossings": boundary_crossings,
            "unencrypted_hops": unencrypted_hops,
            "unauthenticated_hops": unauthenticated_hops,
            "target_sensitivity": target_sensitivity,
            "hops": num_hops,
            "description": description,
            "has_confirmed_steps": False,  # Will be enriched by STRIDE layer if DAST confirms
        }

    def _risk_to_rating(self, risk: float) -> str:
        """Convert numeric risk to rating."""
        if risk >= 0.7:
            return "Critical"
        elif risk >= 0.5:
            return "High"
        elif risk >= 0.3:
            return "Medium"
        elif risk >= 0.1:
            return "Low"
        return "Minimal"

    def _ensure_minimum_architecture(self, graph: dict) -> dict:
        """
        Ensure the component graph has minimum structure for v2 posture calculation.
        
        Auto-detection may produce sparse results. v2 needs:
        - At least one public-facing component
        - At least one trust boundary
        - Data flows with sensitivity and boundary crossing info
        - Components with security property flags

        This method enriches IN THE ENGINE (not in wrapper scripts)
        so ALL callers benefit.
        """
        components = graph.get("components", [])
        flows = graph.get("data_flows", [])
        boundaries = graph.get("trust_boundaries", [])

        # Filter metadata-only components
        real_comps = [c for c in components if c.get("metadata", {}).get("type") != "metadata"]
        meta_comps = [c for c in components if c.get("metadata", {}).get("type") == "metadata"]

        if not real_comps:
            # Nothing detected — create minimal placeholder
            real_comps = [{
                "id": "process-application",
                "name": "Application (auto-detected)",
                "type": "process",
                "is_public_facing": True,
                "has_authentication": False,
                "has_encryption": False,
                "technology": "Unknown",
                "ports": [],
                "source_paths": [],
                "metadata": {},
                "trust_level": "internal",
            }]

        # Ensure at least one public-facing component
        if not any(c.get("is_public_facing") for c in real_comps):
            for c in real_comps:
                if c.get("type") == "process":
                    c["is_public_facing"] = True
                    break

        # Ensure trust boundaries exist
        if not boundaries:
            internal_ids = [c["id"] for c in real_comps if c.get("type") in ("process", "data_store")]
            external_ids = [c["id"] for c in real_comps if c.get("type") == "external_entity"]
            if internal_ids:
                boundaries.append({
                    "id": "tb-auto-internal",
                    "name": "Internal Network",
                    "trust_level": "internal",
                    "component_ids": internal_ids,
                })
            if external_ids:
                boundaries.append({
                    "id": "tb-auto-external",
                    "name": "External",
                    "trust_level": "external",
                    "component_ids": external_ids,
                })

        # Build boundary lookup for crossing detection
        comp_to_boundary = {}
        for b in boundaries:
            for cid in b.get("component_ids", []):
                comp_to_boundary[cid] = b.get("trust_level", "unknown")

        # If no flows exist, infer basic flows from component relationships
        if not flows and len(real_comps) > 1:
            flow_id = 0
            externals = [c for c in real_comps if c.get("type") == "external_entity"]
            processes = [c for c in real_comps if c.get("type") == "process"]
            data_stores = [c for c in real_comps if c.get("type") == "data_store"]
            public_procs = [c for c in processes if c.get("is_public_facing")]

            # External → Public processes
            for ext in externals:
                for proc in (public_procs or processes[:1]):
                    flow_id += 1
                    src_level = comp_to_boundary.get(ext["id"], "external")
                    tgt_level = comp_to_boundary.get(proc["id"], "internal")
                    flows.append({
                        "id": f"flow-auto-{flow_id}",
                        "source_id": ext["id"],
                        "target_id": proc["id"],
                        "protocol": "HTTPS",
                        "is_encrypted": True,
                        "is_authenticated": False,
                        "crosses_trust_boundary": src_level != tgt_level,
                        "data_types": ["user_requests"],
                        "data_sensitivity": ["credentials"],
                        "description": f"Traffic to {proc.get('name', '')}",
                    })

            # Processes → Data stores
            for proc in processes:
                for ds in data_stores:
                    flow_id += 1
                    flows.append({
                        "id": f"flow-auto-{flow_id}",
                        "source_id": proc["id"],
                        "target_id": ds["id"],
                        "protocol": "TCP",
                        "is_encrypted": False,
                        "is_authenticated": True,
                        "crosses_trust_boundary": False,
                        "data_types": ["queries"],
                        "data_sensitivity": ["internal"],
                        "description": f"{proc.get('name', '')} → {ds.get('name', '')}",
                    })

        # Ensure flows have data_sensitivity and crosses_trust_boundary
        for flow in flows:
            if not flow.get("data_sensitivity"):
                flow["data_sensitivity"] = ["internal"]
            if "crosses_trust_boundary" not in flow:
                src_level = comp_to_boundary.get(flow.get("source_id"), "unknown")
                tgt_level = comp_to_boundary.get(flow.get("target_id"), "unknown")
                flow["crosses_trust_boundary"] = (
                    src_level != tgt_level and src_level != "unknown" and tgt_level != "unknown"
                )

        graph["components"] = real_comps + meta_comps
        graph["data_flows"] = flows
        graph["trust_boundaries"] = boundaries

        logger.info(
            f"[Pre-process] Architecture enriched: "
            f"{len(real_comps)} components, {len(flows)} flows, {len(boundaries)} boundaries"
        )

        return graph
