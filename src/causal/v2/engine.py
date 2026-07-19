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
