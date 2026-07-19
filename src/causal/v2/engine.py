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
