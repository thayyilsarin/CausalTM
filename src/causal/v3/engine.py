"""
CausalTM v3 — Engine Orchestrator

Wires all layers together: A → B → C → D → E → F → G → H

This is the single entry point for callers.
"""

import logging
from typing import Optional

from src.causal.v3.models import (
    CausalTMv3Result,
    ControlCategory,
    FusionLayerOutput,
    RemediationRoadmap,
    SourceType,
    WhatIfResult,
)
from src.causal.v3.normalization import NormalizationLayerV3
from src.causal.v3.sast_subdag import SASTSubDAGV3
from src.causal.v3.dast_subdag import DASTSubDAGV3
from src.causal.v3.repo_subdag import RepoSubDAGV3
from src.causal.v3.fusion import FusionLayerV3
from src.causal.v3.master_dag import MasterDAGV3
from src.causal.v3.stride_layer import StrideLayerV3

logger = logging.getLogger(__name__)


class CausalTMv3Engine:
    """
    CausalTM v3 Engine — complete 8-layer orchestrator.

    Usage:
        engine = CausalTMv3Engine()
        result = engine.analyze(component_graph, sast_findings, dast_findings)
        what_if = engine.what_if("validation", 1.0)
    """

    def __init__(self):
        self._normalization = NormalizationLayerV3()
        self._sast_subdag = SASTSubDAGV3()
        self._dast_subdag = DASTSubDAGV3()
        self._repo_subdag = RepoSubDAGV3()
        self._fusion = FusionLayerV3()
        self._master_dag = MasterDAGV3()
        self._stride_layer = StrideLayerV3()
        self._component_graph: Optional[dict] = None
        self._fusion_output: Optional[FusionLayerOutput] = None
        self._result: Optional[CausalTMv3Result] = None

    def analyze(
        self,
        component_graph: dict,
        sast_findings: list[dict],
        dast_findings: list[dict],
        iac_findings: Optional[list[dict]] = None,
        repo_findings: Optional[list[dict]] = None,
    ) -> CausalTMv3Result:
        """
        Run complete v3 analysis pipeline.

        A → B → C → D → E → F → (G optional) → Result
        """
        self._component_graph = component_graph

        logger.info("=" * 60)
        logger.info("CausalTM v3 Engine: Running analysis")
        logger.info("=" * 60)

        # ── Layer B: Normalize all findings ──
        logger.info("[Layer B] Normalizing findings...")
        all_evidence = []

        if sast_findings:
            sast_evidence = self._normalization.normalize(
                sast_findings, SourceType.SAST, component_graph
            )
            all_evidence.extend(sast_evidence)
            logger.info(f"  SAST: {len(sast_evidence)} findings normalized")

        if dast_findings:
            dast_evidence = self._normalization.normalize(
                dast_findings, SourceType.DAST, component_graph
            )
            all_evidence.extend(dast_evidence)
            logger.info(f"  DAST: {len(dast_evidence)} findings normalized")

        if iac_findings:
            iac_evidence = self._normalization.normalize(
                iac_findings, SourceType.IAC, component_graph
            )
            all_evidence.extend(iac_evidence)
            logger.info(f"  IaC: {len(iac_evidence)} findings normalized")

        # ── Layer C: Build sub-DAGs and compute boundary postures ──
        logger.info("[Layer C] Computing boundary-specific postures...")

        boundary_postures = []

        # SAST sub-DAG
        sast_only = [e for e in all_evidence if e.source_type == SourceType.SAST]
        if sast_only:
            self._sast_subdag.build(sast_only)
            sast_postures = self._sast_subdag.compute_boundary_postures()
            boundary_postures.extend(sast_postures)
            logger.info(f"  SAST sub-DAG: {len(sast_postures)} boundary postures")

        # DAST sub-DAG
        dast_only = [e for e in all_evidence if e.source_type == SourceType.DAST]
        if dast_only:
            self._dast_subdag.build(dast_only)
            dast_postures = self._dast_subdag.compute_boundary_postures()
            boundary_postures.extend(dast_postures)
            logger.info(f"  DAST sub-DAG: {len(dast_postures)} boundary postures")

        # Repo sub-DAG (derives posture from component graph structure)
        self._repo_subdag.build_from_graph(component_graph)
        repo_postures = self._repo_subdag.compute_boundary_postures()
        boundary_postures.extend(repo_postures)
        logger.info(f"  Repo sub-DAG: {len(repo_postures)} boundary postures")

        # ── Layer D: Fusion ──
        logger.info("[Layer D] Fusing boundary postures into architectural posture...")
        criticalities = self._fusion.compute_all_criticalities(component_graph)
        self._fusion_output = self._fusion.fuse(boundary_postures, criticalities)

        for ap in self._fusion_output.postures:
            logger.info(
                f"  arch.{ap.control_category.value}_posture = {ap.posture:.3f} "
                f"(conf={ap.confidence:.2f}, worst_crit={ap.worst_critical_boundary:.3f})"
            )

        # ── Layer E: Master DAG ──
        logger.info("[Layer E] Building Master DAG...")
        self._master_dag.build(self._fusion_output)
        stride_postures = self._master_dag.get_stride_postures()
        overall_risk = self._master_dag.get_overall_risk()

        for cat, posture in stride_postures.items():
            logger.info(f"  STRIDE {cat}: {posture:.3f}")
        logger.info(f"  Overall risk: {overall_risk:.3f}")

        # ── Layer F: STRIDE Threats ──
        logger.info("[Layer F] Evaluating STRIDE threats...")
        threats = self._stride_layer.evaluate(
            stride_postures, self._fusion_output, component_graph
        )
        logger.info(f"  Threats generated: {len(threats)}")

        # ── Build Result ──
        boundaries_assessed = list(set(
            bp.boundary_id for bp in boundary_postures
        ))

        self._result = CausalTMv3Result(
            threats=threats,
            total_threats=len(threats),
            fused_postures=self._fusion_output.postures,
            stride_posture_per_category=stride_postures,
            overall_risk=overall_risk,
            risk_rating=self._risk_to_rating(overall_risk),
            evidence_count=len(all_evidence),
            boundary_count=len(boundaries_assessed),
            boundaries_assessed=boundaries_assessed,
            average_confidence=sum(ap.confidence for ap in self._fusion_output.postures) / max(len(self._fusion_output.postures), 1),
            uncertain_divergences=sum(
                1 for fbp in self._fusion_output.boundary_postures
                if fbp.fusion_status.value == "uncertain_divergence"
            ),
        )

        logger.info("=" * 60)
        logger.info(
            f"CausalTM v3: Complete. Risk={overall_risk:.3f} ({self._result.risk_rating}), "
            f"Threats={len(threats)}, Boundaries={len(boundaries_assessed)}"
        )
        logger.info("=" * 60)

        return self._result

    def what_if(self, variable: str, new_value: float, description: str = "") -> WhatIfResult:
        """Run a what-if query after analysis."""
        return self._master_dag.what_if(variable, new_value, description)

    def get_attack_paths(self, max_paths: int = 10) -> list[dict]:
        """
        Compute attack paths through the component graph.
        Reuses the v2 algorithm (graph traversal from external to data stores).
        """
        # Import the algorithm from v2 engine (reuse, don't rewrite)
        from src.causal.v2.engine import CausalTMv2Engine
        temp = CausalTMv2Engine()
        temp._component_graph = self._component_graph
        return temp.get_attack_paths(max_paths=max_paths)

    def get_dfd_model(self) -> dict:
        """Generate DFD model from component graph."""
        from src.causal.v2.engine import CausalTMv2Engine
        temp = CausalTMv2Engine()
        temp._component_graph = self._component_graph
        return temp.get_dfd_model()

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
