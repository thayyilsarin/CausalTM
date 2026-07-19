"""
Federated Causal Engine — Orchestrator for the hierarchical SCM.

This is the main entry point that replaces the old flat CausalThreatEngine.
It orchestrates:
1. Building domain-specific sub-graphs (SAST, DAST, Repo)
2. Extracting edge nodes from each
3. Building the master DAG
4. Running multi-level counterfactual analysis
5. Producing the unified analysis result

The key architectural principle:
- Sub-graphs reason WITHIN their domain (tactical level)
- Master DAG reasons ACROSS domains (strategic level)
- Counterfactuals work at BOTH levels with propagation
"""

import logging
from typing import Optional

from pydantic import BaseModel, Field

from src.causal.federated.base import EdgeNode, SubGraphSummary, TacticalCounterfactual
from src.causal.federated.dast_subgraph import DASTSubGraph
from src.causal.federated.master_dag import MasterDAG, MasterDAGResult, StrategicCounterfactual
from src.causal.federated.repo_subgraph import RepoSubGraph
from src.causal.federated.sast_subgraph import SASTSubGraph

logger = logging.getLogger(__name__)


# ──── FEDERATED ANALYSIS RESULT ──────────────────────────────────────────────


class FederatedAnalysisResult(BaseModel):
    """Complete output from the Federated Causal Engine."""

    # Overall risk from master DAG
    overall_risk: float = Field(ge=0.0, le=1.0, default=0.0)
    risk_rating: str = ""

    # Intermediate scores (from master)
    exploitability: float = 0.0
    exposure: float = 0.0
    impact_severity: float = 0.0
    blast_radius: float = 0.0
    mitigation_posture: float = 0.0

    # Layer contributions
    layer_contributions: dict[str, float] = Field(default_factory=dict)

    # Strategic counterfactuals (cross-layer)
    strategic_counterfactuals: list[dict] = Field(default_factory=list)

    # Tactical counterfactuals (within-layer, propagated to master)
    tactical_counterfactuals: list[dict] = Field(default_factory=list)

    # Cross-layer confounders
    cross_layer_confounders: list[dict] = Field(default_factory=list)

    # Critical paths
    critical_paths: list[dict] = Field(default_factory=list)

    # Concrete attack paths (from CausalAttackGraph)
    attack_paths: list[dict] = Field(default_factory=list)
    attack_graph_choke_points: list[str] = Field(default_factory=list)

    # Sub-graph summaries
    layer_summaries: dict[str, dict] = Field(default_factory=dict)

    # All edge nodes (for transparency/auditability)
    edge_nodes: list[dict] = Field(default_factory=list)

    # Graph statistics
    stats: dict[str, int] = Field(default_factory=dict)

    def to_pipeline_output(self) -> dict:
        """
        Convert to the format expected by the scan pipeline.

        This maintains backward compatibility with the existing
        pipeline that expects the old flat engine's output format.
        """
        # Build attack_paths: map critical paths to element-level scores
        attack_path_scores = {}
        for node in self.critical_paths[:20]:
            path = node.get("path", [])
            score = node.get("score", 0.0)
            for node_id in path:
                # Only include component-like IDs (not intermediate nodes)
                if node_id.startswith(("process-", "data_store-", "ext-")):
                    if node_id not in attack_path_scores:
                        attack_path_scores[node_id] = {"score": 0.0, "paths_through": 0}
                    attack_path_scores[node_id]["score"] = max(
                        attack_path_scores[node_id]["score"], score
                    )
                    attack_path_scores[node_id]["paths_through"] += 1

        # Build confirmed_exploitable: components confirmed by DAST
        # Map DAST findings to public-facing components
        confirmed_components = []
        dast_confirmed_value = 0.0
        for en in self.edge_nodes:
            if en.get("id") == "dast.confirmed_exploitable":
                dast_confirmed_value = en.get("value", 0.0)

        # If DAST found ANY findings, mark all public-facing components as confirmed
        # (DAST by definition only finds things on reachable components)
        if dast_confirmed_value > 0:
            for en in self.edge_nodes:
                if en.get("id") == "repo.public_exposure" and en.get("value", 0) > 0:
                    confirmed_components = en.get("metadata", {}).get(
                        "public_component_ids", ""
                    ).split(",")
                    confirmed_components = [c.strip() for c in confirmed_components if c.strip()]

            # Fallback: if no component IDs in metadata, use attack path components
            if not confirmed_components:
                for node in self.critical_paths[:10]:
                    for node_id in node.get("path", []):
                        if node_id.startswith("process-") and node_id not in confirmed_components:
                            confirmed_components.append(node_id)

            # Final fallback: mark any component that has attack_path score
            if not confirmed_components:
                confirmed_components = list(attack_path_scores.keys())

        return {
            "overall_risk": self.overall_risk,
            "risk_rating": self.risk_rating,
            "attack_paths": attack_path_scores,
            "confirmed_exploitable": confirmed_components,
            "confounder_adjustments": {
                conf["confounder_node"]: {
                    "reduce_severity": True,
                    "reason": conf["implication"],
                }
                for conf in self.cross_layer_confounders
            },
            "high_risk_flows": [],
            "mediators": [],
            "counterfactuals": self.strategic_counterfactuals[:5],
            "graph_stats": self.stats,
            "threat_counts_by_element": {},
            # Concrete attack graph (component-level paths)
            "causal_attack_graph": {
                "paths": self.attack_paths[:10],
                "choke_points": self.attack_graph_choke_points,
                "total_paths": len(self.attack_paths),
            },
            # New federated-specific fields
            "federated": {
                "layer_contributions": self.layer_contributions,
                "intermediate_scores": {
                    "exploitability": self.exploitability,
                    "exposure": self.exposure,
                    "impact_severity": self.impact_severity,
                    "blast_radius": self.blast_radius,
                    "mitigation_posture": self.mitigation_posture,
                },
                "tactical_counterfactuals": self.tactical_counterfactuals,
            },
        }


# ──── FEDERATED CAUSAL ENGINE ────────────────────────────────────────────────


class FederatedCausalEngine:
    """
    The Federated Causal Engine — orchestrates hierarchical causal reasoning.

    This replaces the old flat CausalThreatEngine with a modular architecture
    where each data source has its own causal sub-graph, and a master DAG
    performs cross-layer reasoning.

    Benefits over flat approach:
    - Scalable: each layer stays small regardless of finding count
    - Interpretable: clear separation of concerns
    - Powerful counterfactuals: strategic (cross-layer) + tactical (within-layer)
    - Modular: add/remove layers without restructuring
    - Auditable: each layer's contribution to risk is quantified
    """

    def __init__(self):
        self.sast_subgraph = SASTSubGraph()
        self.dast_subgraph = DASTSubGraph()
        self.repo_subgraph = RepoSubGraph()
        self.master_dag = MasterDAG()
        self.attack_graph = None  # Built during analyze()
        self._built = False
        self._result: Optional[FederatedAnalysisResult] = None
        self._component_graph: Optional[dict] = None

    def build_graph(
        self,
        component_graph: dict,
        sast_findings: list,
        dast_findings: list,
    ) -> None:
        """
        Build the federated causal model from all data sources.

        Args:
            component_graph: Discovered architecture (ComponentGraph dict)
            sast_findings: Normalized SAST findings (from SARIFIngestor)
            dast_findings: Normalized DAST findings (from ZAPIngestor)
        """
        logger.info("=" * 60)
        logger.info("FEDERATED CAUSAL ENGINE: Building hierarchical model")
        logger.info("=" * 60)

        # Store component graph for attack graph construction
        self._component_graph = component_graph

        # Step 1: Build each sub-graph independently
        logger.info("[Layer 1/3] Building SAST sub-graph...")
        self.sast_subgraph.build({
            "findings": sast_findings,
            "component_graph": component_graph,
            "code_patterns": self._extract_code_patterns(component_graph),
        })

        logger.info("[Layer 2/3] Building DAST sub-graph...")
        self.dast_subgraph.build({
            "findings": dast_findings,
            "component_graph": component_graph,
        })

        logger.info("[Layer 3/3] Building Repository sub-graph...")
        self.repo_subgraph.build({
            "component_graph": component_graph,
        })

        # Step 2: Extract edge nodes from each sub-graph
        logger.info("[Federation] Extracting edge nodes from sub-graphs...")
        sast_edges = self.sast_subgraph.get_edge_nodes()
        dast_edges = self.dast_subgraph.get_edge_nodes()
        repo_edges = self.repo_subgraph.get_edge_nodes()

        all_edge_nodes = sast_edges + dast_edges + repo_edges
        logger.info(
            f"  SAST: {len(sast_edges)} edge nodes | "
            f"DAST: {len(dast_edges)} edge nodes | "
            f"Repo: {len(repo_edges)} edge nodes | "
            f"Total: {len(all_edge_nodes)}"
        )

        # Step 3: Build master DAG from edge nodes
        logger.info("[Master DAG] Building cross-layer causal model...")
        self.master_dag.build(all_edge_nodes)

        self._built = True
        logger.info("=" * 60)
        logger.info(f"FEDERATED MODEL BUILT: Overall Risk = {self.master_dag._overall_risk:.3f}")
        logger.info("=" * 60)

    def analyze(self) -> dict:
        """
        Run the full federated analysis.

        Returns:
            FederatedAnalysisResult as dictionary (pipeline-compatible)
        """
        if not self._built:
            logger.warning("analyze() called before build_graph(). Returning empty result.")
            return FederatedAnalysisResult().to_pipeline_output()

        logger.info("Running federated causal analysis...")

        # Run master DAG analysis
        master_result = self.master_dag.analyze()

        # Build the Concrete Causal Attack Graph (cross-layer composition)
        logger.info("[Attack Graph] Building concrete causal attack graph...")
        from src.causal.federated.attack_graph import CausalAttackGraph

        attack_graph_builder = CausalAttackGraph()
        attack_graph_result = attack_graph_builder.build(
            repo_subgraph=self.repo_subgraph,
            sast_subgraph=self.sast_subgraph,
            dast_subgraph=self.dast_subgraph,
            component_graph=self._component_graph or {},
        )
        self.attack_graph = attack_graph_result

        # Run tactical counterfactuals and propagate to master
        tactical_results = self._run_tactical_counterfactuals()

        # Build full result
        all_edge_nodes = (
            self.sast_subgraph.get_edge_nodes()
            + self.dast_subgraph.get_edge_nodes()
            + self.repo_subgraph.get_edge_nodes()
        )

        result = FederatedAnalysisResult(
            overall_risk=master_result.overall_risk,
            risk_rating=self._risk_to_rating(master_result.overall_risk),
            exploitability=master_result.exploitability_score,
            exposure=master_result.exposure_score,
            impact_severity=master_result.impact_severity_score,
            blast_radius=master_result.blast_radius_score,
            mitigation_posture=master_result.mitigation_posture_score,
            layer_contributions=master_result.layer_contributions,
            strategic_counterfactuals=[
                cf.model_dump() for cf in master_result.strategic_counterfactuals
            ],
            tactical_counterfactuals=tactical_results,
            cross_layer_confounders=[
                conf.model_dump() for conf in master_result.cross_layer_confounders
            ],
            critical_paths=master_result.critical_paths,
            attack_paths=[p.model_dump() for p in attack_graph_result.paths[:20]],
            attack_graph_choke_points=attack_graph_result.critical_choke_points,
            layer_summaries={
                "sast": self.sast_subgraph.get_summary().model_dump(),
                "dast": self.dast_subgraph.get_summary().model_dump(),
                "repo": self.repo_subgraph.get_summary().model_dump(),
            },
            edge_nodes=[en.model_dump() for en in all_edge_nodes],
            stats={
                "sast_nodes": self.sast_subgraph.graph.number_of_nodes(),
                "sast_edges": self.sast_subgraph.graph.number_of_edges(),
                "dast_nodes": self.dast_subgraph.graph.number_of_nodes(),
                "dast_edges": self.dast_subgraph.graph.number_of_edges(),
                "repo_nodes": self.repo_subgraph.graph.number_of_nodes(),
                "repo_edges": self.repo_subgraph.graph.number_of_edges(),
                "master_nodes": self.master_dag.graph.number_of_nodes(),
                "master_edges": self.master_dag.graph.number_of_edges(),
                "total_edge_nodes": len(all_edge_nodes),
                "attack_graph_nodes": attack_graph_result.stats.get("total_nodes", 0),
                "attack_graph_edges": attack_graph_result.stats.get("total_edges", 0),
                "attack_paths_found": attack_graph_result.total_paths,
                "confirmed_attack_paths": attack_graph_result.confirmed_paths,
            },
        )

        self._result = result

        logger.info(
            f"Federated analysis complete: "
            f"Risk={result.overall_risk:.3f} ({result.risk_rating}) | "
            f"Layers: SAST={result.layer_contributions.get('sast', 0):.0%}, "
            f"DAST={result.layer_contributions.get('dast', 0):.0%}, "
            f"Repo={result.layer_contributions.get('repo', 0):.0%}"
        )

        return result.to_pipeline_output()

    def get_full_result(self) -> Optional[FederatedAnalysisResult]:
        """Get the full result object (not pipeline-compatible, for reporting)."""
        return self._result

    def multi_level_counterfactual(
        self, layer: str, intervention: str, params: Optional[dict] = None
    ) -> dict:
        """
        Perform a multi-level counterfactual analysis.

        This is the key capability of the federated architecture:
        1. Intervene at the tactical level (within a sub-graph)
        2. Observe how edge nodes change
        3. Propagate to master DAG
        4. Observe how overall risk changes

        Args:
            layer: Which layer to intervene in ('sast', 'dast', 'repo')
            intervention: Intervention type (layer-specific)
            params: Optional parameters for the intervention

        Returns:
            Multi-level counterfactual result showing both local and global effects
        """
        params = params or {}

        # Get the appropriate sub-graph
        subgraph = self._get_subgraph(layer)
        if not subgraph:
            return {"error": f"Unknown layer: {layer}"}

        # Step 1: Perform tactical counterfactual in sub-graph
        tactical = subgraph.tactical_counterfactual(intervention, params)

        # Step 2: Propagate new edge values to master DAG
        new_risk = self.master_dag.recalculate_with_tactical(layer, tactical.edge_nodes_after)
        original_risk = self.master_dag._overall_risk

        # Step 3: Combine results
        return {
            "layer": layer,
            "intervention": intervention,
            "description": tactical.intervention_description,
            "tactical_result": {
                "edge_nodes_before": tactical.edge_nodes_before,
                "edge_nodes_after": tactical.edge_nodes_after,
                "delta": tactical.delta,
                "local_effectiveness": tactical.effectiveness,
            },
            "strategic_impact": {
                "risk_before": original_risk,
                "risk_after": new_risk,
                "risk_reduction": original_risk - new_risk,
                "risk_reduction_pct": (
                    (original_risk - new_risk) / max(original_risk, 0.001) * 100
                ),
            },
            "recommendation": (
                f"Tactical intervention '{tactical.intervention_description}' in {layer} layer "
                f"would reduce overall risk from {original_risk:.3f} to {new_risk:.3f} "
                f"({(original_risk - new_risk) / max(original_risk, 0.001) * 100:.0f}% reduction)"
            ),
        }

    # ──── INTERNAL METHODS ───────────────────────────────────────────────

    def _run_tactical_counterfactuals(self) -> list[dict]:
        """Run standard tactical counterfactuals across all layers and propagate."""
        results = []

        # SAST tactical interventions
        for intervention in ["fix_critical", "fix_injection", "add_auth"]:
            result = self.multi_level_counterfactual("sast", intervention)
            results.append(result)

        # DAST tactical interventions
        for intervention in ["fix_auth", "fix_tls", "fix_critical"]:
            result = self.multi_level_counterfactual("dast", intervention)
            results.append(result)

        # Repo tactical interventions
        for intervention in ["add_gateway", "add_segmentation", "encrypt_flows"]:
            result = self.multi_level_counterfactual("repo", intervention)
            results.append(result)

        # Sort by strategic impact (highest risk reduction first)
        results.sort(
            key=lambda r: r.get("strategic_impact", {}).get("risk_reduction", 0),
            reverse=True,
        )

        return results

    def _get_subgraph(self, layer: str):
        """Get a sub-graph by layer name."""
        mapping = {
            "sast": self.sast_subgraph,
            "dast": self.dast_subgraph,
            "repo": self.repo_subgraph,
        }
        return mapping.get(layer)

    def _extract_code_patterns(self, component_graph: dict) -> dict:
        """Extract code pattern metadata from component graph."""
        patterns = {}
        for comp in component_graph.get("components", []):
            meta = comp.get("metadata", {})
            if meta.get("type") == "metadata":
                patterns.update(meta)
        return patterns

    def _risk_to_rating(self, risk: float) -> str:
        """Convert numeric risk to human-readable rating."""
        if risk >= 0.8:
            return "Critical"
        elif risk >= 0.6:
            return "High"
        elif risk >= 0.4:
            return "Medium"
        elif risk >= 0.2:
            return "Low"
        return "Minimal"
