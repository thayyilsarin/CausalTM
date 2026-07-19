"""
Master DAG v2 — Cross-Layer Causal Reasoning with Bidirectional Propagation.

Receives edge nodes from all sub-DAGs and:
1. Builds unified architecture understanding
2. Applies cross-layer dependency rules (fixing in one layer affects others)
3. Forward propagation: fix → recalculate all affected edge nodes → new risk
4. Backward propagation: target posture → what must be fixed across layers
5. Feeds STRIDE layer with complete architecture state
"""

import logging
from typing import Optional

import networkx as nx
from pydantic import BaseModel, Field

from src.causal.v2.base import ArchitecturalEdgeNode, CrossLayerEffect

logger = logging.getLogger(__name__)


# ──── CROSS-LAYER DEPENDENCY RULES ──────────────────────────────────────────

CROSS_LAYER_RULES = [
    # Fixing auth in code → runtime auth should improve
    CrossLayerEffect(
        trigger_layer="sast",
        trigger_edge_node="sast.auth_posture",
        trigger_change="increase",
        affected_layer="dast",
        affected_edge_node="dast.runtime_auth_enforcement",
        effect_direction="increase",
        strength=0.7,
        reason="Fixing auth in code should improve runtime auth enforcement",
    ),
    # Fixing crypto in code → runtime encryption improves
    CrossLayerEffect(
        trigger_layer="sast",
        trigger_edge_node="sast.crypto_posture",
        trigger_change="increase",
        affected_layer="dast",
        affected_edge_node="dast.runtime_encryption_status",
        effect_direction="increase",
        strength=0.6,
        reason="Implementing encryption in code should make runtime encryption work",
    ),
    # Fixing input validation → reduces attack surface exploitability
    CrossLayerEffect(
        trigger_layer="sast",
        trigger_edge_node="sast.validation_posture",
        trigger_change="increase",
        affected_layer="dast",
        affected_edge_node="dast.exposed_attack_surface",
        effect_direction="decrease",
        strength=0.5,
        reason="Better input validation makes exposed endpoints less exploitable",
    ),
    # Adding defense-in-depth → reduces exposed attack surface
    CrossLayerEffect(
        trigger_layer="repo",
        trigger_edge_node="repo.defense_depth",
        trigger_change="increase",
        affected_layer="dast",
        affected_edge_node="dast.exposed_attack_surface",
        effect_direction="decrease",
        strength=0.6,
        reason="Adding defense layers (gateway, WAF) reduces what attackers can reach",
    ),
    # Reducing topology exposure → reduces attack surface
    CrossLayerEffect(
        trigger_layer="repo",
        trigger_edge_node="repo.topology_exposure",
        trigger_change="decrease",
        affected_layer="dast",
        affected_edge_node="dast.exposed_attack_surface",
        effect_direction="decrease",
        strength=0.8,
        reason="Fewer public-facing components means smaller attack surface",
    ),
    # Improving trust boundary integrity → reduces info leakage
    CrossLayerEffect(
        trigger_layer="repo",
        trigger_edge_node="repo.trust_boundary_integrity",
        trigger_change="increase",
        affected_layer="dast",
        affected_edge_node="dast.information_leakage",
        effect_direction="decrease",
        strength=0.5,
        reason="Better boundary controls reduce unintended information exposure",
    ),
]


# ──── MASTER DAG RESULT ──────────────────────────────────────────────────────


class MasterDAGResult(BaseModel):
    """Output from the Master DAG's analysis."""

    # Edge nodes received (architectural posture from each layer)
    edge_nodes: dict[str, float] = Field(default_factory=dict)

    # STRIDE-relevant architecture scores (fed to STRIDE layer)
    architecture_scores: dict[str, float] = Field(default_factory=dict)

    # Which STRIDE categories are threatened (and why)
    stride_inputs: dict[str, dict] = Field(default_factory=dict)

    # Cross-layer effects that would activate on intervention
    active_cross_layer_rules: list[dict] = Field(default_factory=list)


class WhatIfResult(BaseModel):
    """Result of a what-if / counterfactual analysis."""

    intervention: str
    layer: str
    description: str

    # Direct effect (in the source layer)
    edge_nodes_before: dict[str, float] = Field(default_factory=dict)
    edge_nodes_after: dict[str, float] = Field(default_factory=dict)

    # Cross-layer effects
    cross_layer_effects: list[dict] = Field(default_factory=list)

    # Net impact on STRIDE posture
    stride_before: dict[str, float] = Field(default_factory=dict)
    stride_after: dict[str, float] = Field(default_factory=dict)

    # Recommendations
    recommendation: str = ""
    side_effects: list[str] = Field(default_factory=list)


# ──── MASTER DAG IMPLEMENTATION ──────────────────────────────────────────────


class MasterDAGV2:
    """
    Master DAG v2 — combines edge nodes from all sub-DAGs and reasons
    about the complete architecture for STRIDE evaluation.

    Key capabilities:
    - Unified architecture view (all posture scores in one place)
    - Cross-layer dependency tracking
    - Forward propagation (what happens if we fix X?)
    - Backward propagation (what must we fix to achieve target Y?)
    - STRIDE input preparation (feeds the cream layer)
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self._edge_nodes: dict[str, ArchitecturalEdgeNode] = {}
        self._cross_layer_rules = CROSS_LAYER_RULES
        # Compatibility with renderer (which looks for _nodes or _base_variables)
        self._base_variables: dict[str, dict] = {}

    @property
    def layer_name(self) -> str:
        return "master"

    def build(self, all_edge_nodes: list[ArchitecturalEdgeNode]) -> None:
        """
        Build master DAG from all sub-DAG edge nodes.

        Args:
            all_edge_nodes: Edge nodes from SAST + DAST + Repo sub-DAGs
        """
        self._edge_nodes = {en.id: en for en in all_edge_nodes}

        # Populate _base_variables for renderer compatibility
        for en in all_edge_nodes:
            self._base_variables[en.id] = {
                "node_type": "edge_node",
                "name": en.name,
                "layer": en.layer,
                "value": en.value,
                "description": f"[{en.layer.upper()}] {en.name}: {en.value:.2f}",
            }

        # Build graph: edge_nodes → cross-layer edges
        for en in all_edge_nodes:
            self.graph.add_node(en.id, layer=en.layer, value=en.value, node_type="edge_node")

        # Add cross-layer dependency edges
        for rule in self._cross_layer_rules:
            if rule.trigger_edge_node in self._edge_nodes and rule.affected_edge_node in self._edge_nodes:
                self.graph.add_edge(
                    rule.trigger_edge_node,
                    rule.affected_edge_node,
                    rule_type="cross_layer",
                    strength=rule.strength,
                    reason=rule.reason,
                )

        # Add STRIDE posture nodes (intermediate reasoning)
        stride_categories = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"]
        for cat in stride_categories:
            node_id = f"stride.{cat.lower().replace(' ', '_')}"
            self.graph.add_node(node_id, node_type="stride_posture", category=cat)
            self._base_variables[node_id] = {
                "node_type": "stride_posture",
                "name": f"STRIDE: {cat}",
                "description": f"STRIDE: {cat} Posture",
            }
            # Connect relevant edge nodes to this STRIDE category
            for en in all_edge_nodes:
                if cat in en.stride_relevance:
                    self.graph.add_edge(en.id, node_id, edge_type="determines", weight=en.causal_strength)

        # Add final Overall Risk node
        risk_node_id = "overall_risk"
        self.graph.add_node(risk_node_id, node_type="final_effect")
        self._base_variables[risk_node_id] = {
            "node_type": "final_effect",
            "name": "OVERALL RISK",
            "description": "Overall Risk (final effect)",
        }
        # Connect STRIDE posture nodes to overall risk
        for cat in stride_categories:
            node_id = f"stride.{cat.lower().replace(' ', '_')}"
            self.graph.add_edge(node_id, risk_node_id, edge_type="contributes_to", weight=0.5)

        logger.info(
            f"[Master DAG v2] Built with {len(self._edge_nodes)} edge nodes, "
            f"{self.graph.number_of_edges()} cross-layer edges"
        )

    def analyze(self) -> MasterDAGResult:
        """
        Produce the unified architecture analysis for STRIDE layer consumption.
        """
        # Collect all edge node values
        edge_node_values = {en_id: en.value for en_id, en in self._edge_nodes.items()}

        # Compute STRIDE-relevant scores by combining edge nodes per STRIDE category
        stride_inputs = self._compute_stride_inputs()

        # Identify which cross-layer rules would activate
        active_rules = self._identify_active_rules()

        return MasterDAGResult(
            edge_nodes=edge_node_values,
            architecture_scores=self._compute_architecture_scores(),
            stride_inputs=stride_inputs,
            active_cross_layer_rules=active_rules,
        )

    def what_if(
        self,
        layer: str,
        edge_node_id: str,
        new_value: float,
        description: str = "",
    ) -> WhatIfResult:
        """
        What-If analysis: set an edge node to a new value and compute full impact.

        Forward: new value → cross-layer effects → new STRIDE posture
        Backward: what base variables must change (delegated to sub-DAG)

        Args:
            layer: Which layer the intervention is in
            edge_node_id: Which edge node changes
            new_value: Target value
            description: Human description of the intervention
        """
        # Capture before state
        before = {en_id: en.value for en_id, en in self._edge_nodes.items()}
        stride_before = self._compute_stride_posture_scores()

        # Apply the change
        after = dict(before)
        after[edge_node_id] = new_value

        # Compute cross-layer effects
        cross_effects = []
        for rule in self._cross_layer_rules:
            if rule.trigger_edge_node != edge_node_id:
                continue

            old_trigger_value = before.get(rule.trigger_edge_node, 0)
            new_trigger_value = new_value
            delta = new_trigger_value - old_trigger_value

            # Does this change match the trigger direction?
            if rule.trigger_change == "increase" and delta > 0:
                triggered = True
            elif rule.trigger_change == "decrease" and delta < 0:
                triggered = True
            else:
                triggered = False

            if triggered:
                # Apply effect to affected edge node
                affected_current = after.get(rule.affected_edge_node, 0)
                effect_magnitude = abs(delta) * rule.strength

                if rule.effect_direction == "increase":
                    affected_new = min(1.0, affected_current + effect_magnitude)
                else:
                    affected_new = max(0.0, affected_current - effect_magnitude)

                after[rule.affected_edge_node] = affected_new

                cross_effects.append({
                    "affected_edge_node": rule.affected_edge_node,
                    "affected_layer": rule.affected_layer,
                    "old_value": affected_current,
                    "new_value": affected_new,
                    "reason": rule.reason,
                })

        # Compute STRIDE posture after changes
        stride_after = self._compute_stride_posture_scores_from(after)

        # Identify side effects (unexpected negative changes)
        side_effects = []
        for en_id, new_val in after.items():
            old_val = before.get(en_id, 0)
            # Check for negative side effects (posture decreasing where it shouldn't)
            if new_val < old_val and en_id != edge_node_id:
                en = self._edge_nodes.get(en_id)
                if en:
                    side_effects.append(
                        f"WARNING: {en.name} decreased from {old_val:.2f} to {new_val:.2f} ({en.layer} layer)"
                    )

        return WhatIfResult(
            intervention=edge_node_id,
            layer=layer,
            description=description or f"Set {edge_node_id} to {new_value:.2f}",
            edge_nodes_before=before,
            edge_nodes_after=after,
            cross_layer_effects=cross_effects,
            stride_before=stride_before,
            stride_after=stride_after,
            recommendation=self._generate_recommendation(before, after, stride_before, stride_after),
            side_effects=side_effects,
        )

    def roadmap_to_zero(self, sub_dags: dict) -> list[dict]:
        """
        Generate sequenced remediation roadmap to 0% risk.

        Iteratively asks: "What single intervention has the highest
        cross-layer impact?" and sequences fixes optimally.

        Args:
            sub_dags: Dict of {layer_name: sub_dag_instance}

        Returns:
            Ordered list of remediation steps
        """
        roadmap = []
        current_state = {en_id: en.value for en_id, en in self._edge_nodes.items()}
        fixed_nodes = set()  # Track what's already been fixed
        step_number = 0

        while True:
            step_number += 1
            if step_number > 20:  # Safety limit
                break

            # Find the edge node with the worst posture (biggest gap from 1.0)
            best_fix = None
            best_impact = 0

            for en_id, en in self._edge_nodes.items():
                # Skip already-fixed nodes
                if en_id in fixed_nodes:
                    continue

                current_val = current_state.get(en_id, en.value)

                # Skip already-good postures and exposure metrics (where lower is better)
                if "exposure" in en_id or "leakage" in en_id or "sensitivity" in en_id:
                    if current_val <= 0.1:
                        continue
                    # For exposure, try reducing to 0.1
                    target = 0.1
                else:
                    if current_val >= 0.95:
                        continue
                    target = 1.0

                # Temporarily update edge nodes to current_state for accurate what_if
                original_values = {}
                for eid, eval_val in current_state.items():
                    if eid in self._edge_nodes:
                        original_values[eid] = self._edge_nodes[eid].value
                        self._edge_nodes[eid].value = eval_val

                # Simulate fixing this one
                result = self.what_if(en.layer, en_id, target, f"Fix {en.name}")

                # Restore original values
                for eid, orig_val in original_values.items():
                    if eid in self._edge_nodes:
                        self._edge_nodes[eid].value = orig_val

                # Calculate total STRIDE improvement
                stride_improvement = sum(
                    result.stride_after.get(cat, 0) - result.stride_before.get(cat, 0)
                    for cat in result.stride_after
                )

                # Add cross-layer bonus
                cross_layer_bonus = len(result.cross_layer_effects) * 0.1

                total_impact = stride_improvement + cross_layer_bonus

                if total_impact > best_impact:
                    best_impact = total_impact
                    best_fix = {
                        "step": step_number,
                        "edge_node": en_id,
                        "layer": en.layer,
                        "name": en.name,
                        "current_value": current_val,
                        "target_value": target,
                        "stride_improvement": stride_improvement,
                        "cross_layer_effects": result.cross_layer_effects,
                        "side_effects": result.side_effects,
                        "base_variables": en.base_variables,
                    }

            if best_fix is None or best_impact <= 0.01:
                break  # No more meaningful improvements possible

            # Apply the fix to current state for next iteration
            current_state[best_fix["edge_node"]] = best_fix["target_value"]
            fixed_nodes.add(best_fix["edge_node"])
            # Apply cross-layer effects
            for effect in best_fix["cross_layer_effects"]:
                current_state[effect["affected_edge_node"]] = effect["new_value"]

            roadmap.append(best_fix)

        return roadmap

    # ──── INTERNAL METHODS ───────────────────────────────────────────────

    def _compute_stride_inputs(self) -> dict[str, dict]:
        """Compute what the STRIDE layer needs to evaluate each category."""
        stride_inputs = {}

        for en_id, en in self._edge_nodes.items():
            for stride_cat in en.stride_relevance:
                if stride_cat not in stride_inputs:
                    stride_inputs[stride_cat] = {"posture_scores": {}, "evidence": []}
                stride_inputs[stride_cat]["posture_scores"][en_id] = en.value
                stride_inputs[stride_cat]["evidence"].extend(en.evidence)

        return stride_inputs

    def _compute_architecture_scores(self) -> dict[str, float]:
        """Compute overall architecture security scores."""
        scores = {}
        for en_id, en in self._edge_nodes.items():
            scores[en_id] = en.value
        return scores

    def _compute_stride_posture_scores(self) -> dict[str, float]:
        """Compute posture per STRIDE category from current edge nodes."""
        return self._compute_stride_posture_scores_from(
            {en_id: en.value for en_id, en in self._edge_nodes.items()}
        )

    def _compute_stride_posture_scores_from(self, edge_values: dict[str, float]) -> dict[str, float]:
        """Compute STRIDE posture from a given set of edge node values."""
        stride_scores = {
            "Spoofing": 0.0,
            "Tampering": 0.0,
            "Repudiation": 0.0,
            "Information Disclosure": 0.0,
            "Denial of Service": 0.0,
            "Elevation of Privilege": 0.0,
        }
        stride_counts = {cat: 0 for cat in stride_scores}

        for en_id, en in self._edge_nodes.items():
            value = edge_values.get(en_id, en.value)
            for cat in en.stride_relevance:
                if cat in stride_scores:
                    # For exposure/leakage: INVERT (lower exposure = better posture)
                    if "exposure" in en_id or "leakage" in en_id or "sensitivity" in en_id:
                        stride_scores[cat] += (1.0 - value) * en.causal_strength
                    else:
                        stride_scores[cat] += value * en.causal_strength
                    stride_counts[cat] += 1

        # Normalize
        for cat in stride_scores:
            if stride_counts[cat] > 0:
                stride_scores[cat] /= stride_counts[cat]

        return stride_scores

    def _identify_active_rules(self) -> list[dict]:
        """Identify which cross-layer rules could be triggered by improvements."""
        active = []
        for rule in self._cross_layer_rules:
            trigger_en = self._edge_nodes.get(rule.trigger_edge_node)
            if trigger_en and trigger_en.value < 0.9:  # Room for improvement
                active.append({
                    "trigger": rule.trigger_edge_node,
                    "affects": rule.affected_edge_node,
                    "direction": rule.effect_direction,
                    "strength": rule.strength,
                    "reason": rule.reason,
                })
        return active

    def _generate_recommendation(
        self, before: dict, after: dict, stride_before: dict, stride_after: dict
    ) -> str:
        """Generate a human-readable recommendation."""
        improvements = []
        for cat in stride_after:
            delta = stride_after[cat] - stride_before.get(cat, 0)
            if delta > 0.01:
                improvements.append(f"{cat} +{delta:.0%}")

        if improvements:
            return f"This intervention improves: {', '.join(improvements)}"
        return "Minimal impact on STRIDE posture"
