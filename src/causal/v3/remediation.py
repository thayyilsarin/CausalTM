"""
CausalTM v3 — Remediation Planner (Layer G)

Responsibility:
  - Sequence fixes by cross-layer impact with boundary-level traceability
  - Each step traces to: which boundary, which findings, what cross-layer effects
  - Produces an ordered roadmap where each step builds on the previous state

Algorithm:
  1. Find fused posture variable with highest deficit × criticality
  2. Simulate fix → propagate cross-layer effects (Layer E rules)
  3. Record step with boundary-level traceability
  4. Mark fixed; repeat until deficit < 0.05

Must NOT:
  - Invent new findings
  - Overwrite evidence provenance
  - Recommend fixes without traceability to specific boundaries and findings
"""

import logging
from typing import Optional

from src.causal.v3.models import (
    CausalEffect,
    ControlCategory,
    FusedArchitecturalPosture,
    FusionLayerOutput,
    NormalizedEvidence,
    RemediationRoadmap,
    RemediationStep,
    RemediationType,
    WhatIfResult,
)

logger = logging.getLogger(__name__)

# Min posture deficit to consider for remediation
MIN_DEFICIT_THRESHOLD = 0.05

# Maps control categories to remediation types
CATEGORY_TO_REMEDIATION_TYPE = {
    ControlCategory.AUTH: RemediationType.CODE,
    ControlCategory.CRYPTO: RemediationType.CONFIG,
    ControlCategory.VALIDATION: RemediationType.CODE,
    ControlCategory.LOGGING: RemediationType.CONFIG,
}


class RemediationPlannerV3:
    """
    v3 Remediation Planner — sequences fixes by impact with boundary traceability.

    Produces an ordered roadmap where each step:
      - Identifies the highest-impact fix (deficit × criticality)
      - Traces to specific boundaries and findings
      - Predicts cross-layer effects with assumptions
      - Shows risk reduction from this step
    """

    def generate_roadmap(
        self,
        fusion_output: FusionLayerOutput,
        master_dag,
        evidence: list[NormalizedEvidence],
    ) -> RemediationRoadmap:
        """
        Generate sequenced remediation roadmap.

        Iteratively finds the best fix, applies it (simulated), and repeats.
        """
        initial_risk = master_dag.get_overall_risk()
        steps: list[RemediationStep] = []
        fixed_categories: set[str] = set()
        cross_layer_effects_total = 0

        # Get current posture state
        posture_state = dict(master_dag.get_posture_values())

        step_number = 0
        while True:
            # Find highest-priority unfixed posture gap
            best_target = self._find_best_target(
                fusion_output, posture_state, fixed_categories
            )

            if best_target is None:
                break  # No more actionable gaps

            category, boundary_id, boundary_name, current_posture, criticality = best_target
            step_number += 1

            # Simulate fixing this posture to 1.0
            what_if = master_dag.what_if(
                category.value, 1.0,
                f"Fix {category.value} at {boundary_id}"
            )

            # Find related findings
            related_findings = self._find_related_findings(
                evidence, category, boundary_id
            )

            # Build step
            risk_before = what_if.risk_before
            risk_after = what_if.risk_after
            risk_reduction = risk_before - risk_after

            step = RemediationStep(
                step_number=step_number,
                name=f"Fix {category.value} at {boundary_name or boundary_id}",
                remediation_type=CATEGORY_TO_REMEDIATION_TYPE.get(category, RemediationType.CODE),
                target_posture_category=category,
                target_boundary_id=boundary_id,
                target_boundary_name=boundary_name,
                current_posture=current_posture,
                target_posture=1.0,
                direct_stride_improvement=risk_reduction,
                cross_layer_effects=what_if.propagated_effects,
                total_risk_reduction=risk_reduction,
                findings_to_fix=[f.id for f in related_findings],
                fix_description=self._build_fix_description(category, related_findings, boundary_id),
                assumptions=["Fix is implemented and deployed", "Improved code is in active runtime path"],
            )

            steps.append(step)
            cross_layer_effects_total += len(what_if.propagated_effects)

            # Mark as fixed
            fixed_categories.add(category.value)
            posture_state[category.value] = 1.0

            logger.info(
                f"[Roadmap] Step {step_number}: Fix {category.value} at {boundary_id} "
                f"({current_posture:.0%} → 100%) | Risk −{risk_reduction:.3f} | "
                f"Findings: {len(related_findings)}"
            )

            # Safety: max 10 steps
            if step_number >= 10:
                break

        # Compute projected final risk
        projected_final_risk = master_dag.get_overall_risk()
        # After simulating all fixes, recompute
        if steps:
            projected_final_risk = steps[-1].direct_stride_improvement  # Approximate

        roadmap = RemediationRoadmap(
            steps=steps,
            initial_risk=initial_risk,
            projected_final_risk=max(0.0, initial_risk - sum(s.total_risk_reduction for s in steps)),
            total_steps=len(steps),
            cross_layer_effects_triggered=cross_layer_effects_total,
        )

        logger.info(
            f"[Remediation Planner] Generated {len(steps)} steps. "
            f"Risk: {initial_risk:.3f} → {roadmap.projected_final_risk:.3f} "
            f"(−{initial_risk - roadmap.projected_final_risk:.3f})"
        )

        return roadmap

    def _find_best_target(
        self,
        fusion_output: FusionLayerOutput,
        posture_state: dict[str, float],
        fixed_categories: set[str],
    ) -> Optional[tuple]:
        """
        Find the posture variable with highest deficit × criticality.

        Returns: (category, boundary_id, boundary_name, current_posture, criticality)
        or None if no actionable gaps remain.
        """
        best_score = 0.0
        best_target = None

        for ap in fusion_output.postures:
            if ap.control_category.value in fixed_categories:
                continue

            current = posture_state.get(ap.control_category.value, ap.posture)
            deficit = 1.0 - current

            if deficit < MIN_DEFICIT_THRESHOLD:
                continue

            # Score = deficit × (1 + boundary count factor)
            # More boundaries affected = higher priority
            boundary_factor = 1.0 + (ap.high_criticality_boundary_count * 0.2)
            score = deficit * boundary_factor

            if score > best_score:
                best_score = score
                best_target = (
                    ap.control_category,
                    ap.worst_critical_boundary_id,
                    ap.worst_critical_boundary_id,  # Name = ID for now
                    current,
                    boundary_factor,
                )

        return best_target

    def _find_related_findings(
        self,
        evidence: list[NormalizedEvidence],
        category: ControlCategory,
        boundary_id: str,
    ) -> list[NormalizedEvidence]:
        """Find findings that contribute to this boundary's posture gap."""
        related = []
        for ev in evidence:
            if ev.control_category == category:
                if ev.boundary_assignment.boundary_id == boundary_id:
                    related.append(ev)

        # If no exact boundary match, include global/unresolved findings of same category
        if not related:
            for ev in evidence:
                if ev.control_category == category:
                    related.append(ev)

        return related[:10]  # Limit to top 10 for readability

    def _build_fix_description(
        self,
        category: ControlCategory,
        findings: list[NormalizedEvidence],
        boundary_id: str,
    ) -> str:
        """Build human-readable fix description."""
        if not findings:
            return f"Improve {category.value} controls at {boundary_id}"

        cwe_set = set(f.cwe_id for f in findings if f.cwe_id)
        file_set = set(f.file_path for f in findings if f.file_path)

        parts = [f"Fix {len(findings)} {category.value} issues at {boundary_id}"]
        if cwe_set:
            parts.append(f"CWEs: {', '.join(sorted(cwe_set)[:5])}")
        if file_set:
            parts.append(f"Files: {', '.join(sorted(file_set)[:3])}")

        return ". ".join(parts)
