"""
CausalTM v3 — Fusion / Interface Layer (Layer D)

Responsibility:
  - Merge boundary-specific postures from ALL sub-DAGs into architectural posture
  - Resolve conflicting evidence across sources
  - Compute worst-case-adjusted architectural aggregation
  - Track confidence and fusion status throughout

Operations:
  1. Group boundary postures by (boundary_id, control_category)
  2. For each group, merge across sources (corroboration/conflict/single-source)
  3. Aggregate boundary → architecture using:
       arch_posture(C) = α × weighted_avg + (1-α) × worst_critical

Must NOT:
  - Introduce new causal semantics
  - Emit threats directly
  - Consume raw findings (only BoundaryPosture from sub-DAGs)
"""

import logging
from collections import defaultdict
from typing import Optional

from src.causal.v3.interfaces import FusionLayer
from src.causal.v3.models import (
    BoundaryCriticality,
    BoundaryPosture,
    ControlCategory,
    FusedArchitecturalPosture,
    FusedBoundaryPosture,
    FusionLayerOutput,
    FusionStatus,
    SourceType,
)

logger = logging.getLogger(__name__)

# Aggregation balance parameter
ALPHA = 0.6


class FusionLayerV3(FusionLayer):
    """
    v3 Fusion Layer — merges boundary postures into architectural posture.

    Handles three scenarios:
      - Corroborated: multiple sources agree → confidence boost
      - Divergent: sources disagree → flag uncertainty, bias toward higher confidence
      - Single-source: only one source → apply confidence penalty
    """

    def fuse(
        self,
        boundary_postures: list[BoundaryPosture],
        boundary_criticalities: list[BoundaryCriticality],
    ) -> FusionLayerOutput:
        """
        Complete fusion pipeline: merge sources → aggregate to architecture.
        """
        # Step 1: Group by (boundary_id, control_category)
        grouped: dict[tuple[str, str], list[BoundaryPosture]] = defaultdict(list)
        for bp in boundary_postures:
            key = (bp.boundary_id, bp.control_category.value)
            grouped[key].append(bp)

        # Step 2: Fuse each group across sources
        fused_boundary_postures: list[FusedBoundaryPosture] = []
        for (boundary_id, cat_str), postures in grouped.items():
            fused = self.resolve_conflict(postures)
            fused_boundary_postures.append(fused)

        # Step 3: Build criticality lookup
        crit_lookup = {bc.boundary_id: bc for bc in boundary_criticalities}

        # Step 4: Aggregate boundary → architectural posture per control category
        arch_postures = self._aggregate_to_architecture(
            fused_boundary_postures, crit_lookup
        )

        logger.info(
            f"[Fusion Layer] Fused {len(boundary_postures)} boundary postures → "
            f"{len(fused_boundary_postures)} fused boundaries → "
            f"{len(arch_postures)} architectural postures"
        )

        return FusionLayerOutput(
            postures=arch_postures,
            boundary_postures=fused_boundary_postures,
            boundary_criticalities=boundary_criticalities,
        )

    def resolve_conflict(
        self,
        postures_for_same_boundary: list[BoundaryPosture],
    ) -> FusedBoundaryPosture:
        """
        Resolve evidence at a single (boundary, category) group.

        Rules:
          - Single source: use value, apply 0.7 confidence penalty
          - Both agree (within 0.3): weighted average, confidence boost (×1.1)
          - Both disagree (>0.3): weighted average biased toward higher confidence,
            flag as uncertain_divergence
        """
        boundary_id = postures_for_same_boundary[0].boundary_id
        category = postures_for_same_boundary[0].control_category

        # Collect source postures
        source_postures: dict[str, float] = {}
        for bp in postures_for_same_boundary:
            source_postures[bp.source_type.value] = bp.posture

        contributing_sources = [bp.source_type for bp in postures_for_same_boundary]

        if len(postures_for_same_boundary) == 1:
            # ── Single source ──
            bp = postures_for_same_boundary[0]
            return FusedBoundaryPosture(
                boundary_id=boundary_id,
                control_category=category,
                fused_posture=bp.posture,
                confidence=round(bp.confidence * 0.7, 4),  # Single-source penalty
                fusion_status=FusionStatus.SINGLE_SOURCE,
                contributing_sources=contributing_sources,
                source_postures=source_postures,
            )

        # ── Multiple sources ──
        # Compute weighted average (weight = confidence × causal_strength)
        total_weight = 0.0
        weighted_sum = 0.0
        for bp in postures_for_same_boundary:
            w = bp.confidence * bp.causal_strength
            weighted_sum += w * bp.posture
            total_weight += w

        fused_posture = weighted_sum / total_weight if total_weight > 0 else 0.5

        # Check agreement
        posture_values = [bp.posture for bp in postures_for_same_boundary]
        max_divergence = max(posture_values) - min(posture_values)

        if max_divergence <= 0.3:
            # ── Corroborated ──
            confidence = min(1.0, max(bp.confidence for bp in postures_for_same_boundary) * 1.1)
            fusion_status = FusionStatus.CORROBORATED
        else:
            # ── Divergent ──
            confidence = min(bp.confidence for bp in postures_for_same_boundary)
            fusion_status = FusionStatus.UNCERTAIN_DIVERGENCE

        return FusedBoundaryPosture(
            boundary_id=boundary_id,
            control_category=category,
            fused_posture=round(fused_posture, 4),
            confidence=round(confidence, 4),
            fusion_status=fusion_status,
            contributing_sources=contributing_sources,
            source_postures=source_postures,
        )

    def compute_criticality(self, boundary: dict, component_graph: dict) -> BoundaryCriticality:
        """
        Compute criticality for a boundary from the component graph.

        Formula:
          criticality(B) = 0.35 × is_external_facing
                         + 0.25 × crosses_trust_boundary
                         + 0.25 × handles_sensitive_data
                         + 0.15 × privilege_level_normalized
        """
        boundary_id = boundary.get("id", "")
        trust_level = boundary.get("trust_level", "internal")
        component_ids = boundary.get("component_ids", [])

        components = component_graph.get("components", [])
        flows = component_graph.get("data_flows", [])

        # Determine properties from contained components and flows
        is_external = trust_level == "external" or trust_level == "dmz"
        crosses_boundary = any(
            f.get("crosses_trust_boundary", False) for f in flows
            if f.get("source_id") in component_ids or f.get("target_id") in component_ids
        )
        handles_sensitive = any(
            any(s in (f.get("data_sensitivity") or []) for s in ["credentials", "pii", "secret", "financial"])
            for f in flows
            if f.get("source_id") in component_ids or f.get("target_id") in component_ids
        )

        # Privilege level: data stores get higher privilege (they hold the data)
        has_data_store = any(
            c.get("type") == "data_store"
            for c in components if c.get("id") in component_ids
        )
        privilege_level = 0.8 if has_data_store else 0.3

        criticality = (
            0.35 * float(is_external)
            + 0.25 * float(crosses_boundary)
            + 0.25 * float(handles_sensitive)
            + 0.15 * privilege_level
        )

        return BoundaryCriticality(
            boundary_id=boundary_id,
            criticality=round(criticality, 4),
            is_external_facing=is_external,
            crosses_trust_boundary=crosses_boundary,
            handles_sensitive_data=handles_sensitive,
            privilege_level=privilege_level,
        )

    def compute_all_criticalities(self, component_graph: dict) -> list[BoundaryCriticality]:
        """Compute criticality for all boundaries in the component graph."""
        boundaries = component_graph.get("trust_boundaries", [])
        criticalities = []

        for boundary in boundaries:
            crit = self.compute_criticality(boundary, component_graph)
            criticalities.append(crit)
            logger.debug(
                f"[Fusion] boundary={crit.boundary_id} criticality={crit.criticality:.3f} "
                f"(ext={crit.is_external_facing}, cross={crit.crosses_trust_boundary}, "
                f"sensitive={crit.handles_sensitive_data})"
            )

        # Add global/unresolved with minimal criticality
        criticalities.append(BoundaryCriticality(
            boundary_id="global/unresolved",
            criticality=0.15,  # Only base privilege level
            is_external_facing=False,
            crosses_trust_boundary=False,
            handles_sensitive_data=False,
            privilege_level=0.3,
        ))

        return criticalities

    def _aggregate_to_architecture(
        self,
        fused_boundaries: list[FusedBoundaryPosture],
        crit_lookup: dict[str, BoundaryCriticality],
    ) -> list[FusedArchitecturalPosture]:
        """
        Aggregate fused boundary postures → architectural posture per control category.

        Formula:
          arch_posture(C) = α × weighted_avg + (1-α) × worst_critical

        Where:
          weighted_avg = Σ (criticality(B) × posture(B,C)) / Σ criticality(B)
          worst_critical = min(posture(B,C)) for B where B is high-criticality
          High-criticality = is_external OR handles_sensitive OR crosses_boundary
        """
        # Group fused boundary postures by control category
        by_category: dict[str, list[FusedBoundaryPosture]] = defaultdict(list)
        for fbp in fused_boundaries:
            by_category[fbp.control_category.value].append(fbp)

        arch_postures: list[FusedArchitecturalPosture] = []

        for cat_str, boundary_list in by_category.items():
            category = ControlCategory(cat_str)

            # Compute weighted average
            total_weight = 0.0
            weighted_sum = 0.0
            worst_critical = 1.0
            worst_critical_id = ""
            high_crit_count = 0

            for fbp in boundary_list:
                crit = crit_lookup.get(fbp.boundary_id)
                criticality = crit.criticality if crit else 0.15

                total_weight += criticality
                weighted_sum += criticality * fbp.fused_posture

                # Track worst-case among high-criticality boundaries
                is_high_crit = crit and (
                    crit.is_external_facing or
                    crit.handles_sensitive_data or
                    crit.crosses_trust_boundary
                )
                if is_high_crit:
                    high_crit_count += 1
                    if fbp.fused_posture < worst_critical:
                        worst_critical = fbp.fused_posture
                        worst_critical_id = fbp.boundary_id

            weighted_avg = weighted_sum / total_weight if total_weight > 0 else 1.0

            # If no high-crit boundaries contributed, use weighted_avg as worst too
            if worst_critical == 1.0 and high_crit_count == 0:
                worst_critical = weighted_avg

            # Final aggregation: α × avg + (1-α) × worst_critical
            arch_value = ALPHA * weighted_avg + (1 - ALPHA) * worst_critical

            # Confidence: average across boundaries
            avg_confidence = sum(fbp.confidence for fbp in boundary_list) / len(boundary_list)

            # Fusion status counts
            status_counts: dict[str, int] = defaultdict(int)
            for fbp in boundary_list:
                status_counts[fbp.fusion_status.value] += 1

            arch_postures.append(FusedArchitecturalPosture(
                control_category=category,
                posture=round(arch_value, 4),
                confidence=round(avg_confidence, 4),
                weighted_average=round(weighted_avg, 4),
                worst_critical_boundary=round(worst_critical, 4),
                worst_critical_boundary_id=worst_critical_id,
                alpha=ALPHA,
                boundary_count=len(boundary_list),
                high_criticality_boundary_count=high_crit_count,
                fusion_statuses=dict(status_counts),
            ))

            logger.debug(
                f"[Fusion] arch.{cat_str}_posture = {arch_value:.3f} "
                f"(avg={weighted_avg:.3f}, worst_crit={worst_critical:.3f} at {worst_critical_id})"
            )

        return arch_postures
