"""
CausalTM v3 — SAST Sub-DAG (Layer C)

Responsibility:
  - Compute BOUNDARY-SPECIFIC posture from normalized SAST evidence
  - One posture score per (boundary, control_category) pair
  - Uses severity-weighted deficit formula

Causal claim:
  "Multiple code-level findings of type X at boundary B provide evidence
   that control X has incomplete coverage at boundary B. The degree of
   incompleteness is proportional to the severity and count of findings."

Must NOT:
  - Produce global/architectural posture (that's Layer D's job)
  - Make runtime claims (SAST is code-level only)
  - Consume raw findings (only NormalizedEvidence)
"""

import logging
from collections import defaultdict

from src.causal.v3.interfaces import CausalSubDAG
from src.causal.v3.models import (
    BoundaryAssignmentPriority,
    BoundaryPosture,
    ControlCategory,
    NormalizedEvidence,
    Severity,
    SourceType,
)

logger = logging.getLogger(__name__)

# Severity weights for deficit calculation
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.4,
    Severity.LOW: 0.2,
    Severity.INFORMATIONAL: 0.05,
}

# Calibration constant: 3 Critical findings bring posture to zero
K = 3.0


class SASTSubDAGV3(CausalSubDAG):
    """
    v3 SAST Sub-DAG — computes boundary-specific code-level posture.

    For each (boundary, control_category) pair where evidence exists:
      coverage_gap = Σ w(severity_i) / K
      boundary_posture = max(0, 1 - coverage_gap)

    Boundaries where NO evidence exists are NOT included in output
    (absence of evidence ≠ evidence of absence).
    """

    def __init__(self):
        self._evidence: list[NormalizedEvidence] = []
        self._grouped: dict[tuple[str, str], list[NormalizedEvidence]] = {}
        self._built = False

    def source_type(self) -> SourceType:
        return SourceType.SAST

    def causal_strength(self) -> float:
        """SAST: code patterns, may not be exploitable at runtime."""
        return 0.70

    def build(self, evidence: list[NormalizedEvidence]) -> None:
        """
        Build the sub-DAG from normalized evidence.

        Groups evidence by (boundary_id, control_category) for posture computation.
        Only accepts evidence from SAST source type.
        """
        self._evidence = [e for e in evidence if e.source_type == SourceType.SAST]

        # Group by (boundary_id, control_category)
        self._grouped = defaultdict(list)
        unclassified = 0

        for ev in self._evidence:
            boundary_id = ev.boundary_assignment.boundary_id
            category = ev.control_category

            if category is None:
                unclassified += 1
                # Default unclassified to validation (most common SAST finding type)
                category = ControlCategory.VALIDATION

            key = (boundary_id, category.value)
            self._grouped[key].append(ev)

        self._built = True

        logger.info(
            f"[SAST Sub-DAG v3] Built from {len(self._evidence)} evidence items. "
            f"Groups: {len(self._grouped)} (boundary×category pairs). "
            f"Unclassified: {unclassified}"
        )

    def compute_boundary_postures(self) -> list[BoundaryPosture]:
        """
        Compute posture for each (boundary, control_category) pair.

        Formula:
          coverage_gap(B, C) = Σ w(severity_i) / K
          boundary_posture(B, C) = max(0, 1 - coverage_gap(B, C))

        Returns BoundaryPosture objects only for pairs where evidence EXISTS.
        """
        if not self._built:
            raise RuntimeError("Must call build() before compute_boundary_postures()")

        postures: list[BoundaryPosture] = []

        for (boundary_id, category_str), findings in self._grouped.items():
            category = ControlCategory(category_str)

            # Compute severity-weighted deficit
            weighted_deficit = 0.0
            for ev in findings:
                weight = SEVERITY_WEIGHTS.get(ev.severity, 0.4)
                weighted_deficit += weight

            # Posture = max(0, 1 - deficit/K)
            posture_value = max(0.0, 1.0 - (weighted_deficit / K))

            # Determine component_id (use first finding's assignment)
            component_id = findings[0].boundary_assignment.component_id

            # Compute confidence from boundary assignment priorities
            avg_confidence = sum(
                ev.boundary_assignment.confidence for ev in findings
            ) / len(findings)

            # Collect evidence IDs and CWEs
            evidence_ids = [ev.id for ev in findings]
            cwes = [ev.cwe_id for ev in findings if ev.cwe_id]

            # Build evidence summary
            severity_counts = defaultdict(int)
            for ev in findings:
                severity_counts[ev.severity.value] += 1
            severity_str = ", ".join(f"{count} {sev}" for sev, count in severity_counts.items())

            posture = BoundaryPosture(
                boundary_id=boundary_id,
                component_id=component_id,
                control_category=category,
                source_type=SourceType.SAST,
                posture=round(posture_value, 4),
                causal_strength=self.causal_strength(),
                contributing_evidence_ids=evidence_ids,
                evidence_count=len(findings),
                weighted_deficit=round(weighted_deficit, 4),
                confidence=round(avg_confidence, 4),
                boundary_assignment_priority=findings[0].boundary_assignment.priority,
                coverage_fraction=None,  # SAST coverage not yet tracked
                evidence_summary=[
                    f"{len(findings)} {category.value} findings ({severity_str})",
                    f"CWEs: {', '.join(cwes)}" if cwes else "No CWE IDs",
                    f"Weighted deficit: {weighted_deficit:.2f} / {K:.1f} (posture: {posture_value:.1%})",
                ],
            )

            postures.append(posture)

            logger.debug(
                f"[SAST v3] boundary={boundary_id} category={category.value} "
                f"findings={len(findings)} deficit={weighted_deficit:.2f} "
                f"posture={posture_value:.3f}"
            )

        logger.info(
            f"[SAST Sub-DAG v3] Computed {len(postures)} boundary postures. "
            f"Lowest: {min((p.posture for p in postures), default=1.0):.2f}"
        )

        return postures
