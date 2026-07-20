"""
CausalTM v3 — DAST Sub-DAG (Layer C)

Responsibility:
  - Compute BOUNDARY-SPECIFIC posture from normalized DAST evidence
  - DAST findings carry higher causal strength (0.85-0.90) because
    they represent observed runtime behavior for tested paths
  - One posture score per (boundary, control_category) pair

Causal claim:
  "Runtime-confirmed findings at endpoint E provide strong evidence
   that a control is not enforced at that endpoint's boundary. DAST
   evidence has higher causal strength because it represents observed
   runtime behavior for tested paths — not absolute proof for the
   entire system."

Must NOT:
  - Produce global/architectural posture (that's Layer D's job)
  - Make code-structure claims (DAST is runtime-level only)
  - Consume raw findings (only NormalizedEvidence)
  - Claim proof for untested paths
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

# Severity weights (same scale as SAST for consistency)
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.4,
    Severity.LOW: 0.2,
    Severity.INFORMATIONAL: 0.05,
}

# Calibration constant (same as SAST for cross-source comparability)
K = 3.0


class DASTSubDAGV3(CausalSubDAG):
    """
    v3 DAST Sub-DAG — computes boundary-specific runtime enforcement posture.

    Key differences from SAST sub-DAG:
      - Higher causal strength (0.87 vs 0.70): runtime-observed > code-pattern
      - Findings represent PROVEN runtime behavior for tested paths
      - Does NOT claim coverage of untested paths

    For each (boundary, control_category) pair where evidence exists:
      coverage_gap = Σ w(severity_i) / K
      boundary_posture = max(0, 1 - coverage_gap)
    """

    def __init__(self):
        self._evidence: list[NormalizedEvidence] = []
        self._grouped: dict[tuple[str, str], list[NormalizedEvidence]] = {}
        self._built = False

    def source_type(self) -> SourceType:
        return SourceType.DAST

    def causal_strength(self) -> float:
        """DAST: observed runtime behavior for tested paths."""
        return 0.87

    def build(self, evidence: list[NormalizedEvidence]) -> None:
        """
        Build the sub-DAG from normalized DAST evidence.

        Groups evidence by (boundary_id, control_category).
        Only accepts evidence from DAST source type.
        """
        self._evidence = [e for e in evidence if e.source_type == SourceType.DAST]

        # Group by (boundary_id, control_category)
        self._grouped = defaultdict(list)
        unclassified = 0

        for ev in self._evidence:
            boundary_id = ev.boundary_assignment.boundary_id
            category = ev.control_category

            if category is None:
                unclassified += 1
                # DAST findings without classification default to validation
                category = ControlCategory.VALIDATION

            key = (boundary_id, category.value)
            self._grouped[key].append(ev)

        self._built = True

        logger.info(
            f"[DAST Sub-DAG v3] Built from {len(self._evidence)} evidence items. "
            f"Groups: {len(self._grouped)} (boundary×category pairs). "
            f"Unclassified: {unclassified}"
        )

    def compute_boundary_postures(self) -> list[BoundaryPosture]:
        """
        Compute posture for each (boundary, control_category) pair.

        Same formula as SAST but with higher causal_strength,
        reflecting that DAST findings are runtime-confirmed.
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

            # Component from first finding's boundary assignment
            component_id = findings[0].boundary_assignment.component_id

            # Confidence from boundary assignments
            avg_confidence = sum(
                ev.boundary_assignment.confidence for ev in findings
            ) / len(findings)

            # Evidence details
            evidence_ids = [ev.id for ev in findings]
            cwes = [ev.cwe_id for ev in findings if ev.cwe_id]

            # Summary
            severity_counts = defaultdict(int)
            for ev in findings:
                severity_counts[ev.severity.value] += 1
            severity_str = ", ".join(f"{count} {sev}" for sev, count in severity_counts.items())

            posture = BoundaryPosture(
                boundary_id=boundary_id,
                component_id=component_id,
                control_category=category,
                source_type=SourceType.DAST,
                posture=round(posture_value, 4),
                causal_strength=self.causal_strength(),
                contributing_evidence_ids=evidence_ids,
                evidence_count=len(findings),
                weighted_deficit=round(weighted_deficit, 4),
                confidence=round(avg_confidence, 4),
                boundary_assignment_priority=findings[0].boundary_assignment.priority,
                coverage_fraction=None,  # DAST coverage tracking is future enhancement
                evidence_summary=[
                    f"{len(findings)} {category.value} DAST findings ({severity_str})",
                    f"CWEs: {', '.join(cwes)}" if cwes else "No CWE IDs",
                    f"Weighted deficit: {weighted_deficit:.2f} / {K:.1f} (posture: {posture_value:.1%})",
                    f"Runtime-confirmed at tested endpoints",
                ],
            )

            postures.append(posture)

            logger.debug(
                f"[DAST v3] boundary={boundary_id} category={category.value} "
                f"findings={len(findings)} deficit={weighted_deficit:.2f} "
                f"posture={posture_value:.3f} (causal_strength={self.causal_strength()})"
            )

        logger.info(
            f"[DAST Sub-DAG v3] Computed {len(postures)} boundary postures. "
            f"Lowest: {min((p.posture for p in postures), default=1.0):.2f}"
        )

        return postures
