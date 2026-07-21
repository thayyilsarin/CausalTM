"""
CausalTM v3 — Report Renderer (Layer H)

Generates polished Markdown reports from CausalTMv3Result.
This is the PRESENTATION layer — separate from the evaluation artifact.

Outputs:
  - Executive summary with risk score
  - Architecture posture table (boundary-specific)
  - STRIDE threat catalog with evidence chains
  - Attack paths table
  - Remediation roadmap
  - What-if analysis results
  - Methodology and confidence notes

Must NOT:
  - Perform any computation or inference
  - Modify the result object
  - Hide uncertainty or silently aggregate
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.causal.v3.models import (
    CausalTMv3Result,
    FusedArchitecturalPosture,
    Severity,
    StrideCategory,
    StrideThreat,
    WhatIfResult,
)


class V3ReportRenderer:
    """
    Renders CausalTMv3Result into polished Markdown reports.

    Designed for human consumption: clear, structured, traceable.
    Every claim in the report traces back to evidence.
    """

    def render_markdown(
        self,
        result: CausalTMv3Result,
        project_name: str = "Unknown Project",
        attack_paths: Optional[list[dict]] = None,
        what_if_results: Optional[list[WhatIfResult]] = None,
    ) -> str:
        """Render complete markdown report."""
        sections = []

        sections.append(self._render_title(project_name))
        sections.append(self._render_executive_summary(result))
        sections.append(self._render_architectural_posture(result))
        sections.append(self._render_stride_threats(result))
        if attack_paths:
            sections.append(self._render_attack_paths(attack_paths))
        if result.roadmap:
            sections.append(self._render_roadmap(result))
        if what_if_results:
            sections.append(self._render_what_if(what_if_results))
        sections.append(self._render_methodology_notes(result))
        sections.append(self._render_footer())

        return "\n\n".join(sections)

    def render_to_file(
        self,
        result: CausalTMv3Result,
        output_path: Path,
        project_name: str = "Unknown Project",
        attack_paths: Optional[list[dict]] = None,
        what_if_results: Optional[list[WhatIfResult]] = None,
    ) -> Path:
        """Render and write to file."""
        content = self.render_markdown(result, project_name, attack_paths, what_if_results)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path

    # ══════════════════════════════════════════════════════════════════════
    # SECTION RENDERERS
    # ══════════════════════════════════════════════════════════════════════

    def _render_title(self, project_name: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return (
            f"# {project_name} — CausalTM v3 Threat Model Report\n\n"
            f"**Generated:** {timestamp}  \n"
            f"**Engine:** CausalTM v3 (Federated Structural Causal Model)  \n"
            f"**Approach:** Boundary-specific posture with hybrid STRIDE classification"
        )

    def _render_executive_summary(self, result: CausalTMv3Result) -> str:
        risk_emoji = {"Critical": "!!!", "High": "!!", "Medium": "!", "Low": ".", "Minimal": ""}
        rating = result.risk_rating

        lines = [
            "## Executive Summary",
            "",
            f"| Metric | Value |",
            f"|---|---|",
            f"| Overall Risk | **{result.overall_risk:.3f}** ({rating}) |",
            f"| STRIDE Threats | {result.total_threats} |",
            f"| Evidence Ingested | {result.evidence_count} findings |",
            f"| Boundaries Assessed | {result.boundary_count} ({', '.join(result.boundaries_assessed)}) |",
            f"| Uncertain Divergences | {result.uncertain_divergences} |",
            f"| Average Confidence | {result.average_confidence:.0%} |",
        ]
        return "\n".join(lines)

    def _render_architectural_posture(self, result: CausalTMv3Result) -> str:
        lines = [
            "## Architectural Security Posture",
            "",
            "Each control category shows the fused posture (aggregated across all boundaries "
            "with worst-case adjustment for critical boundaries).",
            "",
            "| Control Category | Posture | Confidence | Worst Critical Boundary | Boundary ID |",
            "|---|---|---|---|---|",
        ]

        for ap in sorted(result.fused_postures, key=lambda x: x.posture):
            status = self._posture_status(ap.posture)
            lines.append(
                f"| {ap.control_category.value.title()} | "
                f"**{ap.posture:.1%}** {status} | "
                f"{ap.confidence:.0%} | "
                f"{ap.worst_critical_boundary:.1%} | "
                f"{ap.worst_critical_boundary_id} |"
            )

        # Posture bar chart
        lines.extend(["", "### Posture Visualization", "```"])
        for ap in sorted(result.fused_postures, key=lambda x: x.posture):
            bar_len = int(ap.posture * 30)
            bar = "█" * bar_len + "░" * (30 - bar_len)
            lines.append(f"  {ap.control_category.value:<12} |{bar}| {ap.posture:.0%}")
        lines.append(f"  {'THRESHOLD':<12} |{'─' * 25}{'┤'}{'─' * 4}| 85%")
        lines.append("```")

        return "\n".join(lines)

    def _render_stride_threats(self, result: CausalTMv3Result) -> str:
        lines = [
            "## STRIDE Threat Catalog",
            "",
            f"**{result.total_threats} threats** identified via hybrid classification "
            f"(rule-based patterns + posture thresholds).",
            "",
        ]

        # STRIDE posture table
        lines.extend([
            "### STRIDE Category Posture",
            "",
            "| Category | Posture | Threat Level |",
            "|---|---|---|",
        ])
        for cat, posture in sorted(result.stride_posture_per_category.items(), key=lambda x: x[1]):
            level = self._posture_to_level(posture)
            lines.append(f"| {cat} | {posture:.1%} | {level} |")

        lines.append("")

        # Individual threats
        lines.append("### Threat Details")
        lines.append("")

        for threat in result.threats:
            lines.extend(self._render_single_threat(threat))
            lines.append("")

        return "\n".join(lines)

    def _render_single_threat(self, threat: StrideThreat) -> list[str]:
        """Render a single threat with full evidence chain."""
        lines = [
            f"#### [{threat.severity.value}] {threat.category.value}",
            "",
            f"**Classification:** {threat.classification_method.value}  ",
            f"**Triggering Posture:** {threat.triggering_posture_value:.3f} "
            f"(threshold: {threat.posture_threshold_used})  ",
            f"**Confidence:** {threat.confidence:.0%}  ",
            f"**Affected Boundaries:** {', '.join(threat.affected_boundaries) if threat.affected_boundaries else 'Global'}  ",
            f"**Layers Contributing:** {threat.layers_contributing}  ",
            "",
            f"> {threat.description}",
            "",
        ]

        # Evidence chain
        if threat.evidence:
            lines.append("**Evidence Chain:**")
            for ev in threat.evidence:
                lines.append(
                    f"- [{ev.source_type.value.upper()}] Boundary `{ev.boundary_id}`: "
                    f"posture {ev.boundary_posture:.2f} "
                    f"(confidence: {ev.source_confidence:.0%}, "
                    f"status: {ev.fusion_status.value if ev.fusion_status else 'N/A'})"
                )
            lines.append("")

        # CWEs
        if threat.traced_cwes:
            lines.append(f"**Traced CWEs:** {', '.join(threat.traced_cwes)}")
            lines.append("")

        # Remediation
        lines.extend([
            "**Remediation:**",
            f"- Architecture: {threat.remediation_architecture}",
            f"- Code: {threat.remediation_code}",
            f"- Config: {threat.remediation_config}",
        ])

        return lines

    def _render_attack_paths(self, attack_paths: list[dict]) -> str:
        lines = [
            "## Attack Paths",
            "",
            "Concrete multi-hop paths from external entry points to sensitive data stores, "
            "scored by exploitability (boundary crossings, encryption gaps, auth gaps).",
            "",
            "| Score | Attack Path | Boundary Crossings | Unencrypted Hops | Target Sensitivity |",
            "|---|---|---|---|---|",
        ]

        for path in attack_paths[:10]:
            node_names = path.get("node_names", [])
            path_str = " → ".join(node_names) if node_names else "(path unavailable)"
            score = path.get("score", 0)
            crossings = path.get("boundary_crossings", 0)
            unencrypted = path.get("unencrypted_hops", 0)
            sensitivity = ", ".join(path.get("target_sensitivity", [])) or "—"
            lines.append(f"| {score:.3f} | {path_str} | {crossings} | {unencrypted} | {sensitivity} |")

        return "\n".join(lines)

    def _render_roadmap(self, result: CausalTMv3Result) -> str:
        if not result.roadmap:
            return ""

        lines = [
            "## Remediation Roadmap",
            "",
            f"**{result.roadmap.total_steps} steps** to reduce risk from "
            f"{result.roadmap.initial_risk:.3f} to {result.roadmap.projected_final_risk:.3f}.",
            "",
            "| Step | Fix | Category | Boundary | Current → Target | Risk Reduction |",
            "|---|---|---|---|---|---|",
        ]

        for step in result.roadmap.steps:
            lines.append(
                f"| {step.step_number} | {step.name} | "
                f"{step.target_posture_category.value} | "
                f"{step.target_boundary_name or step.target_boundary_id} | "
                f"{step.current_posture:.0%} → {step.target_posture:.0%} | "
                f"{step.total_risk_reduction:.3f} |"
            )

        return "\n".join(lines)

    def _render_what_if(self, what_if_results: list[WhatIfResult]) -> str:
        lines = [
            "## What-If Analysis",
            "",
            "Predicted effects of candidate interventions (counterfactual reasoning).",
            "",
        ]

        for wif in what_if_results:
            lines.extend([
                f"### {wif.description}",
                "",
                f"- **Variable:** {wif.intervention_variable}",
                f"- **Change:** {wif.old_value:.3f} → {wif.new_value:.3f}",
                f"- **Risk:** {wif.risk_before:.3f} → {wif.risk_after:.3f} "
                f"(reduction: {wif.risk_before - wif.risk_after:.3f})",
                "",
            ])

            if wif.propagated_effects:
                lines.append("**Cross-layer effects:**")
                for eff in wif.propagated_effects:
                    lines.append(
                        f"- {eff.affected_variable}: +{eff.predicted_change:.3f} "
                        f"(via {eff.rule_applied}, assumes: {', '.join(eff.assumptions_required)})"
                    )
                lines.append("")

            if wif.stride_changes:
                lines.append("**STRIDE improvements:**")
                for cat, delta in sorted(wif.stride_changes.items(), key=lambda x: -x[1]):
                    lines.append(f"- {cat}: +{delta:.3f}")
                lines.append("")

        return "\n".join(lines)

    def _render_methodology_notes(self, result: CausalTMv3Result) -> str:
        lines = [
            "## Methodology Notes",
            "",
            "- **Causal claim:** Findings provide evidence of control coverage gaps at specific "
            "boundaries. Posture gaps, combined with boundary context and exposure, determine "
            "STRIDE threat existence.",
            "- **Posture formula:** `P = max(0, 1 - Σ w(severity) / K)` where K=3.0. "
            "Three Critical findings at a boundary bring posture to zero.",
            "- **Aggregation:** `arch_posture = 0.6 × weighted_avg + 0.4 × worst_critical_boundary`. "
            "Prevents dilution of severe local risk.",
            "- **Confidence:** Single-source findings carry 0.7x confidence penalty. "
            "Corroborated findings (SAST + DAST agree) receive confidence boost.",
            f"- **Uncertain divergences:** {result.uncertain_divergences} cases where sources disagreed "
            f"(flagged, not silently resolved).",
            "- **Hybrid STRIDE:** Rule-based patterns (posture + architectural context) take priority; "
            "posture-derived thresholds fill remaining categories.",
            "- **Traceability:** Every threat traces back through 4 abstraction layers: "
            "finding → boundary posture → fused architectural posture → STRIDE classification.",
        ]
        return "\n".join(lines)

    def _render_footer(self) -> str:
        return (
            "---\n\n"
            "*Generated by CausalTM v3 — Federated Structural Causal Model for STRIDE Threat Modeling*"
        )

    # ══════════════════════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════════════════════

    def _posture_status(self, posture: float) -> str:
        if posture < 0.30:
            return "(CRITICAL)"
        elif posture < 0.50:
            return "(HIGH RISK)"
        elif posture < 0.70:
            return "(MEDIUM)"
        elif posture < 0.85:
            return "(LOW)"
        return "(OK)"

    def _posture_to_level(self, posture: float) -> str:
        if posture < 0.30:
            return "Critical"
        elif posture < 0.50:
            return "High"
        elif posture < 0.70:
            return "Medium"
        elif posture < 0.85:
            return "Low"
        return "None (secure)"
