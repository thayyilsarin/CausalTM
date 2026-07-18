"""
Report Generator — produces threat model reports from scan results.

Supports multiple output formats:
- HTML (rich, interactive, embeds diagram)
- Markdown (portable, version-control friendly)
- JSON (machine-readable, for integrations)
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.core.config import get_config
from src.core.exceptions import ReportError

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates threat model reports from scan context.

    Uses Jinja2 templates for HTML/Markdown output and provides
    structured JSON for programmatic consumption.
    """

    def __init__(self, templates_dir: Optional[Path] = None):
        self.templates_dir = templates_dir or Path(__file__).parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(
        self,
        scan_context,
        output_path: Path,
        format: str = "html",
    ) -> Path:
        """
        Generate a threat model report.

        Args:
            scan_context: ScanContext object with all scan data
            output_path: Where to write the report
            format: Output format (html, markdown, json)

        Returns:
            Path to the generated report file
        """
        logger.info(f"Generating {format} report: {output_path}")

        # Build template context from scan data
        context = self._build_context(scan_context)

        if format == "html":
            return self._render_html(context, output_path)
        elif format == "markdown":
            return self._render_markdown(context, output_path)
        elif format == "json":
            return self._render_json(context, output_path)
        else:
            raise ReportError(f"Unsupported format: {format}")

    def generate_from_data(
        self,
        dfd_model: dict,
        threats: list[dict],
        causal_result: Optional[dict] = None,
        diagram_svg: Optional[str] = None,
        project_name: str = "Unknown Project",
        scan_id: str = "manual",
        output_path: Optional[Path] = None,
        format: str = "html",
    ) -> str:
        """
        Generate a report directly from data dictionaries.

        This is the preferred method for standalone usage without
        a full scan pipeline context.

        Args:
            dfd_model: DFD model dictionary
            threats: List of threat dictionaries
            causal_result: Optional causal analysis output
            diagram_svg: Optional SVG string of rendered DFD
            project_name: Name of the project
            scan_id: Scan identifier
            output_path: Optional file path to write (returns string if None)
            format: Output format

        Returns:
            Generated report content as string, or path if output_path given
        """
        context = self._build_context_from_data(
            dfd_model=dfd_model,
            threats=threats,
            causal_result=causal_result,
            diagram_svg=diagram_svg,
            project_name=project_name,
            scan_id=scan_id,
        )

        if format == "html":
            content = self._render_html_string(context)
        elif format == "markdown":
            content = self._render_markdown_string(context)
        elif format == "json":
            content = json.dumps(context, indent=2, default=str)
        else:
            raise ReportError(f"Unsupported format: {format}")

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")
            logger.info(f"Report written to: {output_path}")
            return str(output_path)

        return content

    def _build_context(self, scan_context) -> dict:
        """Build Jinja2 template context from a ScanContext object."""
        threats = scan_context.threats or []
        causal_result = scan_context.causal_result or {}

        # Read diagram SVG if available
        diagram_svg = None
        if scan_context.diagram_path and scan_context.diagram_path.exists():
            try:
                diagram_svg = scan_context.diagram_path.read_text(encoding="utf-8")
            except Exception as e:
                logger.warning(f"Could not read diagram: {e}")

        return self._build_context_from_data(
            dfd_model=scan_context.component_graph or {},
            threats=threats,
            causal_result=causal_result,
            diagram_svg=diagram_svg,
            project_name=scan_context.request.project_name or "Unknown",
            scan_id=scan_context.scan_id,
            branch=scan_context.request.branch,
        )

    def _build_context_from_data(
        self,
        dfd_model: dict,
        threats: list[dict],
        causal_result: Optional[dict] = None,
        diagram_svg: Optional[str] = None,
        project_name: str = "Unknown",
        scan_id: str = "manual",
        branch: str = "main",
    ) -> dict:
        """Build template context from raw data dictionaries."""
        causal_result = causal_result or {}

        # Categorize threats by STRIDE
        stride_categories = self._group_threats_by_stride(threats)

        # Count severities
        severity_counts = self._count_by_field(threats, "severity")
        critical_count = severity_counts.get("Critical", 0)
        high_count = severity_counts.get("High", 0)
        medium_count = severity_counts.get("Medium", 0)

        # Calculate risk score
        risk_score = self._calculate_risk_score(threats)
        risk_rating_class = self._risk_rating_class(risk_score)

        # Extract components from DFD model
        components = dfd_model.get("elements", [])

        # Extract causal insights
        attack_paths = self._format_attack_paths(causal_result.get("attack_paths", {}))
        counterfactuals = causal_result.get("counterfactuals", [])
        confounders = causal_result.get("confounders", [])
        mediators = causal_result.get("mediators", [])

        config = get_config()

        return {
            "title": f"{project_name} — Threat Model Report",
            "project_name": project_name,
            "scan_id": scan_id,
            "branch": branch,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "version": config.version,
            # Executive summary
            "risk_score": risk_score,
            "risk_rating_class": risk_rating_class,
            "total_threats": len(threats),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "components_count": len(components),
            "attack_paths_count": len(attack_paths),
            # Diagram
            "diagram_svg": diagram_svg,
            # Components
            "components": components,
            # Threats by STRIDE category
            "stride_categories": stride_categories,
            # All threats (flat)
            "threats": threats,
            # Causal analysis
            "attack_paths": attack_paths,
            "counterfactuals": counterfactuals,
            "confounders": confounders,
            "mediators": mediators,
            # Stats
            "graph_stats": causal_result.get("graph_stats", {}),
        }

    def _render_html(self, context: dict, output_path: Path) -> Path:
        """Render HTML report to file."""
        content = self._render_html_string(context)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path

    def _render_html_string(self, context: dict) -> str:
        """Render HTML report to string."""
        try:
            template = self.env.get_template("report.html.j2")
            return template.render(**context)
        except Exception as e:
            raise ReportError(f"Failed to render HTML template: {e}")

    def _render_markdown(self, context: dict, output_path: Path) -> Path:
        """Render Markdown report to file."""
        content = self._render_markdown_string(context)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        return output_path

    def _render_markdown_string(self, context: dict) -> str:
        """Render Markdown report to string."""
        try:
            template = self.env.get_template("report.md.j2")
            return template.render(**context)
        except Exception as e:
            # Fallback: generate markdown programmatically
            return self._generate_markdown_fallback(context)

    def _render_json(self, context: dict, output_path: Path) -> Path:
        """Render JSON report to file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(context, indent=2, default=str),
            encoding="utf-8",
        )
        return output_path

    def _generate_markdown_fallback(self, context: dict) -> str:
        """Generate markdown report without template (fallback)."""
        lines = []
        lines.append(f"# {context['title']}")
        lines.append("")
        lines.append(f"**Generated:** {context['generated_at']}")
        lines.append(f"**Scan ID:** {context['scan_id']}")
        lines.append(f"**Branch:** {context['branch']}")
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Risk Score:** {context['risk_score']:.1f} / 10")
        lines.append(f"- **Total Threats:** {context['total_threats']}")
        lines.append(f"- **Critical:** {context['critical_count']}")
        lines.append(f"- **High:** {context['high_count']}")
        lines.append(f"- **Medium:** {context['medium_count']}")
        lines.append(f"- **Components:** {context['components_count']}")
        lines.append(f"- **Attack Paths:** {context['attack_paths_count']}")
        lines.append("")

        # Threats
        lines.append("## STRIDE Threat Catalog")
        lines.append("")
        for category in context.get("stride_categories", []):
            lines.append(f"### {category['name']} ({len(category['threats'])} threats)")
            lines.append("")
            for threat in category["threats"]:
                severity = threat.get("severity", "Medium")
                title = threat.get("title", "Unknown")
                element = threat.get("element_name", "")
                lines.append(f"- **[{severity}]** {title} (Element: {element})")
                mitigations = threat.get("mitigations", [])
                for mit in mitigations[:2]:
                    lines.append(f"  - Mitigation: {mit}")
            lines.append("")

        # Attack paths
        attack_paths = context.get("attack_paths", [])
        if attack_paths:
            lines.append("## Attack Paths")
            lines.append("")
            for path in attack_paths[:10]:
                node_names = path.get("node_names", [])
                score = path.get("score", 0)
                lines.append(f"- **Score {score:.2f}:** {' -> '.join(node_names)}")
            lines.append("")

        # Counterfactuals
        counterfactuals = context.get("counterfactuals", [])
        if counterfactuals:
            lines.append("## Mitigation Recommendations (Counterfactual Analysis)")
            lines.append("")
            for cf in counterfactuals:
                lines.append(f"- **{cf.get('intervention_name', '')}**: {cf.get('recommendation', '')}")
            lines.append("")

        lines.append("---")
        lines.append(f"*Generated by CausalTM v{context.get('version', '0.1.0')}*")

        return "\n".join(lines)

    # ──── HELPERS ────────────────────────────────────────────────────────

    def _group_threats_by_stride(self, threats: list[dict]) -> list[dict]:
        """Group threats by STRIDE category for template rendering."""
        categories_order = [
            "Spoofing",
            "Tampering",
            "Repudiation",
            "Information Disclosure",
            "Denial of Service",
            "Elevation of Privilege",
        ]

        grouped: dict[str, list] = {cat: [] for cat in categories_order}

        for threat in threats:
            category = threat.get("category", "Unknown")
            if category in grouped:
                grouped[category].append(threat)

        return [
            {"name": cat, "threats": grouped[cat]}
            for cat in categories_order
            if grouped[cat]  # Only include categories with threats
        ]

    def _count_by_field(self, threats: list[dict], field: str) -> dict[str, int]:
        """Count threats by a given field value."""
        counts: dict[str, int] = {}
        for threat in threats:
            value = threat.get(field, "Unknown")
            counts[value] = counts.get(value, 0) + 1
        return counts

    def _calculate_risk_score(self, threats: list[dict]) -> float:
        """Calculate overall risk score (0-10)."""
        if not threats:
            return 0.0

        severity_weights = {
            "Critical": 10.0,
            "High": 7.0,
            "Medium": 4.0,
            "Low": 2.0,
            "Informational": 0.5,
        }

        total = sum(
            severity_weights.get(t.get("severity", "Medium"), 4.0)
            * t.get("confidence", 0.7)
            for t in threats
        )

        # Normalize: scale based on number of threats, capped at 10
        normalized = total / max(len(threats), 1) * 1.5
        return min(10.0, round(normalized, 1))

    def _risk_rating_class(self, score: float) -> str:
        """Map risk score to CSS class for color coding."""
        if score >= 8.0:
            return "critical"
        elif score >= 6.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        return "low"

    def _format_attack_paths(self, attack_paths_data) -> list[dict]:
        """Format attack path data for template rendering."""
        if isinstance(attack_paths_data, dict):
            # Convert element_scores format to list of paths
            paths = []
            for element_id, data in attack_paths_data.items():
                if isinstance(data, dict) and data.get("score", 0) > 0:
                    paths.append({
                        "node_names": [element_id],
                        "score": data.get("score", 0),
                        "crosses_trust_boundary": False,
                    })
            return sorted(paths, key=lambda p: p["score"], reverse=True)[:10]
        elif isinstance(attack_paths_data, list):
            return attack_paths_data[:10]
        return []
