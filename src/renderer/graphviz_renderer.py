"""Graphviz-based DFD renderer — produces professional-quality diagram output."""

import logging
from pathlib import Path
from typing import Optional

from graphviz import Digraph

from src.dfd.models import DFDBoundary, DFDDataFlow, DFDElement, DFDElementType, DFDModel

logger = logging.getLogger(__name__)


class GraphvizRenderer:
    """
    Renders a DFD model as a professional-quality diagram using Graphviz.

    Produces standard DFD notation:
    - Circles (ellipses) for Processes
    - Parallel lines (box with open sides) for Data Stores
    - Rectangles for External Entities
    - Dashed rectangles for Trust Boundaries
    - Labeled arrows for Data Flows
    - Color coding by threat severity

    Output formats: SVG, PNG, PDF
    """

    # Color palette
    COLORS = {
        "process": "#4a90d9",           # Blue
        "process_public": "#e74c3c",    # Red (public-facing)
        "data_store": "#27ae60",        # Green
        "external_entity": "#f39c12",   # Orange
        "boundary_internal": "#27ae60", # Green
        "boundary_dmz": "#f39c12",      # Orange
        "boundary_external": "#e74c3c", # Red
        "flow_normal": "#555555",       # Dark gray
        "flow_sensitive": "#e74c3c",    # Red
        "flow_encrypted": "#27ae60",    # Green
        "flow_crossing": "#9b59b6",     # Purple
    }

    FONT = "Segoe UI"
    FONT_SIZE = "10"

    def render(
        self,
        dfd_model_data: dict,
        output_path: Path,
        format: str = "svg",
    ) -> Path:
        """
        Render the DFD model to a file.

        Args:
            dfd_model_data: DFD model dictionary
            output_path: Where to save the rendered diagram
            format: Output format (svg, png, pdf)

        Returns:
            Path to the rendered file
        """
        dfd = DFDModel(**dfd_model_data) if isinstance(dfd_model_data, dict) else dfd_model_data

        logger.info(f"Rendering DFD: {dfd.title} ({len(dfd.elements)} elements)")

        # Create the graph
        dot = Digraph(
            name="DFD",
            comment=dfd.title,
            format=format,
            engine="dot",  # Hierarchical layout
        )

        # Global graph attributes
        dot.attr(
            rankdir="TB",
            label=dfd.title,
            labelloc="t",
            fontname=self.FONT,
            fontsize="14",
            pad="0.5",
            nodesep="0.8",
            ranksep="1.0",
            splines="ortho",
            bgcolor="white",
        )

        # Default node attributes
        dot.attr("node", fontname=self.FONT, fontsize=self.FONT_SIZE)
        dot.attr("edge", fontname=self.FONT, fontsize="9")

        # Render trust boundaries as subgraphs (clusters)
        self._render_boundaries(dot, dfd)

        # Render elements not in any boundary
        bounded_elements = set()
        for boundary in dfd.boundaries:
            bounded_elements.update(boundary.element_ids)

        for element in dfd.elements:
            if element.id not in bounded_elements:
                self._render_element(dot, element)

        # Render data flows
        for flow in dfd.data_flows:
            self._render_flow(dot, flow, dfd)

        # Add legend
        self._render_legend(dot)

        # Render to file
        output_stem = str(output_path).rsplit(".", 1)[0] if "." in str(output_path) else str(output_path)
        rendered_path = dot.render(output_stem, cleanup=True)

        logger.info(f"DFD rendered to: {rendered_path}")
        return Path(rendered_path)

    def _render_boundaries(self, dot: Digraph, dfd: DFDModel) -> None:
        """Render trust boundaries as Graphviz subgraph clusters."""
        for boundary in dfd.boundaries:
            boundary_color = self._get_boundary_color(boundary.trust_level)

            with dot.subgraph(name=f"cluster_{boundary.id}") as sub:
                sub.attr(
                    label=f"<<B>{boundary.name}</B><BR/><I>Trust Level: {boundary.trust_level}</I>>",
                    style="dashed",
                    color=boundary_color,
                    penwidth="2",
                    fontname=self.FONT,
                    fontsize="11",
                    labeljust="l",
                    margin="20",
                )

                # Add elements within this boundary
                for element in dfd.elements:
                    if element.id in boundary.element_ids:
                        self._render_element(sub, element)

    def _render_element(self, graph: Digraph, element: DFDElement) -> None:
        """Render a single DFD element with appropriate shape and styling."""
        if element.element_type == DFDElementType.PROCESS:
            self._render_process(graph, element)
        elif element.element_type == DFDElementType.DATA_STORE:
            self._render_data_store(graph, element)
        elif element.element_type == DFDElementType.EXTERNAL_ENTITY:
            self._render_external_entity(graph, element)

    def _render_process(self, graph: Digraph, element: DFDElement) -> None:
        """Render a process (circle/ellipse in DFD notation)."""
        color = self.COLORS["process_public"] if element.is_public_facing else self.COLORS["process"]

        label = self._build_element_label(element)
        tooltip = self._build_tooltip(element)

        graph.node(
            element.id,
            label=label,
            shape="ellipse",
            style="filled",
            fillcolor=f"{color}20",  # Light fill
            color=color,
            penwidth="2",
            tooltip=tooltip,
        )

    def _render_data_store(self, graph: Digraph, element: DFDElement) -> None:
        """Render a data store (parallel lines / cylinder in DFD notation)."""
        label = self._build_element_label(element)
        tooltip = self._build_tooltip(element)

        graph.node(
            element.id,
            label=label,
            shape="cylinder",
            style="filled",
            fillcolor=f"{self.COLORS['data_store']}20",
            color=self.COLORS["data_store"],
            penwidth="2",
            tooltip=tooltip,
        )

    def _render_external_entity(self, graph: Digraph, element: DFDElement) -> None:
        """Render an external entity (rectangle in DFD notation)."""
        label = self._build_element_label(element)
        tooltip = self._build_tooltip(element)

        graph.node(
            element.id,
            label=label,
            shape="box",
            style="filled",
            fillcolor=f"{self.COLORS['external_entity']}20",
            color=self.COLORS["external_entity"],
            penwidth="2",
            tooltip=tooltip,
        )

    def _render_flow(self, graph: Digraph, flow: DFDDataFlow, dfd: DFDModel) -> None:
        """Render a data flow as a labeled arrow."""
        color = self._get_flow_color(flow)
        style = "bold" if flow.crosses_trust_boundary else "solid"
        penwidth = "2" if flow.crosses_trust_boundary else "1.5"

        # Build flow label
        label = self._build_flow_label(flow)

        # Security indicator icons
        decorations = []
        if flow.is_encrypted:
            decorations.append("🔒")
        if flow.is_authenticated:
            decorations.append("🔑")
        if flow.crosses_trust_boundary:
            decorations.append("⚠")

        if decorations:
            label = f"{' '.join(decorations)} {label}"

        graph.edge(
            flow.source_id,
            flow.target_id,
            label=label,
            color=color,
            style=style,
            penwidth=penwidth,
            arrowsize="0.8",
            fontcolor=color,
        )

    def _render_legend(self, dot: Digraph) -> None:
        """Add a legend explaining the diagram notation."""
        with dot.subgraph(name="cluster_legend") as legend:
            legend.attr(
                label="<<B>Legend</B>>",
                style="rounded",
                color="#cccccc",
                fontname=self.FONT,
                fontsize="10",
                margin="10",
            )
            legend.node(
                "legend_process", "Process",
                shape="ellipse", style="filled",
                fillcolor=f"{self.COLORS['process']}20",
                color=self.COLORS["process"], fontsize="8",
            )
            legend.node(
                "legend_store", "Data Store",
                shape="cylinder", style="filled",
                fillcolor=f"{self.COLORS['data_store']}20",
                color=self.COLORS["data_store"], fontsize="8",
            )
            legend.node(
                "legend_external", "External Entity",
                shape="box", style="filled",
                fillcolor=f"{self.COLORS['external_entity']}20",
                color=self.COLORS["external_entity"], fontsize="8",
            )
            legend.node(
                "legend_public", "Public-Facing",
                shape="ellipse", style="filled",
                fillcolor=f"{self.COLORS['process_public']}20",
                color=self.COLORS["process_public"], fontsize="8",
            )

            # Make legend nodes invisible connections
            legend.attr("edge", style="invis")
            legend.edge("legend_process", "legend_store")
            legend.edge("legend_store", "legend_external")
            legend.edge("legend_external", "legend_public")

    # ──── HELPERS ────────────────────────────────────────────────────────

    def _build_element_label(self, element: DFDElement) -> str:
        """Build a multi-line label for an element."""
        lines = [element.name]
        if element.technology:
            lines.append(f"[{element.technology}]")
        return "\\n".join(lines)

    def _build_tooltip(self, element: DFDElement) -> str:
        """Build a tooltip with detailed info."""
        parts = [element.name]
        if element.description:
            parts.append(element.description)
        threat_count = element.metadata.get("threat_count")
        if threat_count:
            parts.append(f"Threats: {threat_count}")
        return " | ".join(parts)

    def _build_flow_label(self, flow: DFDDataFlow) -> str:
        """Build a concise label for a data flow."""
        if flow.label and flow.label != "data":
            # Truncate long labels
            label = flow.label[:40]
            if len(flow.label) > 40:
                label += "..."
            return label
        if flow.protocol:
            return flow.protocol
        return ""

    def _get_flow_color(self, flow: DFDDataFlow) -> str:
        """Determine flow color based on security properties."""
        if flow.data_sensitivity:
            return self.COLORS["flow_sensitive"]
        if flow.crosses_trust_boundary:
            return self.COLORS["flow_crossing"]
        if flow.is_encrypted:
            return self.COLORS["flow_encrypted"]
        return self.COLORS["flow_normal"]

    def _get_boundary_color(self, trust_level: str) -> str:
        """Get color for a trust boundary based on trust level."""
        mapping = {
            "internal": self.COLORS["boundary_internal"],
            "dmz": self.COLORS["boundary_dmz"],
            "external": self.COLORS["boundary_external"],
        }
        return mapping.get(trust_level, "#999999")
