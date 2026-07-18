"""
Causal Graph Renderer — Renders sub-graphs and master DAG as diagrams.

Produces separate SVG diagrams for:
1. SAST Sub-Graph (code-level causal relationships)
2. DAST Sub-Graph (runtime-level causal relationships)
3. Repo Sub-Graph (architecture-level causal relationships)
4. Master DAG (cross-layer causal reasoning)
5. Causal Attack Graph (concrete attack paths)

Each diagram uses distinct visual encoding:
- Node shapes by type (vulnerability, component, condition, impact)
- Edge colors by relationship type (enables, causes, influences, mitigates)
- Edge thickness by causal strength
"""

import logging
from pathlib import Path
from typing import Optional

from graphviz import Digraph

logger = logging.getLogger(__name__)


class CausalGraphRenderer:
    """Renders causal sub-graphs and master DAG as Graphviz diagrams."""

    # Node colors by type
    NODE_COLORS = {
        "vulnerability": "#e74c3c",       # Red
        "confirmed_vulnerability": "#9b2335",  # Dark red
        "component": "#4a90d9",           # Blue
        "data_store": "#27ae60",          # Green
        "external_entity": "#f39c12",     # Orange
        "condition": "#9b59b6",           # Purple
        "impact": "#2c3e50",             # Dark
        "impact_potential": "#2c3e50",    # Dark
        "category": "#7f8c8d",           # Gray
        "cwe_category": "#e67e22",       # Dark orange
        "root_cause": "#c0392b",         # Dark red
        "coverage": "#16a085",           # Teal
        "endpoint": "#3498db",           # Light blue
        "exposure_evidence": "#8e44ad",  # Purple
        "analysis": "#95a5a6",           # Light gray
        "trust_boundary": "#bdc3c7",     # Silver
        # Master DAG specific
        "edge_node": "#3498db",          # Blue
        "intermediate": "#e67e22",       # Orange
        "output": "#e74c3c",             # Red
    }

    # Node shapes by type
    NODE_SHAPES = {
        "vulnerability": "octagon",
        "confirmed_vulnerability": "doubleoctagon",
        "component": "ellipse",
        "data_store": "cylinder",
        "external_entity": "box",
        "condition": "diamond",
        "impact": "house",
        "impact_potential": "house",
        "category": "box",
        "cwe_category": "box",
        "root_cause": "hexagon",
        "coverage": "parallelogram",
        "endpoint": "circle",
        "exposure_evidence": "diamond",
        "analysis": "note",
        "trust_boundary": "box3d",
        # Master DAG
        "edge_node": "ellipse",
        "intermediate": "box",
        "output": "doubleoctagon",
    }

    # Edge colors by type
    EDGE_COLORS = {
        "enables": "#e74c3c",           # Red
        "causes": "#c0392b",            # Dark red
        "leads_to": "#e67e22",          # Orange
        "influences": "#9b59b6",        # Purple
        "mitigates": "#27ae60",         # Green
        "connects_to": "#3498db",       # Blue
        "data_flow": "#3498db",         # Blue
        "classified_as": "#7f8c8d",     # Gray
        "indicates": "#f39c12",         # Yellow
        "affects": "#e74c3c",           # Red
        "missing_in": "#e74c3c",        # Red
        "proves": "#27ae60",            # Green
        "contributes_to": "#3498db",    # Blue
        "determines": "#e67e22",        # Orange
        "handles_sensitive_data": "#9b59b6",  # Purple
    }

    FONT = "Segoe UI"

    def render_subgraph(
        self,
        subgraph,
        title: str,
        output_path: Path,
        format: str = "svg",
    ) -> Optional[Path]:
        """
        Render a causal sub-graph as a diagram.

        Args:
            subgraph: A CausalSubGraph instance (SAST, DAST, or Repo)
            title: Diagram title
            output_path: Where to save
            format: svg, png, pdf

        Returns:
            Path to rendered file, or None on failure
        """
        try:
            dot = Digraph(
                name="CausalSubGraph",
                comment=title,
                format=format,
                engine="dot",
            )

            dot.attr(
                rankdir="TB",
                label=f"<<B>{title}</B><BR/><I>Nodes: {subgraph.graph.number_of_nodes()} | Edges: {subgraph.graph.number_of_edges()}</I>>",
                labelloc="t",
                fontname=self.FONT,
                fontsize="14",
                pad="0.5",
                nodesep="0.6",
                ranksep="0.8",
                bgcolor="white",
            )

            dot.attr("node", fontname=self.FONT, fontsize="9")
            dot.attr("edge", fontname=self.FONT, fontsize="8")

            # Add nodes
            for node_id, attrs in subgraph._nodes.items():
                node_type = attrs.get("node_type", "component")
                color = self.NODE_COLORS.get(node_type, "#95a5a6")
                shape = self.NODE_SHAPES.get(node_type, "ellipse")

                # Build label
                label = self._build_node_label(node_id, attrs)

                dot.node(
                    node_id,
                    label=label,
                    shape=shape,
                    style="filled",
                    fillcolor=f"{color}25",
                    color=color,
                    penwidth="1.5",
                )

            # Add edges
            for u, v, edge_data in subgraph.graph.edges(data=True):
                edge_type = edge_data.get("edge_type", "")
                color = self.EDGE_COLORS.get(edge_type, "#555555")
                weight = edge_data.get("weight", 0.5)
                penwidth = str(max(0.5, weight * 3))

                label = edge_type.replace("_", " ") if edge_type else ""

                dot.edge(
                    u, v,
                    label=label,
                    color=color,
                    penwidth=penwidth,
                    arrowsize="0.7",
                    fontcolor=color,
                    fontsize="7",
                )

            # Render
            output_stem = str(output_path).rsplit(".", 1)[0]
            rendered = dot.render(output_stem, cleanup=True)
            logger.info(f"Sub-graph rendered: {rendered}")
            return Path(rendered)

        except Exception as e:
            logger.error(f"Failed to render sub-graph '{title}': {e}")
            return None

    def render_master_dag(
        self,
        master_dag,
        title: str = "Master DAG — Cross-Layer Causal Reasoning",
        output_path: Path = Path("data/diagrams/master-dag.svg"),
        format: str = "svg",
    ) -> Optional[Path]:
        """
        Render the Master DAG showing edge nodes → intermediates → risk.

        Args:
            master_dag: MasterDAG instance
            title: Diagram title
            output_path: Where to save
            format: Output format

        Returns:
            Path to rendered file
        """
        try:
            dot = Digraph(
                name="MasterDAG",
                comment=title,
                format=format,
                engine="dot",
            )

            dot.attr(
                rankdir="LR",
                label=f"<<B>{title}</B><BR/><I>Overall Risk: {master_dag._overall_risk:.3f}</I>>",
                labelloc="t",
                fontname=self.FONT,
                fontsize="14",
                pad="0.5",
                nodesep="0.4",
                ranksep="1.5",
                bgcolor="white",
            )

            dot.attr("node", fontname=self.FONT, fontsize="9")
            dot.attr("edge", fontname=self.FONT, fontsize="8")

            # Layer 1: Edge Nodes (inputs from sub-graphs)
            with dot.subgraph(name="cluster_edge_nodes") as sub:
                sub.attr(
                    label="<<B>Edge Nodes (from Sub-Graphs)</B>>",
                    style="dashed",
                    color="#3498db",
                    fontname=self.FONT,
                    fontsize="10",
                )
                for en_id, en in master_dag._edge_nodes.items():
                    # Color by layer
                    layer_colors = {"sast": "#e74c3c", "dast": "#f39c12", "repo": "#27ae60"}
                    color = layer_colors.get(en.layer, "#3498db")
                    label = f"{en.name}\n({en.value:.2f})"

                    sub.node(
                        en_id,
                        label=label,
                        shape="ellipse",
                        style="filled",
                        fillcolor=f"{color}20",
                        color=color,
                        penwidth="1.5",
                    )

            # Layer 2: Intermediate Nodes
            with dot.subgraph(name="cluster_intermediates") as sub:
                sub.attr(
                    label="<<B>Intermediate Causal Variables</B>>",
                    style="dashed",
                    color="#e67e22",
                    fontname=self.FONT,
                    fontsize="10",
                )
                for node_id, config in master_dag.INTERMEDIATE_NODES.items():
                    value = master_dag._intermediate_values.get(node_id, 0)
                    label = f"{config['name']}\n({value:.3f})"

                    sub.node(
                        node_id,
                        label=label,
                        shape="box",
                        style="filled,rounded",
                        fillcolor="#e67e2220",
                        color="#e67e22",
                        penwidth="2",
                    )

            # Layer 3: Output (Overall Risk)
            risk_color = "#e74c3c" if master_dag._overall_risk > 0.6 else "#f39c12" if master_dag._overall_risk > 0.3 else "#27ae60"
            dot.node(
                "overall_risk",
                label=f"Overall Risk\n{master_dag._overall_risk:.3f}",
                shape="doubleoctagon",
                style="filled",
                fillcolor=f"{risk_color}30",
                color=risk_color,
                penwidth="3",
                fontsize="12",
            )

            # Edges: edge_nodes → intermediates
            for node_id, config in master_dag.INTERMEDIATE_NODES.items():
                for input_id in config["inputs"]:
                    if input_id in master_dag._edge_nodes:
                        en = master_dag._edge_nodes[input_id]
                        dot.edge(
                            input_id,
                            node_id,
                            color="#55555580",
                            penwidth=str(max(0.5, en.causal_strength * 2)),
                            arrowsize="0.6",
                        )

            # Edges: intermediates → overall_risk
            formula = master_dag.RISK_FORMULA["overall_risk"]
            for input_id in formula["inputs"]:
                dot.edge(
                    input_id,
                    "overall_risk",
                    color="#e67e22",
                    penwidth="2",
                    arrowsize="0.8",
                )

            # Mitigation edge (reduces risk)
            mitigator = formula["mitigator"]
            dot.edge(
                mitigator,
                "overall_risk",
                label="mitigates",
                color="#27ae60",
                style="dashed",
                penwidth="2",
                arrowsize="0.8",
            )

            # Render
            output_stem = str(output_path).rsplit(".", 1)[0]
            rendered = dot.render(output_stem, cleanup=True)
            logger.info(f"Master DAG rendered: {rendered}")
            return Path(rendered)

        except Exception as e:
            logger.error(f"Failed to render Master DAG: {e}")
            return None

    def render_attack_graph(
        self,
        attack_graph_result,
        title: str = "Causal Attack Graph",
        output_path: Path = Path("data/diagrams/attack-graph.svg"),
        format: str = "svg",
        max_paths: int = 5,
    ) -> Optional[Path]:
        """
        Render the top attack paths as a graph.

        Args:
            attack_graph_result: AttackGraphResult from the engine
            title: Diagram title
            output_path: Where to save
            max_paths: Maximum paths to show (for readability)

        Returns:
            Path to rendered file
        """
        try:
            dot = Digraph(
                name="AttackGraph",
                comment=title,
                format=format,
                engine="dot",
            )

            dot.attr(
                rankdir="LR",
                label=f"<<B>{title}</B><BR/><I>Top {max_paths} Attack Paths (of {attack_graph_result.total_paths})</I>>",
                labelloc="t",
                fontname=self.FONT,
                fontsize="14",
                pad="0.5",
                nodesep="0.5",
                ranksep="1.0",
                bgcolor="white",
            )

            dot.attr("node", fontname=self.FONT, fontsize="9")
            dot.attr("edge", fontname=self.FONT, fontsize="8")

            # Collect nodes and edges from top paths
            nodes_in_paths = set()
            edges_in_paths = set()
            top_paths = attack_graph_result.paths[:max_paths]

            for path in top_paths:
                for node_id in path.path_nodes:
                    nodes_in_paths.add(node_id)
                for i in range(len(path.path_nodes) - 1):
                    edges_in_paths.add((path.path_nodes[i], path.path_nodes[i + 1]))

            # Add nodes
            for node in attack_graph_result.nodes:
                if node.id not in nodes_in_paths:
                    continue

                node_type = node.node_type
                color = self.NODE_COLORS.get(node_type, "#95a5a6")
                shape = self.NODE_SHAPES.get(node_type, "ellipse")

                # Special styling for choke points
                penwidth = "3" if node.id in attack_graph_result.critical_choke_points else "1.5"
                peripheries = "2" if node.id in attack_graph_result.critical_choke_points else "1"

                label = node.name
                if node.severity:
                    label += f"\n[{node.severity}]"

                dot.node(
                    node.id,
                    label=label,
                    shape=shape,
                    style="filled",
                    fillcolor=f"{color}25",
                    color=color,
                    penwidth=penwidth,
                    peripheries=peripheries,
                )

            # Add edges
            for edge in attack_graph_result.edges:
                if (edge.source_id, edge.target_id) not in edges_in_paths:
                    continue

                color = "#e74c3c" if edge.is_confirmed else "#555555"
                style = "bold" if edge.crosses_boundary else "solid"

                dot.edge(
                    edge.source_id,
                    edge.target_id,
                    label=edge.label,
                    color=color,
                    style=style,
                    penwidth=str(max(1, edge.confidence * 3)),
                    arrowsize="0.7",
                    fontcolor=color,
                )

            # Add legend
            with dot.subgraph(name="cluster_legend") as legend:
                legend.attr(
                    label="<<B>Legend</B>>",
                    style="rounded",
                    color="#cccccc",
                    fontsize="9",
                )
                legend.node("leg_choke", "Choke Point\n(double border)", shape="ellipse", peripheries="2", fontsize="8")
                legend.node("leg_confirmed", "Confirmed\n(DAST-proven)", shape="octagon", color="#e74c3c", fontsize="8")
                legend.node("leg_impact", "Impact", shape="house", color="#2c3e50", fontsize="8")
                legend.attr("edge", style="invis")
                legend.edge("leg_choke", "leg_confirmed")
                legend.edge("leg_confirmed", "leg_impact")

            # Render
            output_stem = str(output_path).rsplit(".", 1)[0]
            rendered = dot.render(output_stem, cleanup=True)
            logger.info(f"Attack graph rendered: {rendered}")
            return Path(rendered)

        except Exception as e:
            logger.error(f"Failed to render attack graph: {e}")
            return None

    # ──── HELPERS ────────────────────────────────────────────────────────

    def _build_node_label(self, node_id: str, attrs: dict) -> str:
        """Build a readable label for a sub-graph node."""
        node_type = attrs.get("node_type", "")

        # Use meaningful attributes for the label
        if node_type == "vulnerability" or node_type == "confirmed_vulnerability":
            cwe = attrs.get("cwe", "")
            severity = attrs.get("severity", "")
            return f"{cwe}\n[{severity}]" if cwe else node_id

        if node_type == "cwe_category":
            cwe = attrs.get("cwe", "")
            count = attrs.get("count", "")
            return f"{cwe}\n(×{count})" if count else cwe

        if node_type == "root_cause":
            cwe = attrs.get("cwe", "")
            count = attrs.get("instance_count", "")
            return f"Root Cause\n{cwe} (×{count})"

        if node_type in ("component", "data_store", "external_entity"):
            name = attrs.get("name", node_id)
            return name if len(name) < 25 else name[:22] + "..."

        if node_type == "category":
            return attrs.get("category", node_id)

        if node_type == "endpoint":
            url = attrs.get("url", "")
            return url[-30:] if len(url) > 30 else url or node_id

        # Default: clean up the node_id
        clean = node_id.replace("_", " ").replace("-", " ")
        return clean[:25] if len(clean) > 25 else clean
