"""
Causal Graph Renderer — Renders sub-graphs and master DAG as diagrams.

Design principles (based on feedback):
- Sub-graphs: Show ONLY nodes with causal relationships (drop orphans)
- Sub-graphs: HIGHLIGHT edge nodes distinctly (they are the interface to master)
- Master DAG: Edge nodes labeled with source layer (e.g., "[SAST] Vuln Density: 0.72")
- Master DAG: Own intermediate nodes shown separately from edge nodes
- Attack graph: Human-readable names, not internal IDs
"""

import logging
from pathlib import Path
from typing import Optional

from graphviz import Digraph

logger = logging.getLogger(__name__)


class CausalGraphRenderer:
    """Renders causal sub-graphs and master DAG as Graphviz diagrams."""

    FONT = "Segoe UI"

    # Layer colors for edge node identification
    LAYER_COLORS = {
        "sast": "#e74c3c",    # Red
        "dast": "#f39c12",    # Orange
        "repo": "#27ae60",    # Green
    }

    # Edge colors by relationship type
    EDGE_COLORS = {
        "enables": "#e74c3c",
        "causes": "#c0392b",
        "leads_to": "#e67e22",
        "influences": "#9b59b6",
        "mitigates": "#27ae60",
        "connects_to": "#3498db",
        "data_flow": "#3498db",
        "classified_as": "#7f8c8d",
        "indicates": "#f39c12",
        "affects": "#e74c3c",
        "proves": "#27ae60",
        "contributes_to": "#3498db",
        "determines": "#e67e22",
    }

    def render_subgraph(
        self,
        subgraph,
        title: str,
        output_path: Path,
        format: str = "svg",
    ) -> Optional[Path]:
        """
        Render a causal sub-graph showing only connected nodes.
        Edge nodes are highlighted with a distinct border.
        """
        try:
            # Determine which nodes are connected (have at least one edge)
            connected_nodes = set()
            for u, v in subgraph.graph.edges():
                connected_nodes.add(u)
                connected_nodes.add(v)

            # If no connected nodes, show a minimal placeholder
            if not connected_nodes:
                return self._render_empty_subgraph(title, output_path, format,
                    f"No causal relationships found ({subgraph.graph.number_of_nodes()} nodes, 0 edges)")

            # Get edge node IDs for highlighting
            # Support both v1 and v2
            edge_node_ids = set()
            if hasattr(subgraph, '_edge_nodes'):
                edge_node_ids = set(subgraph._edge_nodes.keys())
            # v2 edge nodes are also in the graph with node_type="edge_node"
            for n_id, n_data in subgraph.graph.nodes(data=True):
                if n_data.get("node_type") == "edge_node":
                    edge_node_ids.add(n_id)

            dot = Digraph(
                name="CausalSubGraph",
                comment=title,
                format=format,
                engine="dot",
            )

            dot.attr(
                rankdir="TB",
                label=f"<<B>{title}</B><BR/><I>{len(connected_nodes)} active nodes | {subgraph.graph.number_of_edges()} causal edges</I>>",
                labelloc="t",
                fontname=self.FONT,
                fontsize="13",
                pad="0.5",
                nodesep="0.5",
                ranksep="0.7",
                bgcolor="white",
            )

            dot.attr("node", fontname=self.FONT, fontsize="9")
            dot.attr("edge", fontname=self.FONT, fontsize="7")

            # Render only connected nodes
            # Support both v1 (_nodes) and v2 (_base_variables) sub-DAGs
            node_data = getattr(subgraph, '_nodes', None) or getattr(subgraph, '_base_variables', {})

            for node_id in connected_nodes:
                if node_id not in node_data:
                    # Check if it's an edge node (in the graph but not in _nodes/_base_variables)
                    graph_attrs = subgraph.graph.nodes.get(node_id, {})
                    if graph_attrs:
                        attrs = graph_attrs
                    else:
                        continue
                else:
                    attrs = node_data[node_id]

                is_edge_node = node_id in edge_node_ids

                self._render_subgraph_node(dot, node_id, attrs, is_edge_node, subgraph.layer_name)

            # Render edges (only between connected nodes)
            for u, v, edge_data in subgraph.graph.edges(data=True):
                if u in connected_nodes and v in connected_nodes:
                    edge_type = edge_data.get("edge_type", "")
                    color = self.EDGE_COLORS.get(edge_type, "#555555")
                    weight = edge_data.get("weight", 0.5)

                    dot.edge(
                        u, v,
                        label=edge_type.replace("_", " ") if edge_type else "",
                        color=color,
                        penwidth=str(max(0.8, weight * 2.5)),
                        arrowsize="0.6",
                        fontcolor="#666666",
                    )

            # Add legend for edge nodes
            self._add_edge_node_legend(dot, subgraph.layer_name)

            output_stem = str(output_path).rsplit(".", 1)[0]
            rendered = dot.render(output_stem, cleanup=True)
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
        Render the Master DAG.
        Edge nodes are labeled with their source layer and value.
        Intermediate nodes are the master's own computations.
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
                label=f"<<B>{title}</B><BR/><I>Risk Score: {master_dag._overall_risk:.3f}</I>>",
                labelloc="t",
                fontname=self.FONT,
                fontsize="13",
                pad="0.5",
                nodesep="0.3",
                ranksep="1.2",
                bgcolor="white",
            )

            dot.attr("node", fontname=self.FONT, fontsize="8")
            dot.attr("edge", fontname=self.FONT, fontsize="7")

            # Layer 1: Edge Nodes (inputs FROM sub-graphs)
            # Group by source layer — ONLY include layers that produced edge nodes
            layers = {"sast": [], "dast": [], "repo": []}
            for en_id, en in master_dag._edge_nodes.items():
                # Only include edge nodes with actual values (skip empty layers)
                # But keep them in the REASONING model for counterfactuals
                is_observed = en.metadata.get("observed", "True") == "True"
                if en.layer in layers and (en.value > 0.001 or is_observed):
                    layers[en.layer].append(en)

            for layer_name, edge_nodes in layers.items():
                if not edge_nodes:
                    continue  # Skip entirely empty layers in the VISUAL only

                color = self.LAYER_COLORS.get(layer_name, "#3498db")
                cluster_name = f"cluster_edge_{layer_name}"

                with dot.subgraph(name=cluster_name) as sub:
                    sub.attr(
                        label=f"<<B>[{layer_name.upper()}] Edge Nodes</B>>",
                        style="dashed,rounded",
                        color=color,
                        fontname=self.FONT,
                        fontsize="9",
                        penwidth="2",
                    )

                    for en in edge_nodes:
                        # Label clearly shows: source + name + value
                        is_observed = en.metadata.get("observed", "True") == "True"
                        short_name = en.name.replace(f'{en.layer.upper()} ', '').replace('DAST ', '').replace('SAST ', '').replace('Architecture ', '')

                        if is_observed and en.value > 0.001:
                            label = f"[{en.layer.upper()}]\\n{short_name}\\n= {en.value:.2f}"
                            style = "filled,bold"
                            fillcolor = f"{color}15"
                        else:
                            label = f"[{en.layer.upper()}]\\n{short_name}\\n(not observed)"
                            style = "filled,dashed"
                            fillcolor = "#f5f5f5"

                        sub.node(
                            en.id,
                            label=label,
                            shape="ellipse",
                            style=style,
                            fillcolor=fillcolor,
                            color=color,
                            penwidth="2.5" if is_observed else "1",
                            fontsize="8",
                            fontcolor="#333333" if is_observed else "#999999",
                        )

            # Layer 2: Intermediate Nodes (Master's OWN reasoning)
            with dot.subgraph(name="cluster_intermediates") as sub:
                sub.attr(
                    label="<<B>Intermediate Causal Variables (Master)</B>>",
                    style="dashed,rounded",
                    color="#e67e22",
                    fontname=self.FONT,
                    fontsize="9",
                    penwidth="2",
                )

                for node_id, config in master_dag.INTERMEDIATE_NODES.items():
                    value = master_dag._intermediate_values.get(node_id, 0)
                    label = f"{config['name']}\\n= {value:.3f}"

                    sub.node(
                        node_id,
                        label=label,
                        shape="box",
                        style="filled,rounded",
                        fillcolor="#e67e2218",
                        color="#e67e22",
                        penwidth="2",
                        fontsize="9",
                    )

            # Layer 3: Output node (Overall Risk)
            risk = master_dag._overall_risk
            risk_color = "#e74c3c" if risk > 0.6 else "#f39c12" if risk > 0.3 else "#27ae60"
            dot.node(
                "overall_risk",
                label=f"OVERALL RISK\\n{risk:.3f}",
                shape="doubleoctagon",
                style="filled",
                fillcolor=f"{risk_color}25",
                color=risk_color,
                penwidth="3",
                fontsize="11",
            )

            # Edges: edge_nodes → intermediates
            for node_id, config in master_dag.INTERMEDIATE_NODES.items():
                for i, input_id in enumerate(config["inputs"]):
                    if input_id in master_dag._edge_nodes:
                        en = master_dag._edge_nodes[input_id]
                        weight = config["weights"][i] if i < len(config["weights"]) else 0.3
                        dot.edge(
                            input_id,
                            node_id,
                            color="#88888880",
                            penwidth=str(max(0.5, weight * 3)),
                            arrowsize="0.5",
                        )

            # Edges: intermediates → overall_risk
            formula = master_dag.RISK_FORMULA["overall_risk"]
            for i, input_id in enumerate(formula["inputs"]):
                weight = formula["weights"][i]
                dot.edge(
                    input_id,
                    "overall_risk",
                    label=f"w={weight}",
                    color="#e67e22",
                    penwidth=str(weight * 4),
                    arrowsize="0.7",
                    fontcolor="#e67e22",
                )

            # Mitigation edge
            mitigator = formula["mitigator"]
            dot.edge(
                mitigator,
                "overall_risk",
                label="mitigates",
                color="#27ae60",
                style="dashed",
                penwidth="2",
                arrowsize="0.7",
                fontcolor="#27ae60",
            )

            output_stem = str(output_path).rsplit(".", 1)[0]
            rendered = dot.render(output_stem, cleanup=True)
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
        Render attack paths with human-readable names.
        Choke points highlighted. Scores explained.
        """
        try:
            top_paths = attack_graph_result.paths[:max_paths]
            if not top_paths:
                return self._render_empty_subgraph(title, output_path, format,
                    "No attack paths found")

            dot = Digraph(
                name="AttackGraph",
                comment=title,
                format=format,
                engine="dot",
            )

            dot.attr(
                rankdir="LR",
                label=f"<<B>{title}</B><BR/><I>Showing top {min(max_paths, len(top_paths))} of {attack_graph_result.total_paths} paths</I>>",
                labelloc="t",
                fontname=self.FONT,
                fontsize="13",
                pad="0.5",
                nodesep="0.4",
                ranksep="0.8",
                bgcolor="white",
            )

            dot.attr("node", fontname=self.FONT, fontsize="9")
            dot.attr("edge", fontname=self.FONT, fontsize="8")

            # Collect unique nodes and edges from top paths
            nodes_used = set()
            edges_used = set()

            for path in top_paths:
                for node_id in path.path_nodes:
                    nodes_used.add(node_id)
                for i in range(len(path.path_nodes) - 1):
                    edges_used.add((path.path_nodes[i], path.path_nodes[i + 1]))

            # Render nodes with HUMAN-READABLE names
            for node in attack_graph_result.nodes:
                if node.id not in nodes_used:
                    continue

                is_choke = node.id in attack_graph_result.critical_choke_points
                label = self._human_readable_attack_node(node)

                # Style based on node type
                if node.node_type == "entry_point":
                    shape, color = "box", "#f39c12"
                elif node.node_type == "vulnerability":
                    shape, color = "octagon", "#e74c3c"
                elif node.node_type == "target":
                    shape, color = "cylinder", "#27ae60"
                elif node.node_type == "impact":
                    shape, color = "house", "#2c3e50"
                else:
                    shape, color = "ellipse", "#4a90d9"

                dot.node(
                    node.id,
                    label=label,
                    shape=shape,
                    style="filled",
                    fillcolor=f"{color}20",
                    color=color,
                    penwidth="3" if is_choke else "1.5",
                    peripheries="2" if is_choke else "1",
                )

            # Render edges with meaningful labels
            for edge in attack_graph_result.edges:
                if (edge.source_id, edge.target_id) not in edges_used:
                    continue

                color = "#c0392b" if edge.is_confirmed else "#555555"
                style = "bold" if edge.crosses_boundary else "solid"

                # Human-readable edge label
                label = self._human_readable_edge_label(edge)

                dot.edge(
                    edge.source_id,
                    edge.target_id,
                    label=label,
                    color=color,
                    style=style,
                    penwidth=str(max(1, edge.confidence * 2.5)),
                    arrowsize="0.7",
                    fontcolor="#444444",
                )

            # Score explanation note
            dot.attr(
                label=f"<<B>{title}</B><BR/>"
                      f"<I>Top {min(max_paths, len(top_paths))} of {attack_graph_result.total_paths} paths | "
                      f"Score = exploitability x (1/length) x boundary_bonus x confirmation_bonus | "
                      f"Double-border = choke point (fix here to block most paths)</I>>",
            )

            output_stem = str(output_path).rsplit(".", 1)[0]
            rendered = dot.render(output_stem, cleanup=True)
            return Path(rendered)

        except Exception as e:
            logger.error(f"Failed to render attack graph: {e}")
            return None

    # ──── HELPER METHODS ─────────────────────────────────────────────────

    def _render_subgraph_node(self, dot, node_id, attrs, is_edge_node, layer_name):
        """Render a node in a sub-graph with edge node highlighting."""
        if not isinstance(attrs, dict):
            attrs = {}
        node_type = attrs.get("node_type", "base_variable")

        # Determine shape based on type
        shape_map = {
            "vulnerability": "octagon",
            "confirmed_vulnerability": "doubleoctagon",
            "component": "ellipse",
            "data_store": "cylinder",
            "external_entity": "box",
            "cwe_category": "box",
            "root_cause": "hexagon",
            "impact_potential": "house",
            "category": "box",
            "endpoint": "circle",
            "analysis": "note",
            "trust_boundary": "box3d",
            "coverage": "parallelogram",
            "exposure_evidence": "diamond",
            "base_variable": "ellipse",
            "edge_node": "doubleoctagon",
            "stride_posture": "box",
            "final_effect": "doubleoctagon",
        }
        shape = shape_map.get(node_type, "ellipse")

        # Color based on type
        color_map = {
            "vulnerability": "#e74c3c",
            "confirmed_vulnerability": "#9b2335",
            "component": "#4a90d9",
            "data_store": "#27ae60",
            "external_entity": "#f39c12",
            "cwe_category": "#e67e22",
            "root_cause": "#c0392b",
            "impact_potential": "#2c3e50",
            "base_variable": "#7f8c8d",
            "edge_node": "#3498db",
            "stride_posture": "#9b59b6",
            "final_effect": "#e74c3c",
        }
        color = color_map.get(node_type, "#7f8c8d")

        # Build label
        label = self._build_subgraph_node_label(node_id, attrs)

        # Edge node gets special highlighting
        if is_edge_node:
            layer_color = self.LAYER_COLORS.get(layer_name, "#3498db")
            dot.node(
                node_id,
                label=f"\\n{label}\\n[EDGE NODE]",
                shape="doubleoctagon",
                style="filled,bold",
                fillcolor=f"{layer_color}20",
                color=layer_color,
                penwidth="3",
                fontsize="9",
            )
        else:
            dot.node(
                node_id,
                label=label,
                shape=shape,
                style="filled",
                fillcolor=f"{color}15",
                color=color,
                penwidth="1.5",
            )

    def _build_subgraph_node_label(self, node_id, attrs):
        """Build a human-readable label for a sub-graph node."""
        # Handle both dict attrs and graph node attrs
        if not isinstance(attrs, dict):
            attrs = {}

        node_type = attrs.get("node_type", "")

        # v2 base variables have 'description' field
        if attrs.get("description"):
            desc = attrs["description"]
            return desc[:35] if len(desc) > 35 else desc

        if node_type in ("vulnerability", "confirmed_vulnerability"):
            cwe = attrs.get("cwe", "")
            severity = attrs.get("severity", "")
            if cwe and severity:
                return f"{cwe}\\n[{severity}]"
            elif cwe:
                return cwe
            return "Vulnerability"

        if node_type == "cwe_category":
            cwe = attrs.get("cwe", "")
            count = attrs.get("count", "")
            return f"{cwe}\\n({count} instances)" if count else cwe

        if node_type == "root_cause":
            cwe = attrs.get("cwe", "")
            count = attrs.get("instance_count", "")
            return f"Root Cause\\n{cwe} ({count}x)"

        if node_type == "impact_potential":
            return node_id.replace("impact_", "").replace("_", " ").title()

        if node_type in ("component", "data_store", "external_entity"):
            name = attrs.get("name", "")
            return name if name else node_id.replace("_", " ").title()

        if node_type == "category":
            return attrs.get("category", node_id).title()

        if node_type == "coverage":
            return f"Coverage:\\n{attrs.get('coverage_type', 'unknown')}"

        if node_type == "edge_node":
            return node_id.replace(".", "\\n").replace("_", " ").title()

        if node_type == "base_variable":
            # v2 base variable
            title = attrs.get("title", "")
            cwe = attrs.get("cwe", "")
            if cwe and title:
                return f"{cwe}\\n{title[:25]}"
            elif title:
                return title[:30]
            return node_id.split("_", 1)[-1][:25] if "_" in node_id else node_id[:25]

        # Default: clean up the ID
        clean = node_id.replace("_", " ").replace("-", " ")
        return clean[:30]

    def _human_readable_attack_node(self, node):
        """Convert attack graph node to human-readable label."""
        if node.node_type == "entry_point":
            return node.name

        if node.node_type == "vulnerability":
            cwe = node.metadata.get("cwe", "")
            severity = node.severity or ""
            if cwe and severity:
                return f"{cwe}\\n[{severity}]"
            return node.name

        if node.node_type == "impact":
            return node.name.replace("(", "\\n(")

        if node.node_type == "target":
            return f"{node.name}\\n[Data Store]"

        # Component
        return node.name

    def _human_readable_edge_label(self, edge):
        """Convert attack graph edge to meaningful label."""
        if edge.edge_type == "entry":
            return "targets"
        if edge.edge_type == "exploit":
            return "exploits"
        if edge.edge_type == "lateral_movement":
            return "pivots to"
        if edge.edge_type == "impact":
            return "causes"
        if edge.label and edge.label not in ("connects_to", "data_flow"):
            return edge.label
        return ""

    def _add_edge_node_legend(self, dot, layer_name):
        """Add a small legend explaining edge node highlighting."""
        color = self.LAYER_COLORS.get(layer_name, "#3498db")
        with dot.subgraph(name="cluster_legend") as legend:
            legend.attr(
                label="<<B>Legend</B>>",
                style="rounded",
                color="#cccccc",
                fontsize="8",
            )
            legend.node(
                "legend_edge_node",
                label="Edge Node\\n(→ Master DAG)",
                shape="doubleoctagon",
                style="filled,bold",
                fillcolor=f"{color}20",
                color=color,
                penwidth="3",
                fontsize="7",
            )
            legend.node(
                "legend_internal",
                label="Internal Node",
                shape="ellipse",
                style="filled",
                fillcolor="#7f8c8d15",
                color="#7f8c8d",
                fontsize="7",
            )
            legend.attr("edge", style="invis")
            legend.edge("legend_edge_node", "legend_internal")

    def _render_empty_subgraph(self, title, output_path, format, message):
        """Render a placeholder for an empty sub-graph."""
        dot = Digraph(name="Empty", format=format, engine="dot")
        dot.attr(
            label=f"<<B>{title}</B><BR/><I>{message}</I>>",
            labelloc="t",
            fontname=self.FONT,
            fontsize="13",
            bgcolor="white",
        )
        dot.node("empty", label=message, shape="note", style="filled", fillcolor="#f5f5f5", fontsize="10")

        output_stem = str(output_path).rsplit(".", 1)[0]
        rendered = dot.render(output_stem, cleanup=True)
        return Path(rendered)
