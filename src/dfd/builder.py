"""DFD Builder — transforms ComponentGraph into a formal DFD model."""

import logging
from typing import Optional

from src.analyzer.models.component import (
    Component,
    ComponentGraph,
    ComponentType,
    DataFlow,
    TrustBoundary,
)
from src.dfd.models import (
    DFDBoundary,
    DFDDataFlow,
    DFDElement,
    DFDElementType,
    DFDLevel,
    DFDModel,
)

logger = logging.getLogger(__name__)


class DFDBuilder:
    """
    Builds a formal DFD model from the discovered component graph.

    Transforms raw architecture components into standard DFD elements:
    - Processes (circles in DFD notation)
    - Data Stores (parallel lines)
    - External Entities (rectangles)
    - Data Flows (labeled arrows)
    - Trust Boundaries (dashed boxes)
    """

    def build(
        self,
        component_graph: dict,
        causal_result: Optional[dict] = None,
        level: DFDLevel = DFDLevel.LEVEL_0,
    ) -> dict:
        """
        Build the DFD model from a component graph.

        Args:
            component_graph: Discovered architecture (from AnalyzerEngine)
            causal_result: Optional causal analysis results for enrichment
            level: DFD abstraction level to generate

        Returns:
            DFDModel as dictionary
        """
        try:
            graph = ComponentGraph(**component_graph) if isinstance(component_graph, dict) else component_graph
        except Exception as e:
            logger.warning(f"ComponentGraph validation failed: {e}. Using dict directly.")
            # Fallback: work with raw dict
            from types import SimpleNamespace
            graph = SimpleNamespace(
                components=[Component(**c) if isinstance(c, dict) else c for c in component_graph.get("components", [])],
                data_flows=[DataFlow(**f) if isinstance(f, dict) else f for f in component_graph.get("data_flows", [])],
                trust_boundaries=[TrustBoundary(**b) if isinstance(b, dict) else b for b in component_graph.get("trust_boundaries", [])],
                metadata=component_graph.get("metadata", {}),
            )

        logger.info(f"Building DFD (level: {level}) from {len(graph.components)} components")

        # Filter out metadata-only components
        real_components = [c for c in graph.components if c.metadata.get("type") != "metadata"]

        # Convert components to DFD elements
        elements = self._build_elements(real_components)

        # Convert data flows
        data_flows = self._build_data_flows(graph.data_flows, elements)

        # Convert trust boundaries
        boundaries = self._build_boundaries(graph.trust_boundaries)

        # Assign layout layers for rendering
        elements = self._assign_layers(elements, boundaries)

        # Enrich with causal analysis if available
        if causal_result:
            elements, data_flows = self._enrich_with_causal(elements, data_flows, causal_result)

        # Build the project title
        title = graph.metadata.get("project_name", "System")

        dfd = DFDModel(
            title=f"{title} - Data Flow Diagram",
            level=level,
            description=f"Auto-generated DFD with {len(elements)} elements and {len(data_flows)} data flows",
            elements=elements,
            data_flows=data_flows,
            boundaries=boundaries,
            metadata=graph.metadata,
        )

        logger.info(
            f"DFD built: {len(dfd.get_processes())} processes, "
            f"{len(dfd.get_data_stores())} data stores, "
            f"{len(dfd.get_external_entities())} external entities, "
            f"{len(dfd.data_flows)} flows"
        )

        return dfd.model_dump()

    def _build_elements(self, components: list[Component]) -> list[DFDElement]:
        """Convert architecture components to DFD elements."""
        elements = []

        for comp in components:
            element_type = self._map_component_type(comp.type)

            element = DFDElement(
                id=comp.id,
                name=self._format_element_name(comp.name),
                element_type=element_type,
                description=self._generate_description(comp),
                technology=comp.technology,
                trust_level=comp.trust_level.value if comp.trust_level else None,
                is_public_facing=comp.is_public_facing,
                has_authentication=comp.has_authentication,
                has_encryption=comp.has_encryption,
                metadata=comp.metadata,
            )
            elements.append(element)

        return elements

    def _build_data_flows(
        self, flows: list[DataFlow], elements: list[DFDElement]
    ) -> list[DFDDataFlow]:
        """Convert architecture data flows to DFD data flows."""
        element_ids = {e.id for e in elements}
        dfd_flows = []

        for flow in flows:
            # Only include flows where both endpoints exist in elements
            if flow.source_id not in element_ids or flow.target_id not in element_ids:
                logger.debug(f"Skipping flow {flow.id}: endpoint not in elements")
                continue

            label = self._generate_flow_label(flow)

            dfd_flow = DFDDataFlow(
                id=flow.id,
                source_id=flow.source_id,
                target_id=flow.target_id,
                label=label,
                protocol=flow.protocol,
                data_types=flow.data_types,
                data_sensitivity=[s.value for s in flow.data_sensitivity],
                is_encrypted=flow.is_encrypted,
                is_authenticated=flow.is_authenticated,
                crosses_trust_boundary=flow.crosses_trust_boundary,
            )
            dfd_flows.append(dfd_flow)

        return dfd_flows

    def _build_boundaries(self, boundaries: list[TrustBoundary]) -> list[DFDBoundary]:
        """Convert trust boundaries to DFD boundaries."""
        dfd_boundaries = []
        color_map = {
            "internal": "#e8f5e9",   # Light green
            "dmz": "#fff3e0",        # Light orange
            "external": "#ffebee",   # Light red
            "unknown": "#f5f5f5",    # Light gray
        }

        for boundary in boundaries:
            dfd_boundary = DFDBoundary(
                id=boundary.id,
                name=boundary.name,
                trust_level=boundary.trust_level.value,
                element_ids=boundary.component_ids,
                color=color_map.get(boundary.trust_level.value, "#f5f5f5"),
            )
            dfd_boundaries.append(dfd_boundary)

        return dfd_boundaries

    def _assign_layers(
        self, elements: list[DFDElement], boundaries: list[DFDBoundary]
    ) -> list[DFDElement]:
        """
        Assign layout layers to elements for diagram rendering.

        Layer 0: External entities (top/edges)
        Layer 1: Public-facing processes
        Layer 2: Internal processes
        Layer 3: Data stores (bottom)
        """
        for element in elements:
            if element.element_type == DFDElementType.EXTERNAL_ENTITY:
                element.layer = 0
            elif element.element_type == DFDElementType.PROCESS:
                if element.is_public_facing:
                    element.layer = 1
                else:
                    element.layer = 2
            elif element.element_type == DFDElementType.DATA_STORE:
                element.layer = 3

            # Assign group based on boundary membership
            for boundary in boundaries:
                if element.id in boundary.element_ids:
                    element.group = boundary.id
                    break

        return elements

    def _enrich_with_causal(
        self,
        elements: list[DFDElement],
        data_flows: list[DFDDataFlow],
        causal_result: dict,
    ) -> tuple[list[DFDElement], list[DFDDataFlow]]:
        """Enrich DFD elements with causal analysis metadata."""
        # Add threat severity indicators from causal analysis
        threat_counts = causal_result.get("threat_counts_by_element", {})
        for element in elements:
            if element.id in threat_counts:
                element.metadata["threat_count"] = str(threat_counts[element.id])

        # Mark high-risk flows
        high_risk_flows = causal_result.get("high_risk_flows", [])
        for flow in data_flows:
            if flow.id in high_risk_flows:
                flow.data_types.append("[HIGH RISK]")

        return elements, data_flows

    def _map_component_type(self, comp_type: ComponentType) -> DFDElementType:
        """Map architecture component type to DFD element type."""
        mapping = {
            ComponentType.PROCESS: DFDElementType.PROCESS,
            ComponentType.DATA_STORE: DFDElementType.DATA_STORE,
            ComponentType.EXTERNAL_ENTITY: DFDElementType.EXTERNAL_ENTITY,
        }
        return mapping.get(comp_type, DFDElementType.PROCESS)

    def _format_element_name(self, name: str) -> str:
        """Format a component name for display in the DFD."""
        # Clean up common prefixes
        for prefix in ["process-", "data_store-", "ext-", "meta-"]:
            if name.startswith(prefix):
                name = name[len(prefix):]

        # Title case with reasonable formatting
        return name.replace("-", " ").replace("_", " ").title()

    def _generate_description(self, comp: Component) -> str:
        """Generate a description for a DFD element."""
        parts = []
        if comp.technology:
            parts.append(f"Technology: {comp.technology}")
        if comp.ports:
            parts.append(f"Ports: {', '.join(map(str, comp.ports))}")
        if comp.is_public_facing:
            parts.append("Public-facing")
        if comp.has_authentication:
            parts.append("Has authentication")
        if comp.has_encryption:
            parts.append("Encryption enabled")
        return "; ".join(parts) if parts else ""

    def _generate_flow_label(self, flow: DataFlow) -> str:
        """Generate a label for a data flow arrow."""
        parts = []

        if flow.data_types:
            parts.append(", ".join(flow.data_types[:3]))  # Limit to 3 types

        if flow.protocol:
            parts.append(f"[{flow.protocol}]")

        if not parts and flow.description:
            return flow.description

        return " ".join(parts) if parts else "data"
