"""Utility functions for working with the component graph."""

from src.analyzer.models.component import (
    Component,
    ComponentGraph,
    ComponentType,
    DataFlow,
    DataSensitivity,
    TrustBoundary,
    TrustLevel,
)


def create_component_id(component_type: str, name: str) -> str:
    """Generate a deterministic component ID."""
    sanitized = name.lower().replace(" ", "-").replace("_", "-")
    return f"{component_type}-{sanitized}"


def infer_trust_boundary_crossings(graph: ComponentGraph) -> ComponentGraph:
    """
    Analyze data flows and mark those that cross trust boundaries.

    A flow crosses a trust boundary if the source and target
    components are in different trust boundaries.
    """
    # Build component -> boundary lookup
    component_boundary: dict[str, TrustBoundary] = {}
    for boundary in graph.trust_boundaries:
        for comp_id in boundary.component_ids:
            component_boundary[comp_id] = boundary

    # Check each flow
    for flow in graph.data_flows:
        source_boundary = component_boundary.get(flow.source_id)
        target_boundary = component_boundary.get(flow.target_id)

        if source_boundary and target_boundary:
            if source_boundary.id != target_boundary.id:
                flow.crosses_trust_boundary = True
        elif source_boundary or target_boundary:
            # One is in a boundary, the other isn't — crossing
            flow.crosses_trust_boundary = True

    return graph


def detect_data_sensitivity(data_types: list[str]) -> list[DataSensitivity]:
    """
    Classify data sensitivity based on data type labels.

    Uses keyword matching to identify sensitive data categories.
    """
    sensitivity = set()
    sensitive_keywords = {
        DataSensitivity.PII: [
            "email", "name", "address", "phone", "ssn", "dob",
            "date_of_birth", "personal", "user_info", "profile",
        ],
        DataSensitivity.FINANCIAL: [
            "payment", "credit_card", "card_number", "bank",
            "account_number", "transaction", "billing", "price",
        ],
        DataSensitivity.CREDENTIALS: [
            "password", "token", "api_key", "secret", "credential",
            "auth", "session", "jwt", "oauth", "private_key",
        ],
        DataSensitivity.CONFIDENTIAL: [
            "internal", "proprietary", "restricted", "classified",
            "trade_secret", "nda",
        ],
    }

    for data_type in data_types:
        data_lower = data_type.lower()
        for sensitivity_level, keywords in sensitive_keywords.items():
            if any(kw in data_lower for kw in keywords):
                sensitivity.add(sensitivity_level)

    if not sensitivity:
        sensitivity.add(DataSensitivity.INTERNAL)

    return list(sensitivity)
