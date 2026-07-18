"""Rule evaluator — evaluates STRIDE rules against DFD elements."""

import logging
import uuid
from typing import Optional

from src.dfd.models import DFDDataFlow, DFDElement, DFDElementType, DFDModel
from src.stride.models.threat import Threat, ThreatSeverity, ThreatSource, StrideCategory
from src.stride.rules.loader import Rule

logger = logging.getLogger(__name__)


class RuleEvaluator:
    """
    Evaluates STRIDE rules against DFD elements and data flows.

    For each rule, checks if the conditions are met by the element
    and its associated flows, then generates a Threat if matched.
    """

    def __init__(self):
        self._severity_map = {
            "Critical": ThreatSeverity.CRITICAL,
            "High": ThreatSeverity.HIGH,
            "Medium": ThreatSeverity.MEDIUM,
            "Low": ThreatSeverity.LOW,
            "Informational": ThreatSeverity.INFORMATIONAL,
        }
        self._category_map = {
            "Spoofing": StrideCategory.SPOOFING,
            "Tampering": StrideCategory.TAMPERING,
            "Repudiation": StrideCategory.REPUDIATION,
            "Information Disclosure": StrideCategory.INFORMATION_DISCLOSURE,
            "Denial of Service": StrideCategory.DENIAL_OF_SERVICE,
            "Elevation of Privilege": StrideCategory.ELEVATION_OF_PRIVILEGE,
        }

    def evaluate(
        self,
        rule: Rule,
        element: DFDElement,
        dfd_model: DFDModel,
    ) -> Optional[Threat]:
        """
        Evaluate a single rule against a DFD element.

        Args:
            rule: The STRIDE rule to evaluate
            element: The DFD element to check
            dfd_model: The full DFD model (for flow context)

        Returns:
            A Threat if the rule matches, None otherwise
        """
        # Check if rule applies to this element type
        element_type_str = self._element_type_to_str(element.element_type)
        if element_type_str not in rule.applies_to:
            return None

        # Get flows associated with this element
        flows = dfd_model.get_flows_for_element(element.id)

        # Evaluate conditions
        if not self._evaluate_conditions(rule.condition, element, flows, dfd_model):
            return None

        # Rule matched — create a threat
        threat = Threat(
            id=f"threat-{uuid.uuid4().hex[:8]}",
            rule_id=rule.id,
            category=self._category_map.get(rule.category, StrideCategory.SPOOFING),
            title=rule.title,
            description=rule.description.strip(),
            severity=self._severity_map.get(rule.severity, ThreatSeverity.MEDIUM),
            confidence=rule.confidence,
            element_id=element.id,
            element_name=element.name,
            element_type=element_type_str,
            source=ThreatSource.RULE_ENGINE,
            mitigations=rule.mitigations,
            cwe_ids=rule.cwe_ids,
            attack_vector=rule.attack_vector,
            evidence=self._build_evidence(rule, element, flows),
            affected_data=self._get_affected_data(flows),
        )

        return threat

    def _evaluate_conditions(
        self,
        conditions: dict,
        element: DFDElement,
        flows: list[DFDDataFlow],
        dfd_model: DFDModel,
    ) -> bool:
        """
        Evaluate rule conditions against an element and its flows.

        Conditions are key-value pairs that check element and flow properties.
        All conditions must be satisfied (AND logic).
        """
        for key, expected_value in conditions.items():
            if not self._check_condition(key, expected_value, element, flows, dfd_model):
                return False
        return True

    def _check_condition(
        self,
        key: str,
        expected: object,
        element: DFDElement,
        flows: list[DFDDataFlow],
        dfd_model: DFDModel,
    ) -> bool:
        """Check a single condition."""

        # Special condition: always matches
        if key == "always":
            return bool(expected)

        # Element-level conditions
        if key.startswith("element."):
            return self._check_element_condition(key, expected, element)

        # Flow-level conditions (any matching flow satisfies)
        if key.startswith("flow."):
            return self._check_flow_condition(key, expected, flows, dfd_model)

        logger.debug(f"Unknown condition key: {key}")
        return False

    def _check_element_condition(
        self, key: str, expected: object, element: DFDElement
    ) -> bool:
        """Check a condition against element properties."""
        prop = key.replace("element.", "")

        # Direct element properties
        if prop == "is_public_facing":
            return element.is_public_facing == expected
        if prop == "has_authentication":
            return element.has_authentication == expected
        if prop == "has_encryption":
            return element.has_encryption == expected

        # Metadata properties
        if prop.startswith("metadata."):
            meta_key = prop.replace("metadata.", "")
            return element.metadata.get(meta_key) == expected

        return False

    def _check_flow_condition(
        self,
        key: str,
        expected: object,
        flows: list[DFDDataFlow],
        dfd_model: DFDModel,
    ) -> bool:
        """Check a condition against associated data flows (any match = true)."""
        prop = key.replace("flow.", "")

        if not flows:
            # If no flows exist, some conditions may still apply
            if prop in ["is_authenticated", "is_encrypted"] and expected is False:
                return True  # No flows means no auth/encryption
            return False

        for flow in flows:
            if self._check_single_flow(prop, expected, flow, dfd_model):
                return True

        return False

    def _check_single_flow(
        self, prop: str, expected: object, flow: DFDDataFlow, dfd_model: DFDModel
    ) -> bool:
        """Check a condition against a single flow."""
        if prop == "is_authenticated":
            return flow.is_authenticated == expected
        if prop == "is_encrypted":
            return flow.is_encrypted == expected
        if prop == "crosses_trust_boundary":
            return flow.crosses_trust_boundary == expected
        if prop == "has_sensitive_data":
            has_sensitive = bool(flow.data_sensitivity)
            return has_sensitive == expected
        if prop == "source_type":
            source = dfd_model.get_element(flow.source_id)
            if source:
                return self._element_type_to_str(source.element_type) == expected
        if prop == "target_type":
            target = dfd_model.get_element(flow.target_id)
            if target:
                return self._element_type_to_str(target.element_type) == expected
        if prop == "target_trust_level":
            target = dfd_model.get_element(flow.target_id)
            if target:
                return target.trust_level == expected

        return False

    def _element_type_to_str(self, element_type: DFDElementType) -> str:
        """Convert DFD element type enum to rule-compatible string."""
        mapping = {
            DFDElementType.PROCESS: "process",
            DFDElementType.DATA_STORE: "data_store",
            DFDElementType.EXTERNAL_ENTITY: "external_entity",
        }
        return mapping.get(element_type, "unknown")

    def _build_evidence(
        self, rule: Rule, element: DFDElement, flows: list[DFDDataFlow]
    ) -> list[str]:
        """Build evidence strings for a threat finding."""
        evidence = []
        evidence.append(f"Element: {element.name} (type: {element.element_type.value})")

        if element.is_public_facing:
            evidence.append("Element is public-facing")
        if not element.has_authentication:
            evidence.append("No authentication detected")
        if not element.has_encryption:
            evidence.append("No encryption detected")

        for flow in flows:
            if flow.crosses_trust_boundary:
                evidence.append(f"Flow '{flow.label}' crosses trust boundary")
            if flow.data_sensitivity:
                evidence.append(f"Flow carries sensitive data: {', '.join(flow.data_sensitivity)}")

        return evidence

    def _get_affected_data(self, flows: list[DFDDataFlow]) -> list[str]:
        """Collect affected data types from flows."""
        data = set()
        for flow in flows:
            data.update(flow.data_types)
            data.update(flow.data_sensitivity)
        return list(data)
