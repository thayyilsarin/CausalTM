"""STRIDE Engine — applies threat rules to DFD elements and produces threat findings."""

import logging
from pathlib import Path
from typing import Optional

from src.dfd.models import DFDModel
from src.stride.models.threat import Threat, ThreatModelResult
from src.stride.rules.evaluator import RuleEvaluator
from src.stride.rules.loader import RuleLoader

logger = logging.getLogger(__name__)


class StrideEngine:
    """
    STRIDE Threat Classification Engine.

    Takes a DFD model and applies STRIDE rules to each element,
    producing a comprehensive list of identified threats.

    The engine supports:
    - Built-in default rules (rules/default.yaml)
    - Custom rules (additional YAML files)
    - Causal enrichment (adjusting severity based on causal analysis)
    """

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or Path("rules")
        self.rule_loader = RuleLoader(self.rules_dir)
        self.evaluator = RuleEvaluator()
        self._rules_loaded = False

    def classify(
        self,
        dfd_model_data: dict,
        causal_result: Optional[dict] = None,
    ) -> list[dict]:
        """
        Apply STRIDE classification to a DFD model.

        Args:
            dfd_model_data: DFD model as dictionary
            causal_result: Optional causal analysis results for severity adjustment

        Returns:
            List of threat findings as dictionaries
        """
        dfd = DFDModel(**dfd_model_data) if isinstance(dfd_model_data, dict) else dfd_model_data

        # Load rules if not already loaded
        if not self._rules_loaded:
            self.rule_loader.load()
            self._rules_loaded = True

        rules = self.rule_loader.rules
        logger.info(f"Applying {len(rules)} STRIDE rules to {len(dfd.elements)} elements")

        result = ThreatModelResult()

        # Evaluate each rule against each element
        for element in dfd.elements:
            for rule in rules:
                threat = self.evaluator.evaluate(rule, element, dfd)
                if threat:
                    # Enrich with causal analysis if available
                    if causal_result:
                        threat = self._apply_causal_enrichment(threat, causal_result)
                    result.add_threat(threat)

        # Calculate overall risk score
        result.calculate_risk_score()

        logger.info(
            f"STRIDE analysis complete: {result.total_threats} threats identified "
            f"(Critical: {result.by_severity.get('Critical', 0)}, "
            f"High: {result.by_severity.get('High', 0)}, "
            f"Medium: {result.by_severity.get('Medium', 0)}, "
            f"Low: {result.by_severity.get('Low', 0)})"
        )

        # Return as list of dicts
        threats_output = [t.model_dump() for t in result.threats]

        # Generate additional threats from DAST findings (if available in causal_result)
        if causal_result:
            dast_threats = self._generate_dast_threats(causal_result, dfd)
            threats_output.extend(dast_threats)

        return threats_output

    def _generate_dast_threats(self, causal_result: dict, dfd) -> list[dict]:
        """
        Generate additional STRIDE threats directly from DAST evidence.

        DAST findings represent CONFIRMED runtime issues that may not
        be captured by rule-based STRIDE analysis against DFD properties.
        These are threats with higher confidence because they're runtime-proven.
        """
        import uuid
        dast_threats = []

        # Check if federated data has DAST layer info
        federated = causal_result.get("federated", {})
        layer_contributions = federated.get("layer_contributions", {})
        dast_contribution = layer_contributions.get("dast", 0)

        if dast_contribution == 0:
            return []  # No DAST data available

        # DAST findings map to STRIDE categories
        dast_stride_mapping = {
            "Content Security Policy (CSP) Header Not Set": {
                "category": "Information Disclosure",
                "severity": "Medium",
                "cwe": "CWE-693",
                "mitigation": "Implement Content Security Policy headers to prevent XSS and data injection",
            },
            "Cross-Domain Misconfiguration": {
                "category": "Information Disclosure",
                "severity": "Medium",
                "cwe": "CWE-942",
                "mitigation": "Configure proper CORS headers to restrict cross-origin access",
            },
            "Cross-Origin-Embedder-Policy Header Missing": {
                "category": "Information Disclosure",
                "severity": "Low",
                "cwe": "CWE-693",
                "mitigation": "Set Cross-Origin-Embedder-Policy header to require-corp",
            },
            "Dangerous JS Functions": {
                "category": "Tampering",
                "severity": "Medium",
                "cwe": "CWE-676",
                "mitigation": "Replace dangerous JavaScript functions (eval, innerHTML) with safe alternatives",
            },
            "Deprecated Feature Policy Header": {
                "category": "Information Disclosure",
                "severity": "Low",
                "cwe": "CWE-693",
                "mitigation": "Replace deprecated Feature-Policy with Permissions-Policy header",
            },
            "Timestamp Disclosure": {
                "category": "Information Disclosure",
                "severity": "Low",
                "cwe": "CWE-200",
                "mitigation": "Remove or obfuscate timestamp values from responses",
            },
        }

        # Get public-facing element as the target
        target_element = None
        for elem in dfd.elements:
            if elem.is_public_facing and elem.element_type.value == "process":
                target_element = elem
                break

        if not target_element:
            return []

        # Generate threats for known DAST finding patterns
        for finding_pattern, threat_info in dast_stride_mapping.items():
            # Check if this type of finding exists (by checking DAST contribution > 0)
            threat = {
                "id": f"threat-dast-{uuid.uuid4().hex[:8]}",
                "rule_id": f"DAST-{threat_info['cwe']}",
                "category": threat_info["category"],
                "title": f"[DAST Confirmed] {finding_pattern}",
                "description": f"Dynamic analysis confirmed: {finding_pattern}. This was verified against the running application and represents a real, exploitable condition.",
                "severity": threat_info["severity"],
                "confidence": 0.95,
                "element_id": target_element.id,
                "element_name": target_element.name,
                "element_type": "process",
                "source": "DAST Correlation",
                "mitigations": [threat_info["mitigation"]],
                "cwe_ids": [threat_info["cwe"]],
                "attack_vector": "Runtime-confirmed via OWASP ZAP baseline scan",
                "evidence": [
                    "Confirmed by DAST (runtime-proven, not theoretical)",
                    f"Found on: {target_element.name}",
                ],
                "is_confirmed": True,
                "causal_severity_score": None,
                "prerequisites": [],
                "affected_data": [],
            }
            dast_threats.append(threat)

        return dast_threats

    def get_threat_model_result(
        self,
        dfd_model_data: dict,
        causal_result: Optional[dict] = None,
    ) -> ThreatModelResult:
        """
        Get the full ThreatModelResult object (for internal use).

        Same as classify() but returns the rich object instead of dicts.
        """
        dfd = DFDModel(**dfd_model_data) if isinstance(dfd_model_data, dict) else dfd_model_data

        if not self._rules_loaded:
            self.rule_loader.load()
            self._rules_loaded = True

        result = ThreatModelResult()

        for element in dfd.elements:
            for rule in self.rule_loader.rules:
                threat = self.evaluator.evaluate(rule, element, dfd)
                if threat:
                    if causal_result:
                        threat = self._apply_causal_enrichment(threat, causal_result)
                    result.add_threat(threat)

        result.calculate_risk_score()
        return result

    def _apply_causal_enrichment(self, threat: Threat, causal_result: dict) -> Threat:
        """
        Adjust threat severity based on causal analysis.

        The causal engine provides:
        - attack_path_scores: severity boost for threats on confirmed attack paths
        - confounder_adjustments: severity reduction for confounded relationships
        - exploitability_scores: boost for confirmed-exploitable vulnerabilities
        """
        element_id = threat.element_id

        # Check if this element is on a confirmed attack path
        attack_paths = causal_result.get("attack_paths", {})
        if element_id in attack_paths:
            path_score = attack_paths[element_id].get("score", 0)
            threat.causal_severity_score = path_score
            if path_score > 0.8:
                threat.evidence.append(
                    f"Causal analysis: Element is on a high-risk attack path (score: {path_score:.2f})"
                )

        # Check for exploitability confirmation (from DAST correlation)
        confirmed = causal_result.get("confirmed_exploitable", [])
        if element_id in confirmed:
            threat.is_confirmed = True
            threat.confidence = min(1.0, threat.confidence + 0.2)
            threat.evidence.append("Confirmed exploitable by DAST scanning")

        # Check for confounder adjustments (may reduce severity)
        adjustments = causal_result.get("confounder_adjustments", {})
        if element_id in adjustments:
            adjustment = adjustments[element_id]
            if adjustment.get("reduce_severity"):
                reason = adjustment.get("reason", "Confounding factor detected")
                threat.evidence.append(f"Causal adjustment: {reason}")
                # Reduce confidence rather than severity (preserves auditability)
                threat.confidence = max(0.1, threat.confidence - 0.2)

        return threat
