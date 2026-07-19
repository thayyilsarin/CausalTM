"""
DAST Sub-DAG v2 — Extracts RUNTIME ARCHITECTURAL POSTURE from dynamic analysis.

This answers: "What does the application ACTUALLY look like running?"
  - Is authentication ENFORCED at runtime? (not just coded)
  - Is encryption WORKING? (not just configured)
  - What's actually EXPOSED to attackers?
  - What LEAKS in responses?

Edge nodes represent RUNTIME REALITY (what's true when the app runs):
  - runtime_auth_enforcement: Is auth actually working at boundaries?
  - runtime_encryption_status: Is TLS/encryption actually active?
  - exposed_attack_surface: What's reachable from outside?
  - information_leakage: What extra info leaks in responses?
"""

import logging
from collections import Counter

from src.causal.v2.base import ArchitecturalEdgeNode, ArchitecturalSubDAG

logger = logging.getLogger(__name__)


# DAST finding categories → which architectural posture they reveal
DAST_CATEGORY_TO_POSTURE = {
    "authentication": "runtime_auth",
    "cryptography": "runtime_encryption",
    "configuration": "runtime_encryption",  # TLS/header misconfigs
    "information_disclosure": "information_leakage",
    "injection": "runtime_validation",
    "xss": "runtime_validation",
    "access_control": "runtime_auth",
}


class DASTSubDAG(ArchitecturalSubDAG):
    """
    Extracts runtime architectural posture from DAST findings.

    DAST findings are RUNTIME PROOF — they show what actually happens
    when an attacker interacts with the application. This makes them
    higher confidence than SAST (which shows code, not behaviour).

    Key insight: DAST reveals whether ARCHITECTURAL CONTROLS are
    actually ENFORCED, not just whether they exist in code.
    """

    @property
    def layer_name(self) -> str:
        return "dast"

    def build(self, data: dict) -> None:
        """
        Build sub-DAG from DAST findings.

        Args:
            data: {"findings": list[dict], "component_graph": dict}
        """
        findings = data.get("findings", [])

        logger.info(f"[DAST v2] Building runtime posture from {len(findings)} findings")

        self._findings = findings
        self._posture_gaps = {
            "runtime_auth": [],
            "runtime_encryption": [],
            "runtime_validation": [],
            "information_leakage": [],
            "attack_surface": [],
        }

        for finding in findings:
            category = finding.get("category", "other")
            posture_type = DAST_CATEGORY_TO_POSTURE.get(category, "attack_surface")

            var_id = f"dast_{finding.get('id', 'unknown')}"
            self._add_base_variable(
                var_id,
                title=finding.get("title", ""),
                severity=finding.get("severity", "Medium"),
                url=finding.get("url", ""),
                category=category,
                posture_type=posture_type,
                confirmed=True,  # All DAST findings are runtime-confirmed
                description=f"[Runtime] {finding.get('title', '')} at {finding.get('url', '')}",
                fix_action=f"Fix runtime issue: {finding.get('title', '')}",
            )

            if posture_type in self._posture_gaps:
                self._posture_gaps[posture_type].append(var_id)

        # Every DAST finding also proves something is reachable (attack surface)
        self._total_endpoints = len(set(f.get("url", "") for f in findings if f.get("url")))

        self._built = True
        logger.info(
            f"[DAST v2] Runtime posture gaps: "
            f"auth={len(self._posture_gaps['runtime_auth'])}, "
            f"encryption={len(self._posture_gaps['runtime_encryption'])}, "
            f"validation={len(self._posture_gaps['runtime_validation'])}, "
            f"leakage={len(self._posture_gaps['information_leakage'])}, "
            f"endpoints_reached={self._total_endpoints}"
        )

    def compute_edge_nodes(self) -> list[ArchitecturalEdgeNode]:
        """
        Compute runtime architectural posture.

        DAST posture has HIGHER causal strength than SAST because
        it's runtime-proven (not theoretical).
        """
        edge_nodes = []
        has_findings = bool(self._findings)
        normalizer = max(self._total_endpoints, 5)

        # 1. Runtime Authentication Enforcement
        auth_failures = len(self._posture_gaps["runtime_auth"])
        auth_enforcement = max(0.0, 1.0 - (auth_failures / normalizer))
        edge_nodes.append(ArchitecturalEdgeNode(
            id="dast.runtime_auth_enforcement",
            name="Runtime Auth Enforcement",
            layer=self.layer_name,
            value=auth_enforcement if has_findings else 0.0,
            causal_strength=0.9 if has_findings else 0.0,
            stride_relevance=["Spoofing", "Elevation of Privilege"],
            base_variables=self._posture_gaps["runtime_auth"],
            evidence=[
                f"Auth failures at runtime: {auth_failures}" if has_findings else "DAST not performed",
                f"Enforcement: {auth_enforcement:.0%}" if has_findings else "Unknown",
            ],
            observed=has_findings,
        ))

        # 2. Runtime Encryption Status
        encryption_issues = len(self._posture_gaps["runtime_encryption"])
        encryption_status = max(0.0, 1.0 - (encryption_issues / normalizer))
        edge_nodes.append(ArchitecturalEdgeNode(
            id="dast.runtime_encryption_status",
            name="Runtime Encryption Status",
            layer=self.layer_name,
            value=encryption_status if has_findings else 0.0,
            causal_strength=0.85 if has_findings else 0.0,
            stride_relevance=["Information Disclosure", "Tampering"],
            base_variables=self._posture_gaps["runtime_encryption"],
            evidence=[
                f"Encryption issues at runtime: {encryption_issues}" if has_findings else "DAST not performed",
            ],
            observed=has_findings,
        ))

        # 3. Exposed Attack Surface
        # Higher value = MORE exposed (inverted posture — this is exposure, not protection)
        surface_ratio = min(1.0, self._total_endpoints / 50) if has_findings else 0.0
        edge_nodes.append(ArchitecturalEdgeNode(
            id="dast.exposed_attack_surface",
            name="Exposed Attack Surface (Runtime)",
            layer=self.layer_name,
            value=surface_ratio,
            causal_strength=0.7 if has_findings else 0.0,
            stride_relevance=["Spoofing", "Denial of Service", "Information Disclosure"],
            base_variables=[f"dast_{f.get('id','')}" for f in self._findings],
            evidence=[
                f"Endpoints reached by scanner: {self._total_endpoints}" if has_findings else "DAST not performed",
            ],
            observed=has_findings,
        ))

        # 4. Information Leakage Level
        leakage_issues = len(self._posture_gaps["information_leakage"])
        leakage_level = min(1.0, leakage_issues / normalizer) if has_findings else 0.0
        edge_nodes.append(ArchitecturalEdgeNode(
            id="dast.information_leakage",
            name="Information Leakage Level (Runtime)",
            layer=self.layer_name,
            value=leakage_level,
            causal_strength=0.65 if has_findings else 0.0,
            stride_relevance=["Information Disclosure"],
            base_variables=self._posture_gaps["information_leakage"],
            evidence=[
                f"Info leakage findings: {leakage_issues}" if has_findings else "DAST not performed",
            ],
            observed=has_findings,
        ))

        # Connect base variables to edge nodes
        for gap_type, edge_node_id in [
            ("runtime_auth", "dast.runtime_auth_enforcement"),
            ("runtime_encryption", "dast.runtime_encryption_status"),
            ("information_leakage", "dast.information_leakage"),
        ]:
            self.graph.add_node(edge_node_id, node_type="edge_node")
            for var_id in self._posture_gaps[gap_type]:
                self._add_edge_node_connection(var_id, edge_node_id, weight=0.8)

        self.graph.add_node("dast.exposed_attack_surface", node_type="edge_node")

        self._edge_nodes = {en.id: en for en in edge_nodes}
        return edge_nodes
