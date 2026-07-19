"""
SAST Sub-DAG v2 — Extracts ARCHITECTURAL POSTURE from static analysis findings.

This does NOT count vulnerabilities. It answers:
  "What security controls EXIST in the code? Where are the GAPS?"

Edge nodes (effects) represent architectural state:
  - auth_posture: How complete is authentication coverage?
  - crypto_posture: Is encryption properly implemented?
  - input_validation_posture: Are inputs validated at boundaries?
  - logging_posture: Is audit logging present?

Base variables (causes) are individual SAST findings that reveal gaps.
"""

import logging
from collections import Counter
from typing import Optional

from src.causal.v2.base import ArchitecturalEdgeNode, ArchitecturalSubDAG

logger = logging.getLogger(__name__)


# CWE → which architectural control it reveals a gap in
CWE_TO_POSTURE = {
    # Authentication gaps
    "CWE-287": "auth",    # Improper Authentication
    "CWE-306": "auth",    # Missing Authentication for Critical Function
    "CWE-862": "auth",    # Missing Authorization
    "CWE-863": "auth",    # Incorrect Authorization
    "CWE-640": "auth",    # Weak Password Recovery
    "CWE-798": "auth",    # Hardcoded Credentials (auth design flaw)
    "CWE-522": "auth",    # Insufficiently Protected Credentials
    "CWE-346": "auth",    # Origin Validation Error
    "CWE-352": "auth",    # CSRF (authentication boundary issue)

    # Encryption/crypto gaps
    "CWE-311": "crypto",  # Missing Encryption of Sensitive Data
    "CWE-319": "crypto",  # Cleartext Transmission
    "CWE-327": "crypto",  # Use of Broken Crypto Algorithm
    "CWE-328": "crypto",  # Reversible One-Way Hash
    "CWE-330": "crypto",  # Insufficient Randomness
    "CWE-347": "crypto",  # Improper Verification of Cryptographic Signature

    # Input validation gaps
    "CWE-89": "validation",   # SQL Injection
    "CWE-79": "validation",   # XSS
    "CWE-78": "validation",   # OS Command Injection
    "CWE-77": "validation",   # Command Injection
    "CWE-94": "validation",   # Code Injection
    "CWE-22": "validation",   # Path Traversal
    "CWE-20": "validation",   # Improper Input Validation
    "CWE-502": "validation",  # Deserialization
    "CWE-917": "validation",  # Expression Language Injection
    "CWE-601": "validation",  # Open Redirect

    # Logging/audit gaps
    "CWE-778": "logging",  # Insufficient Logging
    "CWE-532": "logging",  # Sensitive Info in Log (bad logging design)
    "CWE-209": "logging",  # Error Info Exposure (reveals internal state)
}


class SASTSubDAG(ArchitecturalSubDAG):
    """
    Extracts architectural security posture from SAST findings.

    Each finding is treated as EVIDENCE of an architectural gap:
      CWE-89 found → architecture lacks input validation at this boundary
      CWE-287 found → architecture lacks authentication at this point
      No auth CWEs found → architecture HAS authentication coverage

    The ABSENCE of findings is as informative as their presence.
    """

    @property
    def layer_name(self) -> str:
        return "sast"

    def build(self, data: dict) -> None:
        """
        Build sub-DAG from SAST findings.

        Args:
            data: {"findings": list[dict], "component_graph": dict}
        """
        findings = data.get("findings", [])
        component_graph = data.get("component_graph", {})

        logger.info(f"[SAST v2] Building architectural posture from {len(findings)} findings")

        self._findings = findings
        self._component_count = len([
            c for c in component_graph.get("components", [])
            if c.get("metadata", {}).get("type") != "metadata"
        ])

        # Classify each finding as revealing a gap in a specific control
        self._posture_gaps = {"auth": [], "crypto": [], "validation": [], "logging": []}

        for finding in findings:
            cwe = finding.get("cwe_id", "")
            posture_type = CWE_TO_POSTURE.get(cwe)

            # If no CWE match, try to classify by title/rule keywords
            if not posture_type:
                posture_type = self._classify_by_keywords(finding)

            var_id = f"sast_{finding.get('id', 'unknown')}"
            self._add_base_variable(
                var_id,
                cwe=cwe,
                severity=finding.get("severity", "Medium"),
                file_path=finding.get("file_path", ""),
                title=finding.get("title", ""),
                posture_type=posture_type or "validation",  # Default: treat as validation gap
                description=f"{cwe or 'Finding'}: {finding.get('title', '')[:50]} in {finding.get('file_path', '')[:30]}",
                fix_action=f"Fix {cwe or 'issue'} in {finding.get('file_path', 'unknown')}",
            )

            if posture_type and posture_type in self._posture_gaps:
                self._posture_gaps[posture_type].append(var_id)
            elif not posture_type:
                # Default unclassified findings to validation (most common)
                self._posture_gaps["validation"].append(var_id)

        self._built = True
        logger.info(
            f"[SAST v2] Posture gaps found: "
            f"auth={len(self._posture_gaps['auth'])}, "
            f"crypto={len(self._posture_gaps['crypto'])}, "
            f"validation={len(self._posture_gaps['validation'])}, "
            f"logging={len(self._posture_gaps['logging'])}"
        )

    def compute_edge_nodes(self) -> list[ArchitecturalEdgeNode]:
        """
        Compute architectural posture edge nodes.

        Posture is SEVERITY-WEIGHTED:
          - Critical gap contributes 1.0 to deficit
          - High gap contributes 0.7
          - Medium gap contributes 0.4
          - Low gap contributes 0.2
          
        Formula:
          weighted_deficit = sum(severity_weight for each gap)
          posture = max(0, 1.0 - (weighted_deficit / max_expected_deficit))
          
        max_expected_deficit is calibrated so that 3 Critical findings = posture 0.0
        """
        edge_nodes = []
        has_findings = bool(self._findings)

        severity_weights = {"Critical": 1.0, "High": 0.7, "Medium": 0.4, "Low": 0.2}
        # Calibration: 3 critical findings (weight 3.0) should bring posture near 0
        max_deficit = 3.0

        # 1. Authentication Posture
        auth_deficit = self._compute_weighted_deficit(self._posture_gaps["auth"], severity_weights)
        auth_posture = max(0.0, 1.0 - (auth_deficit / max_deficit))
        edge_nodes.append(ArchitecturalEdgeNode(
            id="sast.auth_posture",
            name="Authentication Posture (Code)",
            layer=self.layer_name,
            value=auth_posture,
            causal_strength=0.8,
            stride_relevance=["Spoofing", "Elevation of Privilege"],
            base_variables=self._posture_gaps["auth"],
            evidence=[
                f"Auth gaps in code: {auth_gaps}" if has_findings else "SAST not performed",
                f"Posture: {auth_posture:.0%} coverage",
            ],
            observed=has_findings,
        ))

        # 2. Cryptographic Posture
        crypto_deficit = self._compute_weighted_deficit(self._posture_gaps["crypto"], severity_weights)
        crypto_posture = max(0.0, 1.0 - (crypto_deficit / max_deficit))
        edge_nodes.append(ArchitecturalEdgeNode(
            id="sast.crypto_posture",
            name="Encryption Posture (Code)",
            layer=self.layer_name,
            value=crypto_posture,
            causal_strength=0.75,
            stride_relevance=["Information Disclosure", "Tampering"],
            base_variables=self._posture_gaps["crypto"],
            evidence=[
                f"Crypto gaps: {len(self._posture_gaps['crypto'])} (weighted deficit: {crypto_deficit:.2f})" if has_findings else "SAST not performed",
                f"Posture: {crypto_posture:.0%}",
            ],
            observed=has_findings,
        ))

        # 3. Input Validation Posture
        validation_deficit = self._compute_weighted_deficit(self._posture_gaps["validation"], severity_weights)
        validation_posture = max(0.0, 1.0 - (validation_deficit / max_deficit))
        edge_nodes.append(ArchitecturalEdgeNode(
            id="sast.validation_posture",
            name="Input Validation Posture (Code)",
            layer=self.layer_name,
            value=validation_posture,
            causal_strength=0.85,
            stride_relevance=["Tampering", "Elevation of Privilege"],
            base_variables=self._posture_gaps["validation"],
            evidence=[
                f"Validation gaps: {len(self._posture_gaps['validation'])} (weighted deficit: {validation_deficit:.2f})" if has_findings else "SAST not performed",
                f"Posture: {validation_posture:.0%}",
            ],
            observed=has_findings,
        ))

        # 4. Logging/Audit Posture
        logging_deficit = self._compute_weighted_deficit(self._posture_gaps["logging"], severity_weights)
        logging_posture = max(0.0, 1.0 - (logging_deficit / max_deficit))
        edge_nodes.append(ArchitecturalEdgeNode(
            id="sast.logging_posture",
            name="Audit Logging Posture (Code)",
            layer=self.layer_name,
            value=logging_posture,
            causal_strength=0.6,
            stride_relevance=["Repudiation"],
            base_variables=self._posture_gaps["logging"],
            evidence=[
                f"Logging gaps: {len(self._posture_gaps['logging'])} (weighted deficit: {logging_deficit:.2f})" if has_findings else "SAST not performed",
                f"Posture: {logging_posture:.0%}",
            ],
            observed=has_findings,
        ))

        # Connect base variables to edge nodes in the graph
        for gap_type, edge_node_id in [
            ("auth", "sast.auth_posture"),
            ("crypto", "sast.crypto_posture"),
            ("validation", "sast.validation_posture"),
            ("logging", "sast.logging_posture"),
        ]:
            self.graph.add_node(edge_node_id, node_type="edge_node")
            for var_id in self._posture_gaps[gap_type]:
                self._add_edge_node_connection(var_id, edge_node_id, weight=0.7)

        self._edge_nodes = {en.id: en for en in edge_nodes}
        return edge_nodes

    def _compute_weighted_deficit(self, gap_var_ids: list[str], severity_weights: dict) -> float:
        """
        Compute severity-weighted deficit for a set of posture gaps.
        
        Critical findings contribute more to the deficit than Low ones.
        This makes posture calculation defensible:
          "One Critical auth bypass (weight 1.0) hurts posture more than
           three Low missing-header issues (weight 0.6 total)"
        """
        total_deficit = 0.0
        for var_id in gap_var_ids:
            base_var = self._base_variables.get(var_id, {})
            severity = base_var.get("severity", "Medium")
            weight = severity_weights.get(severity, 0.4)
            total_deficit += weight
        return total_deficit

    def _classify_by_keywords(self, finding: dict) -> Optional[str]:
        """Classify a finding by keywords when CWE is not available."""
        text = (
            finding.get("title", "") + " " +
            finding.get("rule_id", "") + " " +
            finding.get("description", "")
        ).lower()

        auth_keywords = ["auth", "login", "password", "credential", "session", "jwt", "token", "csrf", "permission"]
        crypto_keywords = ["encrypt", "crypto", "tls", "ssl", "hash", "cipher", "secret", "key"]
        validation_keywords = ["inject", "xss", "input", "sanitiz", "escap", "traversal", "command", "sql", "eval", "deserializ"]
        logging_keywords = ["log", "audit", "trace", "monitor"]

        for kw in auth_keywords:
            if kw in text:
                return "auth"
        for kw in crypto_keywords:
            if kw in text:
                return "crypto"
        for kw in validation_keywords:
            if kw in text:
                return "validation"
        for kw in logging_keywords:
            if kw in text:
                return "logging"

        return None
