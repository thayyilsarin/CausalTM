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

            var_id = f"sast_{finding.get('id', 'unknown')}"
            self._add_base_variable(
                var_id,
                cwe=cwe,
                severity=finding.get("severity", "Medium"),
                file_path=finding.get("file_path", ""),
                title=finding.get("title", ""),
                posture_type=posture_type or "other",
                description=f"{cwe}: {finding.get('title', '')} in {finding.get('file_path', '')}",
                fix_action=f"Fix {cwe} in {finding.get('file_path', 'unknown')}",
            )

            if posture_type and posture_type in self._posture_gaps:
                self._posture_gaps[posture_type].append(var_id)

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

        Posture is INVERSE of gap density:
          0 gaps → posture = 1.0 (fully secure)
          Many gaps → posture → 0.0 (many architectural weaknesses)

        The formula:
          posture = 1.0 - (gap_count / normalizer)
          Where normalizer scales based on component count
        """
        edge_nodes = []
        has_findings = bool(self._findings)
        normalizer = max(self._component_count * 2, 5)  # Expected max gaps per posture type

        # 1. Authentication Posture
        auth_gaps = len(self._posture_gaps["auth"])
        auth_posture = max(0.0, 1.0 - (auth_gaps / normalizer))
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
        crypto_gaps = len(self._posture_gaps["crypto"])
        crypto_posture = max(0.0, 1.0 - (crypto_gaps / normalizer))
        edge_nodes.append(ArchitecturalEdgeNode(
            id="sast.crypto_posture",
            name="Encryption Posture (Code)",
            layer=self.layer_name,
            value=crypto_posture,
            causal_strength=0.75,
            stride_relevance=["Information Disclosure", "Tampering"],
            base_variables=self._posture_gaps["crypto"],
            evidence=[
                f"Crypto gaps in code: {crypto_gaps}" if has_findings else "SAST not performed",
                f"Posture: {crypto_posture:.0%} coverage",
            ],
            observed=has_findings,
        ))

        # 3. Input Validation Posture
        validation_gaps = len(self._posture_gaps["validation"])
        validation_posture = max(0.0, 1.0 - (validation_gaps / normalizer))
        edge_nodes.append(ArchitecturalEdgeNode(
            id="sast.validation_posture",
            name="Input Validation Posture (Code)",
            layer=self.layer_name,
            value=validation_posture,
            causal_strength=0.85,
            stride_relevance=["Tampering", "Elevation of Privilege"],
            base_variables=self._posture_gaps["validation"],
            evidence=[
                f"Validation gaps in code: {validation_gaps}" if has_findings else "SAST not performed",
                f"Posture: {validation_posture:.0%} coverage",
            ],
            observed=has_findings,
        ))

        # 4. Logging/Audit Posture
        logging_gaps = len(self._posture_gaps["logging"])
        logging_posture = max(0.0, 1.0 - (logging_gaps / normalizer))
        edge_nodes.append(ArchitecturalEdgeNode(
            id="sast.logging_posture",
            name="Audit Logging Posture (Code)",
            layer=self.layer_name,
            value=logging_posture,
            causal_strength=0.6,
            stride_relevance=["Repudiation"],
            base_variables=self._posture_gaps["logging"],
            evidence=[
                f"Logging gaps in code: {logging_gaps}" if has_findings else "SAST not performed",
                f"Posture: {logging_posture:.0%} coverage",
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
