"""
DAST Sub-Graph — Runtime-Level Causal Reasoning.

This sub-graph reasons about DYNAMIC analysis findings:
- Confirmed exploitable vulnerabilities (runtime-proven)
- Attack surface size (exposed endpoints)
- Authentication bypass evidence
- TLS/encryption configuration issues
- Information disclosure in runtime responses

Internal causal relationships:
  endpoint → exposed_to → internet → confirmed_exploitable
  auth_test_failed → proves → spoofing_possible
  tls_misconfigured → enables → interception

Edge nodes promoted to master:
  - dast.confirmed_exploitable: ratio of findings confirmed exploitable
  - dast.attack_surface: normalized count of exposed endpoints
  - dast.auth_bypass_evidence: presence of auth bypass findings
  - dast.tls_posture: TLS/SSL configuration quality
  - dast.information_leakage: runtime data exposure level
  - dast.confirmation_rate: DAST confirms what % of vulnerability types
"""

import logging
from collections import Counter
from typing import Optional

from src.causal.federated.base import (
    CausalSubGraph,
    EdgeNode,
    TacticalCounterfactual,
)

logger = logging.getLogger(__name__)


class DASTSubGraph(CausalSubGraph):
    """
    Causal sub-graph for DAST (Dynamic Application Security Testing) findings.

    Key distinction from SAST: DAST findings are CONFIRMED in runtime.
    This makes them higher-confidence evidence. The sub-graph captures this
    by treating DAST confirmations as stronger causal links.
    """

    @property
    def layer_name(self) -> str:
        return "dast"

    @property
    def description(self) -> str:
        return "Runtime-level causal reasoning from dynamic analysis findings"

    def build(self, data: dict) -> None:
        """
        Build the DAST sub-graph from normalized findings.

        Args:
            data: {
                "findings": list of NormalizedFinding dicts (from ZAP/Netsparker),
                "component_graph": architecture ComponentGraph dict
            }
        """
        findings = data.get("findings", [])
        component_graph = data.get("component_graph", {})

        logger.info(f"Building DAST sub-graph from {len(findings)} findings")

        self._findings = findings
        self._severity_counts: Counter = Counter()
        self._category_counts: Counter = Counter()
        self._urls_tested: set = set()
        self._confirmed_exploitable: list = []

        # Build nodes for each finding
        for finding in findings:
            self._add_finding_node(finding)

        # Add attack surface nodes (unique URLs/endpoints)
        self._add_attack_surface_nodes()

        # Add category aggregation (auth, injection, info disclosure, config)
        self._add_category_aggregation()

        # Add confirmation evidence chains
        self._add_confirmation_chains()

        self._built = True
        logger.info(
            f"DAST sub-graph built: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )

    def compute_edge_nodes(self) -> list[EdgeNode]:
        """
        Compute edge nodes for the master DAG.
        
        DESIGN PRINCIPLE: Edge nodes are ALWAYS produced, even when no findings exist.
        This is essential for counterfactual reasoning — the Master DAG must be able
        to ask "What if DAST DID find something?" even when DAST hasn't run yet.
        
        When no findings exist:
        - Values are set to 0.0 (observed nothing)
        - causal_strength is set to 0.0 (no influence on current risk)
        - metadata marks them as "not_observed"
        
        This allows:
        - Rendering to HIDE them (visual clarity)
        - Reasoning to USE them (counterfactual completeness)
        """
        edge_nodes = []
        has_findings = bool(self._findings)
        total = max(len(self._findings), 1)

        # When no findings: all values = 0, strength = 0 (no influence)
        # When findings exist: compute normally
        observed_strength_multiplier = 1.0 if has_findings else 0.0

        # 1. Confirmed Exploitable Ratio
        confirmed_count = len(self._confirmed_exploitable)
        edge_nodes.append(EdgeNode(
            id="dast.confirmed_exploitable",
            name="DAST Confirmed Exploitable Ratio",
            layer=self.layer_name,
            value=self._normalize(confirmed_count, total) if has_findings else 0.0,
            causal_strength=0.95 * observed_strength_multiplier,
            evidence=[
                f"Confirmed exploitable: {confirmed_count}/{total}" if has_findings else "DAST scan not performed",
            ],
            metadata={
                "confirmed_count": str(confirmed_count),
                "observed": str(has_findings),
            },
        ))

        # 2. Attack Surface Size
        endpoint_count = len(self._urls_tested)
        edge_nodes.append(EdgeNode(
            id="dast.attack_surface",
            name="DAST Attack Surface Size",
            layer=self.layer_name,
            value=self._normalize(endpoint_count, 50) if has_findings else 0.0,
            causal_strength=0.6 * observed_strength_multiplier,
            evidence=[f"Unique endpoints tested: {endpoint_count}" if has_findings else "DAST scan not performed"],
            metadata={"endpoint_count": str(endpoint_count), "observed": str(has_findings)},
        ))

        # 3. Authentication Bypass Evidence
        auth_findings = self._category_counts.get("authentication", 0)
        has_auth_bypass = auth_findings > 0
        edge_nodes.append(EdgeNode(
            id="dast.auth_bypass_evidence",
            name="DAST Authentication Bypass Evidence",
            layer=self.layer_name,
            value=(1.0 if has_auth_bypass else 0.0) if has_findings else 0.0,
            causal_strength=(0.9 if has_auth_bypass else 0.3) * observed_strength_multiplier,
            evidence=[
                (f"Auth-related findings: {auth_findings}" if has_findings else "DAST scan not performed"),
            ],
            metadata={"observed": str(has_findings)},
        ))

        # 4. TLS Posture
        tls_issues = self._category_counts.get("cryptography", 0)
        config_issues = self._category_counts.get("configuration", 0)
        tls_score = max(0.0, 1.0 - self._normalize(tls_issues + config_issues, 10)) if has_findings else 0.0
        edge_nodes.append(EdgeNode(
            id="dast.tls_posture",
            name="DAST TLS/Encryption Posture",
            layer=self.layer_name,
            value=tls_score,
            causal_strength=0.7 * observed_strength_multiplier,
            evidence=[f"TLS/config issues found: {tls_issues + config_issues}" if has_findings else "DAST scan not performed"],
            metadata={"observed": str(has_findings)},
        ))

        # 5. Information Leakage
        info_findings = self._category_counts.get("information_disclosure", 0)
        edge_nodes.append(EdgeNode(
            id="dast.information_leakage",
            name="DAST Information Leakage",
            layer=self.layer_name,
            value=self._normalize(info_findings, 10) if has_findings else 0.0,
            causal_strength=0.65 * observed_strength_multiplier,
            evidence=[f"Information disclosure findings: {info_findings}" if has_findings else "DAST scan not performed"],
            metadata={"observed": str(has_findings)},
        ))

        # 6. Severity Distribution Score
        critical = self._severity_counts.get("Critical", 0)
        high = self._severity_counts.get("High", 0)
        severity_score = ((critical * 1.0 + high * 0.7) / max(total, 1)) if has_findings else 0.0
        edge_nodes.append(EdgeNode(
            id="dast.severity_score",
            name="DAST Severity Score",
            layer=self.layer_name,
            value=min(1.0, severity_score),
            causal_strength=0.85 * observed_strength_multiplier,
            evidence=[f"Critical: {critical}, High: {high}, Total: {total}" if has_findings else "DAST scan not performed"],
            metadata={"observed": str(has_findings)},
        ))

        self._edge_nodes = {en.id: en for en in edge_nodes}
        return edge_nodes

    def tactical_counterfactual(self, intervention: str, params: dict) -> TacticalCounterfactual:
        """
        Tactical counterfactual within the DAST layer.

        Supported interventions:
        - "fix_auth": What if all auth bypass issues are fixed?
        - "fix_tls": What if TLS is properly configured?
        - "reduce_surface": What if attack surface is reduced by X%?
        - "fix_critical": What if all critical DAST findings are fixed?
        """
        before = {en.id: en.value for en in self.get_edge_nodes()}

        if intervention == "fix_auth":
            after = before.copy()
            after["dast.auth_bypass_evidence"] = 0.0
            description = "Fix all authentication bypass vulnerabilities"
        elif intervention == "fix_tls":
            after = before.copy()
            after["dast.tls_posture"] = 1.0
            description = "Properly configure TLS/SSL on all endpoints"
        elif intervention == "reduce_surface":
            reduction = params.get("reduction_pct", 50) / 100.0
            after = before.copy()
            after["dast.attack_surface"] = before["dast.attack_surface"] * (1 - reduction)
            description = f"Reduce attack surface by {params.get('reduction_pct', 50)}%"
        elif intervention == "fix_critical":
            simulated = [f for f in self._findings if f.get("severity") != "Critical"]
            after = self._recompute_edge_values(simulated)
            description = "Fix all Critical-severity DAST findings"
        else:
            after = before.copy()
            description = f"Unknown intervention: {intervention}"

        delta = {k: before[k] - after.get(k, before[k]) for k in before}
        total_delta = sum(abs(d) for d in delta.values())
        effectiveness = min(1.0, total_delta / max(len(delta), 1))

        return TacticalCounterfactual(
            layer=self.layer_name,
            intervention=intervention,
            intervention_description=description,
            edge_nodes_before=before,
            edge_nodes_after=after,
            delta=delta,
            effectiveness=effectiveness,
            recommendation=(
                f"Applying '{description}' would reduce DAST risk indicators by "
                f"{effectiveness:.0%} on average."
            ),
        )

    # ──── INTERNAL GRAPH CONSTRUCTION ────────────────────────────────────

    def _add_finding_node(self, finding: dict) -> None:
        """Add a DAST finding as a node."""
        finding_id = f"dast_finding_{finding.get('id', 'unknown')}"
        severity = finding.get("severity", "Medium")
        url = finding.get("url", "")
        category = finding.get("category", "other")

        self._severity_counts[severity] += 1
        self._category_counts[category] += 1
        if url:
            self._urls_tested.add(url)

        # All DAST findings are confirmed exploitable (runtime-proven)
        self._confirmed_exploitable.append(finding)

        self._add_node(
            finding_id,
            node_type="confirmed_vulnerability",
            severity=severity,
            url=url,
            category=category,
            confirmed=True,
        )

    def _add_attack_surface_nodes(self) -> None:
        """Add nodes representing the attack surface."""
        for url in self._urls_tested:
            url_node = f"endpoint_{hash(url) % 10000}"
            self._add_node(url_node, node_type="endpoint", url=url)

    def _add_category_aggregation(self) -> None:
        """Add aggregation nodes for vulnerability categories."""
        for category, count in self._category_counts.items():
            cat_node = f"dast_category_{category}"
            self._add_node(cat_node, node_type="category", category=category, count=count)

            # Link findings to their category
            for node_id, attrs in self._nodes.items():
                if attrs.get("category") == category and attrs.get("node_type") == "confirmed_vulnerability":
                    self._add_edge(node_id, cat_node, edge_type="classified_as")

    def _add_confirmation_chains(self) -> None:
        """Add causal chains showing confirmed exploitability."""
        # Each confirmed finding → endpoint → exposure → exploitable
        exposure_node = "dast_exposure_confirmed"
        self._add_node(exposure_node, node_type="exposure_evidence")

        for node_id, attrs in self._nodes.items():
            if attrs.get("node_type") == "confirmed_vulnerability":
                self._add_edge(node_id, exposure_node, edge_type="proves", weight=0.9)

    def _recompute_edge_values(self, simulated_findings: list) -> dict[str, float]:
        """Recompute edge values for simulated findings."""
        total = max(len(simulated_findings), 1)
        sev = Counter(f.get("severity", "Medium") for f in simulated_findings)
        cats = Counter(f.get("category", "other") for f in simulated_findings)

        after = {en.id: en.value for en in self.get_edge_nodes()}
        after["dast.confirmed_exploitable"] = self._normalize(len(simulated_findings), total)
        after["dast.severity_score"] = min(1.0,
            (sev.get("Critical", 0) * 1.0 + sev.get("High", 0) * 0.7) / max(total, 1)
        )
        after["dast.auth_bypass_evidence"] = 1.0 if cats.get("authentication", 0) > 0 else 0.0
        return after
