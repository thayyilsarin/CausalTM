"""
SAST Sub-Graph — Code-Level Causal Reasoning.

This sub-graph reasons about STATIC analysis findings:
- Which files/components have vulnerabilities
- What CWE types are present
- How vulnerabilities relate to each other (shared root causes)
- Auth/crypto coverage patterns in code
- Dependency risks

Internal causal relationships:
  file → contains → vulnerability → has_type → cwe_category → leads_to → potential_impact
  dependency → has_known_cve → affects → component
  missing_pattern(auth) → enables → unauthorized_access_risk

Edge nodes promoted to master:
  - sast.vulnerability_density: normalized critical+high vuln count
  - sast.auth_coverage: fraction of components with auth patterns
  - sast.crypto_usage: encryption implementation quality
  - sast.injection_risk: presence/density of injection-type CWEs
  - sast.affected_components: ratio of components with findings
  - sast.root_cause_concentration: how clustered vulns are (shared causes)
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


class SASTSubGraph(CausalSubGraph):
    """
    Causal sub-graph for SAST (Static Application Security Testing) findings.

    Reasons about code-level vulnerabilities and their causal relationships:
    - Shared root causes (many vulns from one pattern)
    - Coverage gaps (missing auth/crypto patterns)
    - Dependency chains (vulnerable library → affected code)
    """

    @property
    def layer_name(self) -> str:
        return "sast"

    @property
    def description(self) -> str:
        return "Code-level causal reasoning from static analysis findings"

    def build(self, data: dict) -> None:
        """
        Build the SAST sub-graph from normalized findings.

        Args:
            data: {
                "findings": list of NormalizedFinding dicts,
                "component_graph": architecture ComponentGraph dict (for mapping),
                "code_patterns": optional code pattern metadata
            }
        """
        findings = data.get("findings", [])
        component_graph = data.get("component_graph", {})
        code_patterns = data.get("code_patterns", {})

        logger.info(f"Building SAST sub-graph from {len(findings)} findings")

        # Track aggregation data
        self._findings = findings
        self._severity_counts: Counter = Counter()
        self._cwe_counts: Counter = Counter()
        self._affected_files: set = set()
        self._components_with_vulns: set = set()
        self._total_components = len([
            c for c in component_graph.get("components", [])
            if c.get("metadata", {}).get("type") != "metadata"
        ])

        # Layer 1: Add vulnerability nodes
        for finding in findings:
            self._add_finding_node(finding, component_graph)

        # Layer 2: Add CWE category nodes (aggregate by type)
        self._add_cwe_aggregation_nodes()

        # Layer 3: Add root cause nodes (shared patterns)
        self._add_root_cause_nodes()

        # Layer 4: Add code pattern coverage nodes
        self._add_coverage_nodes(code_patterns, component_graph)

        # Layer 5: Internal causal edges (vuln → impact potential)
        self._add_impact_potential_edges()

        self._built = True
        logger.info(
            f"SAST sub-graph built: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )

    def compute_edge_nodes(self) -> list[EdgeNode]:
        """
        Compute edge nodes for the master DAG.

        These are the AGGREGATED causal variables that this layer
        contributes to cross-layer reasoning.
        """
        edge_nodes = []

        # 1. Vulnerability Density (normalized critical+high count)
        critical = self._severity_counts.get("Critical", 0)
        high = self._severity_counts.get("High", 0)
        medium = self._severity_counts.get("Medium", 0)
        total = len(self._findings) if self._findings else 1
        # Weighted severity score
        weighted = (critical * 1.0 + high * 0.7 + medium * 0.4) / max(total, 1)
        edge_nodes.append(EdgeNode(
            id="sast.vulnerability_density",
            name="SAST Vulnerability Density",
            layer=self.layer_name,
            value=min(1.0, weighted),
            causal_strength=0.8,
            evidence=[
                f"Critical: {critical}, High: {high}, Medium: {medium}",
                f"Total findings: {total}",
            ],
            metadata={"critical": str(critical), "high": str(high), "medium": str(medium)},
        ))

        # 2. Injection Risk (CWE-89, CWE-78, CWE-79, CWE-77, CWE-94)
        injection_cwes = {"CWE-89", "CWE-78", "CWE-79", "CWE-77", "CWE-94", "CWE-917"}
        injection_count = sum(
            self._cwe_counts.get(cwe, 0) for cwe in injection_cwes
        )
        edge_nodes.append(EdgeNode(
            id="sast.injection_risk",
            name="SAST Injection Risk",
            layer=self.layer_name,
            value=self._normalize(injection_count, max(total, 1) * 0.3),
            causal_strength=0.9,
            evidence=[f"Injection-type findings: {injection_count}"],
            metadata={"injection_cwes_found": str(injection_count)},
        ))

        # 3. Auth Coverage (fraction of components with auth patterns)
        auth_coverage = self._compute_auth_coverage()
        edge_nodes.append(EdgeNode(
            id="sast.auth_coverage",
            name="SAST Authentication Coverage",
            layer=self.layer_name,
            value=auth_coverage,
            causal_strength=0.7,
            evidence=[f"Auth coverage ratio: {auth_coverage:.2f}"],
        ))

        # 4. Crypto Usage Quality
        crypto_score = self._compute_crypto_score()
        edge_nodes.append(EdgeNode(
            id="sast.crypto_usage",
            name="SAST Cryptographic Implementation",
            layer=self.layer_name,
            value=crypto_score,
            causal_strength=0.6,
            evidence=[f"Crypto quality score: {crypto_score:.2f}"],
        ))

        # 5. Affected Components Ratio
        affected_ratio = (
            len(self._components_with_vulns) / max(self._total_components, 1)
        )
        edge_nodes.append(EdgeNode(
            id="sast.affected_components",
            name="SAST Affected Component Ratio",
            layer=self.layer_name,
            value=min(1.0, affected_ratio),
            causal_strength=0.7,
            evidence=[
                f"Components with findings: {len(self._components_with_vulns)}/{self._total_components}"
            ],
        ))

        # 6. Root Cause Concentration
        # High concentration = few root causes explain many vulns (easier to fix)
        concentration = self._compute_root_cause_concentration()
        edge_nodes.append(EdgeNode(
            id="sast.root_cause_concentration",
            name="SAST Root Cause Concentration",
            layer=self.layer_name,
            value=concentration,
            causal_strength=0.5,
            evidence=[f"Root cause concentration: {concentration:.2f}"],
            metadata={"top_cwes": str(self._cwe_counts.most_common(3))},
        ))

        self._edge_nodes = {en.id: en for en in edge_nodes}
        return edge_nodes

    def tactical_counterfactual(self, intervention: str, params: dict) -> TacticalCounterfactual:
        """
        Tactical counterfactual within the SAST layer.

        Supported interventions:
        - "fix_critical": What if all Critical findings are fixed?
        - "fix_injection": What if all injection vulns are fixed?
        - "add_auth": What if auth patterns are added everywhere?
        - "fix_cwe": What if a specific CWE type is fully remediated?
        """
        # Capture before state
        before = {en.id: en.value for en in self.get_edge_nodes()}

        # Simulate intervention
        if intervention == "fix_critical":
            after = self._simulate_fix_severity("Critical")
            description = "Remediate all Critical-severity SAST findings"
        elif intervention == "fix_injection":
            after = self._simulate_fix_injection()
            description = "Remediate all injection-type vulnerabilities"
        elif intervention == "add_auth":
            after = self._simulate_add_auth()
            description = "Add authentication patterns to all components"
        elif intervention == "fix_cwe":
            cwe_id = params.get("cwe_id", "CWE-89")
            after = self._simulate_fix_cwe(cwe_id)
            description = f"Remediate all {cwe_id} findings"
        else:
            after = before.copy()
            description = f"Unknown intervention: {intervention}"

        # Compute delta
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
                f"Applying '{description}' would reduce SAST risk indicators by "
                f"{effectiveness:.0%} on average across edge nodes."
            ),
        )

    # ──── INTERNAL GRAPH CONSTRUCTION ────────────────────────────────────

    def _add_finding_node(self, finding: dict, component_graph: dict) -> None:
        """Add a single SAST finding as a node with causal edges."""
        finding_id = f"sast_finding_{finding.get('id', 'unknown')}"
        severity = finding.get("severity", "Medium")
        cwe = finding.get("cwe_id", "")
        file_path = finding.get("file_path", "")

        self._severity_counts[severity] += 1
        if cwe:
            self._cwe_counts[cwe] += 1
        if file_path:
            self._affected_files.add(file_path)

        self._add_node(
            finding_id,
            node_type="vulnerability",
            severity=severity,
            cwe=cwe,
            file_path=file_path,
        )

        # Map to component
        comp_id = self._map_to_component(finding, component_graph)
        if comp_id:
            self._components_with_vulns.add(comp_id)
            comp_node = f"component_{comp_id}"
            if comp_node not in self._nodes:
                self._add_node(comp_node, node_type="component", component_id=comp_id)
            self._add_edge(finding_id, comp_node, edge_type="affects", weight=0.8)

    def _add_cwe_aggregation_nodes(self) -> None:
        """Add CWE category nodes that aggregate individual findings."""
        for cwe, count in self._cwe_counts.items():
            cwe_node = f"cwe_category_{cwe}"
            self._add_node(cwe_node, node_type="cwe_category", cwe=cwe, count=count)

            # Link findings to their CWE category
            for node_id, attrs in self._nodes.items():
                if attrs.get("cwe") == cwe and attrs.get("node_type") == "vulnerability":
                    self._add_edge(node_id, cwe_node, edge_type="classified_as")

    def _add_root_cause_nodes(self) -> None:
        """Identify shared root causes (same CWE in multiple files = shared pattern)."""
        for cwe, count in self._cwe_counts.items():
            if count >= 3:  # 3+ instances suggests a systemic pattern
                root_cause_id = f"root_cause_{cwe}"
                self._add_node(
                    root_cause_id,
                    node_type="root_cause",
                    cwe=cwe,
                    instance_count=count,
                )
                # Link CWE category to root cause
                cwe_node = f"cwe_category_{cwe}"
                if cwe_node in self._nodes:
                    self._add_edge(cwe_node, root_cause_id, edge_type="indicates")

    def _add_coverage_nodes(self, code_patterns: dict, component_graph: dict) -> None:
        """Add nodes representing auth/crypto coverage (or lack thereof)."""
        # Auth coverage node
        self._add_node("coverage_auth", node_type="coverage", coverage_type="authentication")
        # Crypto coverage node
        self._add_node("coverage_crypto", node_type="coverage", coverage_type="cryptography")

        # If code patterns metadata exists, use it
        components = component_graph.get("components", [])
        for comp in components:
            meta = comp.get("metadata", {})
            if meta.get("has_auth") == "true" or meta.get("type") == "metadata":
                continue
            if not comp.get("has_authentication", False):
                comp_node = f"component_{comp['id']}"
                if comp_node in self._nodes:
                    self._add_edge(
                        "coverage_auth", comp_node,
                        edge_type="missing_in", weight=0.7,
                    )

    def _add_impact_potential_edges(self) -> None:
        """Connect CWE categories to impact potential nodes."""
        cwe_impact = {
            "CWE-89": "impact_data_access",
            "CWE-79": "impact_data_theft",
            "CWE-78": "impact_system_compromise",
            "CWE-287": "impact_auth_bypass",
            "CWE-311": "impact_data_exposure",
            "CWE-269": "impact_privilege_gain",
            "CWE-400": "impact_availability_loss",
            "CWE-502": "impact_code_execution",
        }

        for cwe, impact_id in cwe_impact.items():
            cwe_node = f"cwe_category_{cwe}"
            if cwe_node in self._nodes:
                if impact_id not in self._nodes:
                    self._add_node(impact_id, node_type="impact_potential")
                self._add_edge(cwe_node, impact_id, edge_type="leads_to", weight=0.7)

    # ──── COUNTERFACTUAL SIMULATIONS ─────────────────────────────────────

    def _simulate_fix_severity(self, severity: str) -> dict[str, float]:
        """Simulate fixing all findings of a given severity."""
        simulated_findings = [
            f for f in self._findings if f.get("severity") != severity
        ]
        return self._recompute_edge_values(simulated_findings)

    def _simulate_fix_injection(self) -> dict[str, float]:
        """Simulate fixing all injection-type findings."""
        injection_cwes = {"CWE-89", "CWE-78", "CWE-79", "CWE-77", "CWE-94"}
        simulated_findings = [
            f for f in self._findings if f.get("cwe_id") not in injection_cwes
        ]
        return self._recompute_edge_values(simulated_findings)

    def _simulate_add_auth(self) -> dict[str, float]:
        """Simulate adding auth patterns to all components."""
        after = {en.id: en.value for en in self.get_edge_nodes()}
        after["sast.auth_coverage"] = 1.0  # Full coverage
        return after

    def _simulate_fix_cwe(self, cwe_id: str) -> dict[str, float]:
        """Simulate fixing all instances of a specific CWE."""
        simulated_findings = [
            f for f in self._findings if f.get("cwe_id") != cwe_id
        ]
        return self._recompute_edge_values(simulated_findings)

    def _recompute_edge_values(self, simulated_findings: list) -> dict[str, float]:
        """Recompute edge node values for a simulated finding set."""
        total = max(len(simulated_findings), 1)
        sev_counts = Counter(f.get("severity", "Medium") for f in simulated_findings)
        cwe_counts = Counter(f.get("cwe_id", "") for f in simulated_findings if f.get("cwe_id"))

        critical = sev_counts.get("Critical", 0)
        high = sev_counts.get("High", 0)
        medium = sev_counts.get("Medium", 0)

        weighted = (critical * 1.0 + high * 0.7 + medium * 0.4) / max(total, 1)
        injection_cwes = {"CWE-89", "CWE-78", "CWE-79", "CWE-77", "CWE-94"}
        injection_count = sum(cwe_counts.get(c, 0) for c in injection_cwes)

        original = {en.id: en.value for en in self.get_edge_nodes()}
        after = original.copy()
        after["sast.vulnerability_density"] = min(1.0, weighted)
        after["sast.injection_risk"] = self._normalize(injection_count, max(total, 1) * 0.3)
        after["sast.affected_components"] = min(1.0, len(set(
            f.get("file_path", "") for f in simulated_findings
        )) / max(self._total_components, 1))

        return after

    # ──── HELPERS ────────────────────────────────────────────────────────

    def _compute_auth_coverage(self) -> float:
        """Compute authentication coverage ratio (higher = more coverage = safer)."""
        if self._total_components == 0:
            return 0.5
        # Look for auth-related CWEs (absence = poor coverage)
        auth_cwes = {"CWE-287", "CWE-306", "CWE-862"}
        auth_issues = sum(self._cwe_counts.get(c, 0) for c in auth_cwes)
        # Invert: more auth issues = lower coverage score
        return max(0.0, 1.0 - self._normalize(auth_issues, self._total_components))

    def _compute_crypto_score(self) -> float:
        """Compute crypto implementation quality (higher = better)."""
        crypto_cwes = {"CWE-311", "CWE-327", "CWE-328", "CWE-330"}
        crypto_issues = sum(self._cwe_counts.get(c, 0) for c in crypto_cwes)
        return max(0.0, 1.0 - self._normalize(crypto_issues, max(len(self._findings), 1) * 0.2))

    def _compute_root_cause_concentration(self) -> float:
        """How concentrated are vulns in a few root causes? (higher = more concentrated)."""
        if not self._cwe_counts:
            return 0.0
        top_3 = sum(count for _, count in self._cwe_counts.most_common(3))
        total = sum(self._cwe_counts.values())
        return top_3 / max(total, 1)

    def _map_to_component(self, finding: dict, component_graph: dict) -> Optional[str]:
        """Map a finding to its architectural component."""
        file_path = finding.get("file_path", "")
        if not file_path:
            return None

        for comp in component_graph.get("components", []):
            if comp.get("metadata", {}).get("type") == "metadata":
                continue
            for src in comp.get("source_paths", []):
                if file_path.startswith(src) or src in file_path:
                    return comp["id"]

        # Fallback: first non-metadata component
        for comp in component_graph.get("components", []):
            if comp.get("metadata", {}).get("type") != "metadata":
                return comp["id"]
        return None
