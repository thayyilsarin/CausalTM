"""
CausalTM v3 — Normalization & Evidence Layer (Layer B)

Responsibility:
  - Convert raw findings into NormalizedEvidence
  - Assign each finding to a boundary using the priority policy:
      P1: Direct file_path → component.source_paths match
      P2: Pattern inference (repo/IaC)
      P3: Unresolved → global/unresolved bucket
  - Preserve traceability to original tool output

Must NOT:
  - Make architectural conclusions
  - Perform cross-source reasoning
  - Compute posture
"""

import logging
from typing import Optional

from src.causal.v3.interfaces import NormalizationLayer
from src.causal.v3.models import (
    BoundaryAssignment,
    BoundaryAssignmentPriority,
    ControlCategory,
    NormalizedEvidence,
    Severity,
    SourceType,
)

logger = logging.getLogger(__name__)


# CWE → control category mapping (same as v2, used for classification)
CWE_TO_CONTROL = {
    # Authentication
    "CWE-287": ControlCategory.AUTH,
    "CWE-306": ControlCategory.AUTH,
    "CWE-862": ControlCategory.AUTH,
    "CWE-863": ControlCategory.AUTH,
    "CWE-640": ControlCategory.AUTH,
    "CWE-798": ControlCategory.AUTH,
    "CWE-522": ControlCategory.AUTH,
    "CWE-346": ControlCategory.AUTH,
    "CWE-352": ControlCategory.AUTH,
    # Cryptography
    "CWE-311": ControlCategory.CRYPTO,
    "CWE-319": ControlCategory.CRYPTO,
    "CWE-327": ControlCategory.CRYPTO,
    "CWE-328": ControlCategory.CRYPTO,
    "CWE-330": ControlCategory.CRYPTO,
    "CWE-347": ControlCategory.CRYPTO,
    "CWE-614": ControlCategory.CRYPTO,
    # Input Validation
    "CWE-89": ControlCategory.VALIDATION,
    "CWE-79": ControlCategory.VALIDATION,
    "CWE-78": ControlCategory.VALIDATION,
    "CWE-77": ControlCategory.VALIDATION,
    "CWE-94": ControlCategory.VALIDATION,
    "CWE-22": ControlCategory.VALIDATION,
    "CWE-20": ControlCategory.VALIDATION,
    "CWE-502": ControlCategory.VALIDATION,
    "CWE-917": ControlCategory.VALIDATION,
    "CWE-601": ControlCategory.VALIDATION,
    "CWE-770": ControlCategory.VALIDATION,
    # Logging
    "CWE-778": ControlCategory.LOGGING,
    "CWE-532": ControlCategory.LOGGING,
    "CWE-209": ControlCategory.LOGGING,
}


class NormalizationLayerV3(NormalizationLayer):
    """
    v3 Normalization Layer implementation.

    Converts raw findings from any source adapter into NormalizedEvidence
    with boundary assignments based on the P1/P2/P3 priority policy.
    """

    def normalize(
        self,
        raw_findings: list[dict],
        source_type: SourceType,
        component_graph: dict,
    ) -> list[NormalizedEvidence]:
        """
        Normalize raw findings and assign boundaries.

        Each finding gets:
          - Severity normalization
          - Control category classification (CWE or keyword-based)
          - Boundary assignment (P1 → P2 → P3 fallback)
          - Traceability metadata
        """
        results = []

        for finding in raw_findings:
            # Classify control category
            control_cat = self._classify_control_category(finding, source_type)

            # Assign boundary
            boundary = self.assign_boundary(finding, source_type, component_graph)

            # Normalize severity
            severity = self._normalize_severity(finding.get("severity", "Medium"))

            evidence = NormalizedEvidence(
                id=finding.get("id", "unknown"),
                title=finding.get("title", ""),
                description=finding.get("description", ""),
                severity=severity,
                confidence=finding.get("confidence", 0.7),
                source_type=source_type,
                control_category=control_cat,
                cwe_id=finding.get("cwe_id"),
                rule_id=finding.get("rule_id"),
                boundary_assignment=boundary,
                file_path=finding.get("file_path"),
                line_number=finding.get("line_number"),
                url=finding.get("url"),
                tool_name=finding.get("tool_name", ""),
                original_finding_ref=finding.get("id", ""),
                coverage_context=self._infer_coverage_context(finding, source_type),
            )

            results.append(evidence)

            logger.debug(
                f"[Norm] {evidence.id} → boundary={boundary.boundary_id} "
                f"({boundary.priority.value}), control={control_cat}, "
                f"severity={severity.value}"
            )

        logger.info(
            f"[Layer B] Normalized {len(results)} findings from {source_type.value}. "
            f"P1: {sum(1 for r in results if r.boundary_assignment.priority == BoundaryAssignmentPriority.DIRECT_MATCH)}, "
            f"P2: {sum(1 for r in results if r.boundary_assignment.priority == BoundaryAssignmentPriority.PATTERN_INFERENCE)}, "
            f"P3: {sum(1 for r in results if r.boundary_assignment.priority == BoundaryAssignmentPriority.UNRESOLVED)}"
        )

        return results

    def assign_boundary(
        self,
        finding: dict,
        source_type: SourceType,
        component_graph: dict,
    ) -> BoundaryAssignment:
        """
        Assign a finding to a boundary using the priority policy.

        P1: Direct file_path → component.source_paths match
        P2: Pattern inference (for repo/IaC keywords)
        P3: Unresolved → global/unresolved
        """
        components = component_graph.get("components", [])
        boundaries = component_graph.get("trust_boundaries", [])

        # Build component → boundary lookup
        comp_to_boundary = {}
        for boundary in boundaries:
            for comp_id in boundary.get("component_ids", []):
                comp_to_boundary[comp_id] = boundary["id"]

        # ── P1: Direct file_path match ──
        file_path = finding.get("file_path", "")
        if file_path:
            match = self._p1_direct_match(file_path, components, comp_to_boundary)
            if match:
                return match

        # ── P1 for DAST: URL → component endpoint match ──
        url = finding.get("url", "")
        if url and source_type == SourceType.DAST:
            match = self._p1_url_match(url, components, comp_to_boundary)
            if match:
                return match

        # ── P2: Pattern inference (IaC/repo) ──
        if source_type in (SourceType.IAC, SourceType.REPO):
            match = self._p2_pattern_inference(finding, components, comp_to_boundary)
            if match:
                return match

        # ── P3: Unresolved ──
        return BoundaryAssignment(
            boundary_id="global/unresolved",
            component_id="global",
            priority=BoundaryAssignmentPriority.UNRESOLVED,
            confidence=0.5,
            match_reason=f"No match found for '{file_path or url or 'unknown'}'",
        )

    def _p1_direct_match(
        self,
        file_path: str,
        components: list[dict],
        comp_to_boundary: dict[str, str],
    ) -> Optional[BoundaryAssignment]:
        """
        Priority 1: Direct file_path → component.source_paths match.

        Checks if file_path starts with any component's source_paths entry.
        Uses longest-prefix matching when multiple components match.
        """
        best_match: Optional[tuple[str, str, str]] = None  # (comp_id, boundary_id, matched_path)
        best_length = 0

        for comp in components:
            source_paths = comp.get("source_paths", [])
            for sp in source_paths:
                if not sp:
                    continue
                # Normalize: ensure source_path doesn't have leading slash issues
                sp_normalized = sp.rstrip("/")
                fp_normalized = file_path.replace("\\", "/")

                if fp_normalized.startswith(sp_normalized) or fp_normalized == sp_normalized:
                    if len(sp_normalized) > best_length:
                        best_length = len(sp_normalized)
                        comp_id = comp["id"]
                        boundary_id = comp_to_boundary.get(comp_id, "global/unresolved")
                        best_match = (comp_id, boundary_id, sp)

        if best_match:
            comp_id, boundary_id, matched_path = best_match
            return BoundaryAssignment(
                boundary_id=boundary_id,
                component_id=comp_id,
                priority=BoundaryAssignmentPriority.DIRECT_MATCH,
                confidence=1.0,
                match_reason=f"file_path '{file_path}' matched source_path '{matched_path}'",
            )

        return None

    def _p1_url_match(
        self,
        url: str,
        components: list[dict],
        comp_to_boundary: dict[str, str],
    ) -> Optional[BoundaryAssignment]:
        """
        Priority 1 for DAST: URL → public-facing component match.

        Maps DAST endpoints to public-facing components by port/technology.
        """
        # For Juice Shop, all HTTP endpoints map to the frontend/API
        # More sophisticated: parse URL path and match to component interfaces
        for comp in components:
            if comp.get("is_public_facing") and comp.get("type") == "process":
                comp_id = comp["id"]
                boundary_id = comp_to_boundary.get(comp_id, "global/unresolved")
                return BoundaryAssignment(
                    boundary_id=boundary_id,
                    component_id=comp_id,
                    priority=BoundaryAssignmentPriority.DIRECT_MATCH,
                    confidence=0.8,  # Slightly lower — URL matching is less precise than file path
                    match_reason=f"DAST url '{url}' matched public-facing component '{comp.get('name')}'",
                )

        return None

    def _p2_pattern_inference(
        self,
        finding: dict,
        components: list[dict],
        comp_to_boundary: dict[str, str],
    ) -> Optional[BoundaryAssignment]:
        """
        Priority 2: Pattern inference for IaC/repo findings.

        Uses resource type and path patterns to infer boundary.
        """
        file_path = finding.get("file_path", "").lower()
        title = finding.get("title", "").lower()
        rule_id = finding.get("rule_id", "").lower()

        text = f"{file_path} {title} {rule_id}"

        # IaC patterns → component type inference
        if any(kw in text for kw in ["security_group", "security-group", "alb", "load_balancer"]):
            # Network/edge component
            for comp in components:
                if comp.get("is_public_facing") and comp.get("type") == "process":
                    comp_id = comp["id"]
                    boundary_id = comp_to_boundary.get(comp_id, "global/unresolved")
                    return BoundaryAssignment(
                        boundary_id=boundary_id,
                        component_id=comp_id,
                        priority=BoundaryAssignmentPriority.PATTERN_INFERENCE,
                        confidence=0.7,
                        match_reason=f"IaC pattern '{text[:50]}' → public-facing component",
                    )

        if any(kw in text for kw in ["dynamodb", "rds", "database", "s3", "storage"]):
            # Data store component
            for comp in components:
                if comp.get("type") == "data_store":
                    comp_id = comp["id"]
                    boundary_id = comp_to_boundary.get(comp_id, "global/unresolved")
                    return BoundaryAssignment(
                        boundary_id=boundary_id,
                        component_id=comp_id,
                        priority=BoundaryAssignmentPriority.PATTERN_INFERENCE,
                        confidence=0.7,
                        match_reason=f"IaC pattern '{text[:50]}' → data store component",
                    )

        return None

    def _classify_control_category(
        self, finding: dict, source_type: SourceType
    ) -> Optional[ControlCategory]:
        """
        Classify a finding into a control category.

        Stage 1: CWE-based (definitive)
        Stage 2: Keyword-based (fallback)
        """
        # Stage 1: CWE lookup
        cwe = finding.get("cwe_id", "")
        if cwe and cwe in CWE_TO_CONTROL:
            return CWE_TO_CONTROL[cwe]

        # Stage 2: Keyword fallback
        text = (
            finding.get("title", "") + " " +
            finding.get("rule_id", "") + " " +
            finding.get("description", "") + " " +
            finding.get("category", "")
        ).lower()

        # Check for explicit category from DAST tools
        if finding.get("category"):
            cat = finding["category"].lower()
            if cat in ("auth", "authentication"):
                return ControlCategory.AUTH
            if cat in ("crypto", "encryption"):
                return ControlCategory.CRYPTO
            if cat in ("validation", "injection"):
                return ControlCategory.VALIDATION
            if cat in ("logging", "audit"):
                return ControlCategory.LOGGING

        # Keyword matching
        if any(kw in text for kw in ["auth", "login", "password", "credential", "session", "jwt", "csrf"]):
            return ControlCategory.AUTH
        if any(kw in text for kw in ["encrypt", "crypto", "tls", "ssl", "hash", "cipher", "secret", "cookie"]):
            return ControlCategory.CRYPTO
        if any(kw in text for kw in ["inject", "xss", "input", "traversal", "command", "sql", "deserializ", "rate"]):
            return ControlCategory.VALIDATION
        if any(kw in text for kw in ["log", "audit", "trace", "monitor"]):
            return ControlCategory.LOGGING

        return None

    def _normalize_severity(self, severity_str: str) -> Severity:
        """Normalize severity string to enum."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFORMATIONAL,
            "info": Severity.INFORMATIONAL,
        }
        return mapping.get(severity_str.lower(), Severity.MEDIUM)

    def _infer_coverage_context(self, finding: dict, source_type: SourceType) -> Optional[str]:
        """Infer coverage context from finding metadata."""
        if source_type == SourceType.SAST:
            fp = finding.get("file_path", "")
            return f"file scanned: {fp}" if fp else None
        elif source_type == SourceType.DAST:
            url = finding.get("url", "")
            return f"endpoint tested: {url}" if url else None
        return None
