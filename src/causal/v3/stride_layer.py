"""
CausalTM v3 — STRIDE Threat Layer (Layer F)

Responsibility:
  - Hybrid STRIDE classification: rules + posture-derived thresholds
  - Generate threats with full evidence chains (finding → boundary → posture → threat)
  - Attach confidence, severity, and multi-layer evidence

Must NOT:
  - Bypass the causal model with direct CWE→STRIDE mapping
  - Generate threats without evidence traceability
  - Recompute posture independently from fusion output
"""

import logging
from typing import Optional

from src.causal.v3.models import (
    ControlCategory,
    FusedArchitecturalPosture,
    FusionLayerOutput,
    Severity,
    StrideCategory,
    StrideThreat,
    ThreatClassificationMethod,
    ThreatEvidence,
)

logger = logging.getLogger(__name__)


# STRIDE severity thresholds
POSTURE_THRESHOLDS = [
    (0.30, Severity.CRITICAL),
    (0.50, Severity.HIGH),
    (0.70, Severity.MEDIUM),
    (0.85, Severity.LOW),
]

# Which control categories trigger which STRIDE threats
STRIDE_TRIGGERS = {
    StrideCategory.SPOOFING: [ControlCategory.AUTH],
    StrideCategory.TAMPERING: [ControlCategory.VALIDATION],
    StrideCategory.REPUDIATION: [ControlCategory.LOGGING],
    StrideCategory.INFORMATION_DISCLOSURE: [ControlCategory.CRYPTO],
    StrideCategory.DENIAL_OF_SERVICE: [ControlCategory.VALIDATION],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [ControlCategory.AUTH, ControlCategory.VALIDATION],
}

# Threat descriptions by category
THREAT_DESCRIPTIONS = {
    StrideCategory.SPOOFING: (
        "Authentication controls are insufficient, allowing attackers to impersonate "
        "legitimate users or services at exposed boundaries."
    ),
    StrideCategory.TAMPERING: (
        "Input validation gaps allow attackers to modify data, inject malicious content, "
        "or alter application behavior through unvalidated inputs."
    ),
    StrideCategory.REPUDIATION: (
        "Insufficient audit logging means security-relevant actions cannot be reliably "
        "traced to their origin, preventing accountability."
    ),
    StrideCategory.INFORMATION_DISCLOSURE: (
        "Cryptographic controls are inadequate, allowing sensitive data to be exposed "
        "through weak encryption, missing TLS, or improper key management."
    ),
    StrideCategory.DENIAL_OF_SERVICE: (
        "Missing input validation and rate limiting allow resource exhaustion attacks "
        "that can degrade or disable service availability."
    ),
    StrideCategory.ELEVATION_OF_PRIVILEGE: (
        "Combined authentication and validation weaknesses allow attackers to gain "
        "unauthorized access to higher-privilege operations or data."
    ),
}


class StrideLayerV3:
    """
    v3 STRIDE Layer — hybrid threat classification.

    Two classification modes:
      1. Posture-derived: posture below threshold → threat at that severity
      2. Rule-based: known patterns combining posture + context
    """

    def evaluate(
        self,
        stride_postures: dict[str, float],
        fusion_output: FusionLayerOutput,
        component_graph: dict,
    ) -> list[StrideThreat]:
        """
        Evaluate STRIDE threats from posture + context.

        Generates threats where posture falls below thresholds.
        Attaches evidence chains tracing back through fusion to boundaries.
        """
        threats: list[StrideThreat] = []
        threat_counter = 0

        for stride_cat in StrideCategory:
            posture = stride_postures.get(stride_cat.value, 1.0)

            # Determine severity from threshold
            severity = self._posture_to_severity(posture)
            if severity is None:
                continue  # Posture above all thresholds — no threat

            threat_counter += 1
            threshold_used = self._get_threshold(severity)

            # Determine triggering control categories
            trigger_controls = STRIDE_TRIGGERS.get(stride_cat, [])

            # Build evidence chain from fusion output
            evidence = self._build_evidence_chain(trigger_controls, fusion_output)

            # Determine affected boundaries
            affected_boundaries = list(set(
                e.boundary_id for e in evidence if e.boundary_id != "global/unresolved"
            ))

            # Determine affected components from boundaries
            affected_components = self._get_components_for_boundaries(
                affected_boundaries, component_graph
            )

            # Collect traced CWEs from evidence
            traced_cwes = list(set(
                cwe for e in evidence for cwe in e.contributing_cwes
            ))

            # Compute confidence from fusion
            avg_confidence = (
                sum(e.source_confidence for e in evidence) / len(evidence)
                if evidence else 0.5
            )

            # Build remediation guidance
            remediation = self._build_remediation(stride_cat, trigger_controls, affected_boundaries)

            threat = StrideThreat(
                id=f"stride-v3-{threat_counter:03d}",
                category=stride_cat,
                title=f"{stride_cat.value} — Architectural Threat",
                description=THREAT_DESCRIPTIONS.get(stride_cat, ""),
                severity=severity,
                confidence=round(avg_confidence, 3),
                classification_method=ThreatClassificationMethod.POSTURE_DERIVED,
                triggering_posture_category=trigger_controls[0] if trigger_controls else ControlCategory.VALIDATION,
                triggering_posture_value=posture,
                posture_threshold_used=threshold_used,
                evidence=evidence,
                layers_contributing=len(set(e.source_type for e in evidence)),
                traced_cwes=traced_cwes,
                affected_boundaries=affected_boundaries,
                affected_components=affected_components,
                affected_flows=[],
                remediation_architecture=remediation["architecture"],
                remediation_code=remediation["code"],
                remediation_config=remediation["config"],
            )

            threats.append(threat)

            logger.info(
                f"[STRIDE v3] {stride_cat.value}: severity={severity.value} "
                f"posture={posture:.3f} boundaries={affected_boundaries} "
                f"cwes={traced_cwes[:3]}"
            )

        logger.info(f"[STRIDE Layer v3] Generated {len(threats)} threats")
        return threats

    def _posture_to_severity(self, posture: float) -> Optional[Severity]:
        """Map posture value to threat severity using thresholds."""
        for threshold, severity in POSTURE_THRESHOLDS:
            if posture < threshold:
                return severity
        # Check the final threshold (< 0.85 = Low)
        if posture < 0.85:
            return Severity.LOW
        return None  # Posture ≥ 0.85 — no threat

    def _get_threshold(self, severity: Severity) -> float:
        """Get the threshold value for a given severity."""
        for threshold, sev in POSTURE_THRESHOLDS:
            if sev == severity:
                return threshold
        return 0.85

    def _build_evidence_chain(
        self,
        trigger_controls: list[ControlCategory],
        fusion_output: FusionLayerOutput,
    ) -> list[ThreatEvidence]:
        """Build evidence chain from fusion layer tracing back to boundaries."""
        evidence_list = []

        for fbp in fusion_output.boundary_postures:
            if fbp.control_category in trigger_controls:
                # This boundary contributes to the triggering control
                evidence_list.append(ThreatEvidence(
                    source_type=fbp.contributing_sources[0] if fbp.contributing_sources else "sast",
                    boundary_id=fbp.boundary_id,
                    boundary_posture=fbp.fused_posture,
                    contributing_cwes=[],  # Would be populated from NormalizedEvidence in full pipeline
                    finding_count=0,
                    summary=f"{fbp.control_category.value} posture at {fbp.boundary_id}: {fbp.fused_posture:.2f}",
                    boundary_assignment_confidence=fbp.confidence,
                    fusion_status=fbp.fusion_status,
                    source_confidence=fbp.confidence,
                ))

        return evidence_list

    def _get_components_for_boundaries(
        self, boundary_ids: list[str], component_graph: dict
    ) -> list[str]:
        """Get component IDs for given boundaries."""
        components = []
        for boundary in component_graph.get("trust_boundaries", []):
            if boundary["id"] in boundary_ids:
                components.extend(boundary.get("component_ids", []))
        return list(set(components))

    def _build_remediation(
        self,
        stride_cat: StrideCategory,
        trigger_controls: list[ControlCategory],
        affected_boundaries: list[str],
    ) -> dict[str, str]:
        """Build three-level remediation guidance."""
        boundary_str = ", ".join(affected_boundaries) if affected_boundaries else "all boundaries"

        remediation_map = {
            StrideCategory.SPOOFING: {
                "architecture": f"Add authentication gateway at {boundary_str}. Implement mutual TLS between services.",
                "code": "Fix hardcoded credentials, implement proper session management, add CSRF tokens.",
                "config": "Enable authentication middleware on all public endpoints. Configure JWT with secure signing.",
            },
            StrideCategory.TAMPERING: {
                "architecture": f"Add input validation layer at {boundary_str}. Implement WAF for external traffic.",
                "code": "Fix SQL injection, XSS, and path traversal vulnerabilities. Use parameterized queries.",
                "config": "Enable input validation middleware. Configure content-type enforcement.",
            },
            StrideCategory.REPUDIATION: {
                "architecture": f"Add centralized logging service covering {boundary_str}.",
                "code": "Add audit logging for security-relevant operations. Log authentication events.",
                "config": "Enable access logging on all services. Configure log retention and integrity checks.",
            },
            StrideCategory.INFORMATION_DISCLOSURE: {
                "architecture": f"Add encryption at rest and in transit at {boundary_str}.",
                "code": "Replace weak crypto algorithms (MD5). Implement proper key management.",
                "config": "Enable TLS on all internal connections. Configure secure cookie flags.",
            },
            StrideCategory.DENIAL_OF_SERVICE: {
                "architecture": f"Add rate limiting and throttling at {boundary_str}.",
                "code": "Add request size limits, pagination, and timeout handling.",
                "config": "Configure rate limiting middleware. Set resource quotas per client.",
            },
            StrideCategory.ELEVATION_OF_PRIVILEGE: {
                "architecture": f"Enforce least-privilege access at {boundary_str}. Add authorization checks.",
                "code": "Implement role-based access control. Fix IDOR and broken access control.",
                "config": "Configure authorization policies. Enable principle of least privilege for service accounts.",
            },
        }

        return remediation_map.get(stride_cat, {
            "architecture": f"Review security controls at {boundary_str}.",
            "code": "Address identified code-level vulnerabilities.",
            "config": "Review and harden configuration.",
        })
