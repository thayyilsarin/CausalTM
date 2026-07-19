"""
STRIDE Layer v2 — The Cream Layer.

Sits ABOVE the Master DAG and evaluates the complete architecture
understanding against the six STRIDE threat categories.

This layer does NOT need vulnerabilities to identify threats.
Architecture alone is sufficient:
  "Data flow crosses trust boundary without encryption → Information Disclosure THREAT"

It uses posture scores from all layers to determine:
  1. WHICH STRIDE threats exist (based on architectural gaps)
  2. HOW SEVERE each threat is (based on data sensitivity and exposure)
  3. WHETHER the threat is confirmed (corroborated by multiple layers)
  4. WHAT fixes it (traced back through edge nodes to base variables)
"""

import logging
import uuid
from typing import Optional

from pydantic import BaseModel, Field

from src.causal.v2.master_dag import MasterDAGResult

logger = logging.getLogger(__name__)


class StrideThreathV2(BaseModel):
    """A STRIDE threat identified from architecture analysis."""

    id: str
    category: str  # Spoofing, Tampering, Repudiation, Info Disclosure, DoS, EoP
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low
    confidence: float = Field(ge=0.0, le=1.0, default=0.7)

    # What architectural elements are affected
    affected_components: list[str] = []
    affected_flows: list[str] = []

    # Evidence from each layer
    evidence_sast: list[str] = []
    evidence_dast: list[str] = []
    evidence_repo: list[str] = []

    # Corroboration: how many layers agree this threat exists?
    layers_confirming: int = 1  # 1 = one source, 3 = all three agree

    # What posture scores indicate this threat
    posture_indicators: dict[str, float] = Field(default_factory=dict)

    # How to fix it (from backward propagation)
    remediation_architecture: str = ""  # Architecture-level fix
    remediation_code: str = ""  # Code-level fix (if applicable)
    remediation_verification: str = ""  # How to verify it's fixed

    # STRIDE-specific
    stride_posture_score: float = 0.0  # 0 = fully threatened, 1 = fully mitigated


class StrideThreatModelV2(BaseModel):
    """Complete STRIDE threat model output."""

    threats: list[StrideThreathV2] = []
    total_threats: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)

    # Overall posture per STRIDE category (0 = no protection, 1 = fully protected)
    posture_per_category: dict[str, float] = Field(default_factory=dict)

    # Overall risk (inverse of average posture)
    overall_risk: float = 0.0

    # Roadmap summary
    roadmap_steps: int = 0


# ──── STRIDE EVALUATION ENGINE ───────────────────────────────────────────────


class StrideLayerV2:
    """
    The STRIDE Cream Layer.

    Evaluates the complete architecture (from Master DAG) against
    STRIDE threat categories. Produces threats based on DESIGN,
    not on individual vulnerabilities.
    """

    # Thresholds below which a threat is identified
    # Lower thresholds = more sensitive (catches more threats)
    # For deliberately vulnerable apps like Juice Shop, posture will be low
    THREAT_THRESHOLDS = {
        "critical": 0.3,   # Posture below 30% = Critical threat
        "high": 0.5,       # Posture below 50% = High threat
        "medium": 0.7,     # Posture below 70% = Medium threat
        "low": 0.85,       # Posture below 85% = Low threat (catches more)
    }

    def evaluate(self, master_result: MasterDAGResult, component_graph: dict) -> StrideThreatModelV2:
        """
        Evaluate architecture against STRIDE.

        Args:
            master_result: Output from Master DAG (posture scores, stride inputs)
            component_graph: Original architecture (for component/flow references)

        Returns:
            Complete STRIDE threat model
        """
        logger.info("[STRIDE v2] Evaluating architecture against STRIDE categories...")

        threats = []
        posture_per_category = {}

        # Evaluate each STRIDE category
        stride_evaluators = {
            "Spoofing": self._evaluate_spoofing,
            "Tampering": self._evaluate_tampering,
            "Repudiation": self._evaluate_repudiation,
            "Information Disclosure": self._evaluate_information_disclosure,
            "Denial of Service": self._evaluate_denial_of_service,
            "Elevation of Privilege": self._evaluate_elevation_of_privilege,
        }

        for category, evaluator in stride_evaluators.items():
            category_inputs = master_result.stride_inputs.get(category, {})
            posture_scores = category_inputs.get("posture_scores", {})

            # Compute category posture (average of relevant edge nodes)
            if posture_scores:
                # For exposure/leakage scores, invert them (lower exposure = better posture)
                adjusted_scores = []
                for en_id, val in posture_scores.items():
                    if "exposure" in en_id or "leakage" in en_id or "sensitivity" in en_id:
                        adjusted_scores.append(1.0 - val)
                    else:
                        adjusted_scores.append(val)
                category_posture = sum(adjusted_scores) / len(adjusted_scores)
            else:
                category_posture = 0.5  # Unknown = assume medium

            posture_per_category[category] = category_posture

            # Generate threats if posture is below thresholds
            category_threats = evaluator(category_posture, posture_scores, component_graph)
            threats.extend(category_threats)

        # Build result
        result = StrideThreatModelV2(
            threats=threats,
            total_threats=len(threats),
            by_category={cat: sum(1 for t in threats if t.category == cat) for cat in stride_evaluators},
            by_severity={
                sev: sum(1 for t in threats if t.severity == sev)
                for sev in ["Critical", "High", "Medium", "Low"]
            },
            posture_per_category=posture_per_category,
            overall_risk=1.0 - (sum(posture_per_category.values()) / max(len(posture_per_category), 1)),
        )

        logger.info(
            f"[STRIDE v2] Evaluation complete: {len(threats)} threats, "
            f"overall risk: {result.overall_risk:.3f}"
        )

        return result

    # ──── STRIDE CATEGORY EVALUATORS ─────────────────────────────────────

    def _evaluate_spoofing(self, posture: float, scores: dict, component_graph: dict) -> list[StrideThreathV2]:
        """Can identity be forged? Is authentication adequate?"""
        threats = []

        if posture < self.THREAT_THRESHOLDS["low"]:
            severity = self._posture_to_severity(posture)

            # Determine specific spoofing issues from posture scores
            auth_code = scores.get("sast.auth_posture", 1.0)
            auth_runtime = scores.get("dast.runtime_auth_enforcement", 1.0)
            exposure = scores.get("repo.topology_exposure", 0.0)

            layers_confirming = sum([
                auth_code < 0.7,
                auth_runtime < 0.7,
                exposure > 0.3,
            ])

            threats.append(StrideThreathV2(
                id=f"stride-s-{uuid.uuid4().hex[:6]}",
                category="Spoofing",
                title="Insufficient Identity Verification at Trust Boundaries",
                description=(
                    f"The architecture has authentication gaps that allow identity spoofing. "
                    f"Code auth posture: {auth_code:.0%}, Runtime auth enforcement: {auth_runtime:.0%}, "
                    f"Topology exposure: {exposure:.0%}."
                ),
                severity=severity,
                confidence=min(0.95, 0.5 + layers_confirming * 0.15),
                evidence_sast=[f"Auth posture in code: {auth_code:.0%}"] if auth_code < 0.9 else [],
                evidence_dast=[f"Runtime auth enforcement: {auth_runtime:.0%}"] if auth_runtime < 0.9 else [],
                evidence_repo=[f"Topology exposure: {exposure:.0%}"] if exposure > 0.2 else [],
                layers_confirming=layers_confirming,
                posture_indicators={"auth_code": auth_code, "auth_runtime": auth_runtime, "exposure": exposure},
                remediation_architecture="Add authentication requirement to all trust boundary crossings",
                remediation_code="Implement authentication middleware on all public-facing endpoints",
                remediation_verification="Re-run DAST to confirm auth is enforced at runtime",
                stride_posture_score=posture,
            ))

        return threats

    def _evaluate_tampering(self, posture: float, scores: dict, component_graph: dict) -> list[StrideThreathV2]:
        """Can data be modified in transit or at rest?"""
        threats = []

        if posture < self.THREAT_THRESHOLDS["low"]:
            severity = self._posture_to_severity(posture)

            crypto_code = scores.get("sast.crypto_posture", 1.0)
            crypto_runtime = scores.get("dast.runtime_encryption_status", 1.0)
            validation = scores.get("sast.validation_posture", 1.0)
            boundary = scores.get("repo.trust_boundary_integrity", 1.0)

            layers_confirming = sum([
                crypto_code < 0.7,
                crypto_runtime < 0.7,
                validation < 0.7,
                boundary < 0.7,
            ])

            threats.append(StrideThreathV2(
                id=f"stride-t-{uuid.uuid4().hex[:6]}",
                category="Tampering",
                title="Data Integrity Not Guaranteed Across Boundaries",
                description=(
                    f"Data can be modified in transit or through injection. "
                    f"Encryption posture: {crypto_code:.0%}, Input validation: {validation:.0%}, "
                    f"Boundary integrity: {boundary:.0%}."
                ),
                severity=severity,
                confidence=min(0.95, 0.5 + layers_confirming * 0.12),
                evidence_sast=[f"Crypto posture: {crypto_code:.0%}, Validation: {validation:.0%}"],
                evidence_dast=[f"Runtime encryption: {crypto_runtime:.0%}"] if crypto_runtime < 0.9 else [],
                evidence_repo=[f"Boundary integrity: {boundary:.0%}"] if boundary < 0.9 else [],
                layers_confirming=layers_confirming,
                posture_indicators={"crypto": crypto_code, "validation": validation, "boundary": boundary},
                remediation_architecture="Encrypt all data flows crossing trust boundaries; add integrity verification",
                remediation_code="Implement parameterized queries, input validation, and TLS for all connections",
                remediation_verification="Re-run DAST to confirm encryption active and injection not possible",
                stride_posture_score=posture,
            ))

        return threats

    def _evaluate_repudiation(self, posture: float, scores: dict, component_graph: dict) -> list[StrideThreathV2]:
        """Can actions be denied? Is there audit trail?"""
        threats = []

        if posture < self.THREAT_THRESHOLDS["low"]:
            severity = self._posture_to_severity(posture)
            logging_posture = scores.get("sast.logging_posture", 1.0)

            threats.append(StrideThreathV2(
                id=f"stride-r-{uuid.uuid4().hex[:6]}",
                category="Repudiation",
                title="Insufficient Audit Trail for Critical Actions",
                description=(
                    f"The architecture lacks comprehensive audit logging. "
                    f"Logging posture: {logging_posture:.0%}. "
                    f"Actions may not be traceable to their originator."
                ),
                severity=severity,
                confidence=0.7,
                evidence_sast=[f"Logging posture: {logging_posture:.0%}"],
                layers_confirming=1,
                posture_indicators={"logging": logging_posture},
                remediation_architecture="Design audit logging service; define what actions must be logged",
                remediation_code="Add structured logging for all authentication, authorization, and data modification events",
                remediation_verification="Verify logs capture who, what, when, where for all critical operations",
                stride_posture_score=posture,
            ))

        return threats

    def _evaluate_information_disclosure(self, posture: float, scores: dict, component_graph: dict) -> list[StrideThreathV2]:
        """Can sensitive data be exposed to unauthorized parties?"""
        threats = []

        if posture < self.THREAT_THRESHOLDS["low"]:
            severity = self._posture_to_severity(posture)

            crypto = scores.get("sast.crypto_posture", 1.0)
            encryption_runtime = scores.get("dast.runtime_encryption_status", 1.0)
            leakage = scores.get("dast.information_leakage", 0.0)
            sensitivity = scores.get("repo.data_sensitivity", 0.0)
            boundary = scores.get("repo.trust_boundary_integrity", 1.0)

            layers_confirming = sum([
                crypto < 0.7,
                leakage > 0.3,
                sensitivity > 0.7,
                boundary < 0.7,
            ])

            threats.append(StrideThreathV2(
                id=f"stride-i-{uuid.uuid4().hex[:6]}",
                category="Information Disclosure",
                title="Sensitive Data Exposure Risk",
                description=(
                    f"Sensitive data ({sensitivity:.0%} sensitivity level) may be exposed. "
                    f"Encryption: {crypto:.0%}, Runtime leakage: {leakage:.0%}, "
                    f"Boundary integrity: {boundary:.0%}."
                ),
                severity=severity,
                confidence=min(0.95, 0.5 + layers_confirming * 0.12),
                evidence_sast=[f"Crypto posture: {crypto:.0%}"],
                evidence_dast=[f"Info leakage level: {leakage:.0%}"] if leakage > 0.1 else [],
                evidence_repo=[f"Data sensitivity: {sensitivity:.0%}, Boundary: {boundary:.0%}"],
                layers_confirming=layers_confirming,
                posture_indicators={"crypto": crypto, "leakage": leakage, "sensitivity": sensitivity},
                remediation_architecture="Encrypt all sensitive data flows; implement data classification and access controls",
                remediation_code="Use TLS for all connections; encrypt sensitive fields at rest; remove verbose error responses",
                remediation_verification="Re-run DAST to confirm no information leakage in responses",
                stride_posture_score=posture,
            ))

        return threats

    def _evaluate_denial_of_service(self, posture: float, scores: dict, component_graph: dict) -> list[StrideThreathV2]:
        """Can the service be made unavailable?"""
        threats = []

        if posture < self.THREAT_THRESHOLDS["low"]:
            severity = self._posture_to_severity(posture)

            exposure = scores.get("repo.topology_exposure", 0.0)
            defense = scores.get("repo.defense_depth", 1.0)
            surface = scores.get("dast.exposed_attack_surface", 0.0)

            threats.append(StrideThreathV2(
                id=f"stride-d-{uuid.uuid4().hex[:6]}",
                category="Denial of Service",
                title="Service Availability Risk from Exposure",
                description=(
                    f"Public-facing components ({exposure:.0%} exposed) with limited defense depth "
                    f"({defense:.0%}) are vulnerable to availability attacks."
                ),
                severity=severity,
                confidence=0.65,
                evidence_repo=[f"Exposure: {exposure:.0%}, Defense depth: {defense:.0%}"],
                evidence_dast=[f"Attack surface: {surface:.0%}"] if surface > 0.2 else [],
                layers_confirming=1 + (1 if surface > 0.2 else 0),
                posture_indicators={"exposure": exposure, "defense": defense, "surface": surface},
                remediation_architecture="Add rate limiting, WAF, auto-scaling, and redundancy",
                remediation_code="Implement request timeouts, connection limits, and circuit breakers",
                remediation_verification="Load test to confirm service remains available under stress",
                stride_posture_score=posture,
            ))

        return threats

    def _evaluate_elevation_of_privilege(self, posture: float, scores: dict, component_graph: dict) -> list[StrideThreathV2]:
        """Can attacker gain higher access than intended?"""
        threats = []

        if posture < self.THREAT_THRESHOLDS["low"]:
            severity = self._posture_to_severity(posture)

            auth_code = scores.get("sast.auth_posture", 1.0)
            auth_runtime = scores.get("dast.runtime_auth_enforcement", 1.0)
            validation = scores.get("sast.validation_posture", 1.0)
            boundary = scores.get("repo.trust_boundary_integrity", 1.0)

            layers_confirming = sum([
                auth_code < 0.7,
                auth_runtime < 0.7,
                validation < 0.7,
                boundary < 0.7,
            ])

            threats.append(StrideThreathV2(
                id=f"stride-e-{uuid.uuid4().hex[:6]}",
                category="Elevation of Privilege",
                title="Privilege Escalation Possible Through Boundary Gaps",
                description=(
                    f"Insufficient access controls allow privilege escalation. "
                    f"Auth posture: {auth_code:.0%}, Boundary integrity: {boundary:.0%}, "
                    f"Input validation: {validation:.0%}."
                ),
                severity=severity,
                confidence=min(0.95, 0.5 + layers_confirming * 0.12),
                evidence_sast=[f"Auth: {auth_code:.0%}, Validation: {validation:.0%}"],
                evidence_dast=[f"Runtime auth: {auth_runtime:.0%}"] if auth_runtime < 0.9 else [],
                evidence_repo=[f"Boundary integrity: {boundary:.0%}"] if boundary < 0.9 else [],
                layers_confirming=layers_confirming,
                posture_indicators={"auth": auth_code, "validation": validation, "boundary": boundary},
                remediation_architecture="Implement least-privilege access; enforce authorization at every boundary",
                remediation_code="Add role-based access control; validate all privilege-changing operations",
                remediation_verification="Re-run DAST with authenticated scanning to confirm privilege boundaries hold",
                stride_posture_score=posture,
            ))

        return threats

    # ──── HELPERS ────────────────────────────────────────────────────────

    def _posture_to_severity(self, posture: float) -> str:
        """Convert posture score to severity (lower posture = higher severity)."""
        if posture < self.THREAT_THRESHOLDS["critical"]:
            return "Critical"
        elif posture < self.THREAT_THRESHOLDS["high"]:
            return "High"
        elif posture < self.THREAT_THRESHOLDS["medium"]:
            return "Medium"
        return "Low"
