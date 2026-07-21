"""
CausalTM v3 — Repo/Topology Sub-DAG (Layer C)

Responsibility:
  - Compute BOUNDARY-SPECIFIC structural posture from the component graph
  - Assesses architectural design properties WITHOUT needing external findings
  - Evaluates: topology exposure, boundary integrity, defense-in-depth, data sensitivity

Causal claim:
  "Architectural configuration at boundary B determines the DESIGNED security
   properties of that boundary. Structural weaknesses (public exposure without
   auth, sensitive data without encryption, missing defense layers) are evidence
   of architectural control gaps — independent of any SAST/DAST findings."

Must NOT:
  - Produce global/architectural posture (that's Layer D's job)
  - Make code-level claims (Repo is structural/design-level only)
  - Require external scan findings (operates on component_graph alone)
"""

import logging
from collections import defaultdict

from src.causal.v3.interfaces import CausalSubDAG
from src.causal.v3.models import (
    BoundaryAssignmentPriority,
    BoundaryPosture,
    ControlCategory,
    NormalizedEvidence,
    SourceType,
)

logger = logging.getLogger(__name__)


class RepoSubDAGV3(CausalSubDAG):
    """
    v3 Repo Sub-DAG — computes boundary-specific structural posture.

    Unlike SAST/DAST sub-DAGs which process external findings, the Repo
    sub-DAG derives posture directly from the component graph's structural
    properties:
      - Auth posture: does this boundary have authentication on public components?
      - Crypto posture: are flows at this boundary encrypted?
      - Validation posture: is there a defense layer between external and internal?
      - Logging posture: are components in this boundary configured for auditing?

    Each boundary gets a posture score based on what security controls the
    DESIGN provides — regardless of whether specific vulnerabilities exist.
    """

    def __init__(self):
        self._component_graph: dict = {}
        self._boundary_postures: list[BoundaryPosture] = []
        self._built = False

    def source_type(self) -> SourceType:
        return SourceType.REPO

    def causal_strength(self) -> float:
        """Repo: structural design properties, architecture-level."""
        return 0.60

    def build(self, evidence: list[NormalizedEvidence]) -> None:
        """
        Build from normalized evidence.

        For Repo sub-DAG, the primary input is the component_graph (passed
        separately via build_from_graph). NormalizedEvidence from repo scanners
        (secret detection, dependency scanning) would be handled here if present.
        """
        # Repo sub-DAG primarily works from the component graph
        # Any repo-specific findings (secrets, deps) are handled as supplementary
        self._repo_evidence = [e for e in evidence if e.source_type == SourceType.REPO]
        self._built = True

    def build_from_graph(self, component_graph: dict) -> None:
        """
        Build structural posture directly from the component graph.

        This is the primary entry point for the Repo sub-DAG.
        """
        self._component_graph = component_graph
        self._built = True

        components = component_graph.get("components", [])
        flows = component_graph.get("data_flows", [])
        boundaries = component_graph.get("trust_boundaries", [])

        logger.info(
            f"[Repo Sub-DAG v3] Building from graph: "
            f"{len(components)} components, {len(flows)} flows, {len(boundaries)} boundaries"
        )

    def compute_boundary_postures(self) -> list[BoundaryPosture]:
        """
        Compute structural posture for each boundary.

        Evaluates 4 control categories based on design properties:
          - auth: do components at this boundary have authentication?
          - crypto: are flows at/to this boundary encrypted?
          - validation: is there input filtering/defense at this boundary?
          - logging: are components configured for audit logging?
        """
        if not self._built:
            raise RuntimeError("Must call build_from_graph() before compute_boundary_postures()")

        components = self._component_graph.get("components", [])
        flows = self._component_graph.get("data_flows", [])
        boundaries = self._component_graph.get("trust_boundaries", [])

        postures: list[BoundaryPosture] = []

        for boundary in boundaries:
            boundary_id = boundary["id"]
            comp_ids = set(boundary.get("component_ids", []))

            # Get components in this boundary
            boundary_comps = [c for c in components if c["id"] in comp_ids]
            if not boundary_comps:
                continue

            # Get flows involving this boundary's components
            boundary_flows = [
                f for f in flows
                if f.get("source_id") in comp_ids or f.get("target_id") in comp_ids
            ]

            # Compute each control category posture
            auth_posture = self._compute_auth_posture(boundary_comps, boundary_flows)
            crypto_posture = self._compute_crypto_posture(boundary_comps, boundary_flows)
            validation_posture = self._compute_validation_posture(boundary_comps, boundary_flows, boundaries)
            logging_posture = self._compute_logging_posture(boundary_comps)

            # Create BoundaryPosture for each category
            for category, posture_value, evidence_summary in [
                (ControlCategory.AUTH, auth_posture, self._auth_evidence(boundary_comps, boundary_flows)),
                (ControlCategory.CRYPTO, crypto_posture, self._crypto_evidence(boundary_flows)),
                (ControlCategory.VALIDATION, validation_posture, self._validation_evidence(boundary_comps, boundary_flows)),
                (ControlCategory.LOGGING, logging_posture, self._logging_evidence(boundary_comps)),
            ]:
                postures.append(BoundaryPosture(
                    boundary_id=boundary_id,
                    component_id=boundary_comps[0]["id"] if boundary_comps else "unknown",
                    control_category=category,
                    source_type=SourceType.REPO,
                    posture=round(posture_value, 4),
                    causal_strength=self.causal_strength(),
                    contributing_evidence_ids=[],  # Structural — no external finding IDs
                    evidence_count=0,
                    weighted_deficit=round(1.0 - posture_value, 4),
                    confidence=0.75,  # Structural assessment — moderate confidence
                    boundary_assignment_priority=BoundaryAssignmentPriority.DIRECT_MATCH,
                    coverage_fraction=1.0,  # Architecture is fully visible
                    evidence_summary=evidence_summary,
                ))

        self._boundary_postures = postures

        logger.info(
            f"[Repo Sub-DAG v3] Computed {len(postures)} boundary postures. "
            f"Lowest: {min((p.posture for p in postures), default=1.0):.2f}"
        )

        return postures

    # ══════════════════════════════════════════════════════════════════════
    # POSTURE COMPUTATIONS
    # ══════════════════════════════════════════════════════════════════════

    def _compute_auth_posture(self, comps: list[dict], flows: list[dict]) -> float:
        """
        Auth posture for a boundary.

        Evaluates:
          - Do public-facing components have authentication? (0.4 weight)
          - Are incoming flows authenticated? (0.4 weight)
          - Is there no hardcoded/weak auth design? (0.2 weight)
        """
        if not comps:
            return 1.0

        # Public components with auth
        public_comps = [c for c in comps if c.get("is_public_facing")]
        if public_comps:
            authed_public = sum(1 for c in public_comps if c.get("has_authentication"))
            public_auth_score = authed_public / len(public_comps)
        else:
            public_auth_score = 1.0  # No public components = no auth needed

        # Incoming flows with auth
        incoming = [f for f in flows if f.get("crosses_trust_boundary")]
        if incoming:
            authed_flows = sum(1 for f in incoming if f.get("is_authenticated"))
            flow_auth_score = authed_flows / len(incoming)
        else:
            flow_auth_score = 1.0

        # Design quality (assume OK unless components explicitly lack auth)
        all_comps_needing_auth = [c for c in comps if c.get("type") == "process"]
        if all_comps_needing_auth:
            design_score = sum(1 for c in all_comps_needing_auth if c.get("has_authentication")) / len(all_comps_needing_auth)
        else:
            design_score = 1.0

        return 0.4 * public_auth_score + 0.4 * flow_auth_score + 0.2 * design_score

    def _compute_crypto_posture(self, comps: list[dict], flows: list[dict]) -> float:
        """
        Crypto posture for a boundary.

        Evaluates:
          - Are flows encrypted? (0.5 weight)
          - Do components have encryption enabled? (0.3 weight)
          - Are sensitive data flows encrypted? (0.2 weight — extra penalty if not)
        """
        if not flows:
            return 1.0

        # Flow encryption
        encrypted_flows = sum(1 for f in flows if f.get("is_encrypted"))
        flow_score = encrypted_flows / len(flows)

        # Component encryption
        if comps:
            encrypted_comps = sum(1 for c in comps if c.get("has_encryption"))
            comp_score = encrypted_comps / len(comps)
        else:
            comp_score = 1.0

        # Sensitive data flows — extra penalty if unencrypted
        sensitive_flows = [
            f for f in flows
            if any(s in (f.get("data_sensitivity") or []) for s in ["credentials", "pii", "secret", "financial"])
        ]
        if sensitive_flows:
            encrypted_sensitive = sum(1 for f in sensitive_flows if f.get("is_encrypted"))
            sensitive_score = encrypted_sensitive / len(sensitive_flows)
        else:
            sensitive_score = 1.0

        return 0.5 * flow_score + 0.3 * comp_score + 0.2 * sensitive_score

    def _compute_validation_posture(
        self, comps: list[dict], flows: list[dict], all_boundaries: list[dict]
    ) -> float:
        """
        Validation/defense posture for a boundary.

        Evaluates:
          - Is there a defense layer between external and this boundary? (0.4)
          - Are there boundary-crossing flows without auth? (0.3)
          - Component count / defense depth indicator (0.3)
        """
        # Defense depth: is this boundary behind another boundary?
        # External boundaries have no defense layer in front
        trust_level = None
        for b in all_boundaries:
            for c in comps:
                if c["id"] in b.get("component_ids", []):
                    trust_level = b.get("trust_level")
                    break

        if trust_level == "external":
            depth_score = 0.3  # External — minimal defense by design
        elif trust_level == "dmz":
            depth_score = 0.6  # DMZ — some defense (behind edge)
        else:
            depth_score = 0.9  # Internal — behind multiple layers

        # Unprotected boundary crossings
        crossing_flows = [f for f in flows if f.get("crosses_trust_boundary")]
        if crossing_flows:
            protected = sum(1 for f in crossing_flows if f.get("is_authenticated") or f.get("is_encrypted"))
            crossing_score = protected / len(crossing_flows)
        else:
            crossing_score = 1.0

        # Component defense (has auth OR encryption = some defense)
        process_comps = [c for c in comps if c.get("type") == "process"]
        if process_comps:
            defended = sum(1 for c in process_comps if c.get("has_authentication") or c.get("has_encryption"))
            comp_defense_score = defended / len(process_comps)
        else:
            comp_defense_score = 1.0

        return 0.4 * depth_score + 0.3 * crossing_score + 0.3 * comp_defense_score

    def _compute_logging_posture(self, comps: list[dict]) -> float:
        """
        Logging posture for a boundary.

        Structural assessment — we cannot determine logging from the component
        graph alone (it's a runtime concern). Default to 0.8 (assumed present
        unless findings indicate otherwise).

        This is intentionally conservative: the Repo sub-DAG acknowledges
        it cannot fully assess logging from architecture alone.
        """
        # If there are data stores, they should have audit capability
        data_stores = [c for c in comps if c.get("type") == "data_store"]
        if data_stores:
            return 0.7  # Data stores need audit logging — assume partial

        return 0.8  # Default — no structural evidence of logging gap

    # ══════════════════════════════════════════════════════════════════════
    # EVIDENCE SUMMARIES
    # ══════════════════════════════════════════════════════════════════════

    def _auth_evidence(self, comps: list[dict], flows: list[dict]) -> list[str]:
        evidence = []
        public = [c for c in comps if c.get("is_public_facing")]
        if public:
            authed = sum(1 for c in public if c.get("has_authentication"))
            evidence.append(f"{authed}/{len(public)} public components have authentication")
        incoming = [f for f in flows if f.get("crosses_trust_boundary")]
        if incoming:
            authed = sum(1 for f in incoming if f.get("is_authenticated"))
            evidence.append(f"{authed}/{len(incoming)} boundary-crossing flows are authenticated")
        return evidence

    def _crypto_evidence(self, flows: list[dict]) -> list[str]:
        evidence = []
        if flows:
            encrypted = sum(1 for f in flows if f.get("is_encrypted"))
            evidence.append(f"{encrypted}/{len(flows)} flows are encrypted")
        sensitive = [f for f in flows if any(s in (f.get("data_sensitivity") or []) for s in ["credentials", "pii"])]
        if sensitive:
            enc_sensitive = sum(1 for f in sensitive if f.get("is_encrypted"))
            evidence.append(f"{enc_sensitive}/{len(sensitive)} sensitive data flows encrypted")
        return evidence

    def _validation_evidence(self, comps: list[dict], flows: list[dict]) -> list[str]:
        evidence = []
        crossing = [f for f in flows if f.get("crosses_trust_boundary")]
        if crossing:
            protected = sum(1 for f in crossing if f.get("is_authenticated") or f.get("is_encrypted"))
            evidence.append(f"{protected}/{len(crossing)} boundary crossings have protection")
        process_comps = [c for c in comps if c.get("type") == "process"]
        if process_comps:
            defended = sum(1 for c in process_comps if c.get("has_authentication") or c.get("has_encryption"))
            evidence.append(f"{defended}/{len(process_comps)} processes have defense mechanisms")
        return evidence

    def _logging_evidence(self, comps: list[dict]) -> list[str]:
        data_stores = [c for c in comps if c.get("type") == "data_store"]
        if data_stores:
            return ["Data stores present — audit logging expected but not verifiable from architecture alone"]
        return ["No structural evidence of logging gap (design-level assessment)"]
