"""
CausalTM v3 — Master Causal DAG (Layer E)

Responsibility:
  - Cross-domain reasoning over fused architectural posture variables
  - Apply cross-layer dependency rules with explicit assumptions
  - Compute STRIDE posture per category
  - Support what-if and counterfactual queries
  - Compute overall risk

Must NOT:
  - Consume raw findings directly
  - Become source-specific
  - Replace sub-DAGs' local reasoning
"""

import logging
from typing import Optional

from src.causal.v3.models import (
    CausalEffect,
    ControlCategory,
    CrossLayerRule,
    FusedArchitecturalPosture,
    FusionLayerOutput,
    StrideCategory,
    WhatIfResult,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# CROSS-LAYER DEPENDENCY RULES
# ═══════════════════════════════════════════════════════════════════════════════

CROSS_LAYER_RULES = [
    CrossLayerRule(
        id="rule-1",
        trigger_variable="arch.auth_posture",
        trigger_condition="improves",
        effect_variable="arch.runtime_auth",
        strength=0.70,
        assumptions=["Code deployed via CI/CD", "Improved code in active runtime path"],
        applicability="When code-level auth improvements are deployed",
    ),
    CrossLayerRule(
        id="rule-2",
        trigger_variable="arch.crypto_posture",
        trigger_condition="improves",
        effect_variable="arch.runtime_crypto",
        strength=0.60,
        assumptions=["Crypto code is reachable at runtime"],
        applicability="When crypto implementation changes reach production",
    ),
    CrossLayerRule(
        id="rule-3",
        trigger_variable="arch.validation_posture",
        trigger_condition="improves",
        effect_variable="arch.attack_surface",
        strength=0.50,
        assumptions=["Validation code is on input processing path"],
        applicability="When validation improvements cover input boundaries",
    ),
    CrossLayerRule(
        id="rule-4",
        trigger_variable="arch.defense_depth",
        trigger_condition="improves",
        effect_variable="arch.attack_surface",
        strength=0.60,
        assumptions=["Architectural change is deployed"],
        applicability="When defense-in-depth layers are added",
    ),
    CrossLayerRule(
        id="rule-5",
        trigger_variable="arch.topology_exposure",
        trigger_condition="improves",
        effect_variable="arch.attack_surface",
        strength=0.80,
        assumptions=["Network/infra change is applied"],
        applicability="When network exposure is reduced",
    ),
    CrossLayerRule(
        id="rule-6",
        trigger_variable="arch.boundary_integrity",
        trigger_condition="improves",
        effect_variable="arch.data_leakage",
        strength=0.50,
        assumptions=["Boundary enforcement is active at runtime"],
        applicability="When trust boundary controls are enforced",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# STRIDE POSTURE MAPPING
# ═══════════════════════════════════════════════════════════════════════════════

# Each STRIDE category is determined by a weighted combination of control postures.
# This defines WHICH controls contribute to WHICH STRIDE category.

STRIDE_CONTROL_MAPPING = {
    StrideCategory.SPOOFING: [
        (ControlCategory.AUTH, 0.60),
        (ControlCategory.CRYPTO, 0.40),
    ],
    StrideCategory.TAMPERING: [
        (ControlCategory.VALIDATION, 0.60),
        (ControlCategory.CRYPTO, 0.40),
    ],
    StrideCategory.REPUDIATION: [
        (ControlCategory.LOGGING, 0.70),
        (ControlCategory.AUTH, 0.30),
    ],
    StrideCategory.INFORMATION_DISCLOSURE: [
        (ControlCategory.CRYPTO, 0.55),
        (ControlCategory.VALIDATION, 0.45),
    ],
    StrideCategory.DENIAL_OF_SERVICE: [
        (ControlCategory.VALIDATION, 0.70),
        (ControlCategory.AUTH, 0.30),
    ],
    StrideCategory.ELEVATION_OF_PRIVILEGE: [
        (ControlCategory.AUTH, 0.50),
        (ControlCategory.VALIDATION, 0.50),
    ],
}


class MasterDAGV3:
    """
    v3 Master Causal DAG — cross-domain reasoning over fused posture.

    Operates ONLY on fused architectural posture variables from Layer D.
    Computes STRIDE category postures and overall risk.
    Supports what-if queries with cross-layer propagation.
    """

    def __init__(self):
        self._fusion_output: Optional[FusionLayerOutput] = None
        self._posture_values: dict[str, float] = {}  # control_category → posture
        self._stride_postures: dict[str, float] = {}  # STRIDE category → posture
        self._overall_risk: float = 0.0
        self._built = False

    def build(self, fusion_output: FusionLayerOutput) -> None:
        """
        Build the master DAG from fused posture variables.

        Extracts posture values and computes STRIDE category postures.
        """
        self._fusion_output = fusion_output

        # Extract posture values into lookup
        self._posture_values = {}
        for ap in fusion_output.postures:
            self._posture_values[ap.control_category.value] = ap.posture

        # Ensure all categories have a value (default 1.0 = no evidence of gap)
        for cat in ControlCategory:
            if cat.value not in self._posture_values:
                self._posture_values[cat.value] = 1.0

        # Compute STRIDE postures
        self._stride_postures = self.compute_stride_postures()

        # Compute overall risk
        self._overall_risk = self.compute_overall_risk()

        self._built = True

        logger.info(
            f"[Master DAG v3] Built. Postures: {self._posture_values}. "
            f"Overall risk: {self._overall_risk:.3f}"
        )

    def compute_stride_postures(self) -> dict[str, float]:
        """
        Compute STRIDE posture per category from fused architectural postures.

        Each STRIDE category = weighted combination of relevant control postures.
        """
        stride_postures = {}

        for stride_cat, control_weights in STRIDE_CONTROL_MAPPING.items():
            weighted_sum = 0.0
            total_weight = 0.0

            for control_cat, weight in control_weights:
                posture = self._posture_values.get(control_cat.value, 1.0)
                weighted_sum += weight * posture
                total_weight += weight

            stride_posture = weighted_sum / total_weight if total_weight > 0 else 1.0
            stride_postures[stride_cat.value] = round(stride_posture, 4)

        return stride_postures

    def compute_overall_risk(self) -> float:
        """
        Compute overall risk from STRIDE postures.

        Risk = 1 - average(STRIDE postures)
        Higher risk = lower average posture across STRIDE categories.
        """
        if not self._stride_postures:
            return 0.0

        avg_posture = sum(self._stride_postures.values()) / len(self._stride_postures)
        return round(1.0 - avg_posture, 4)

    def what_if(
        self,
        variable: str,
        new_value: float,
        description: str = "",
    ) -> WhatIfResult:
        """
        Run a what-if analysis: "If we change this posture, what happens?"

        Propagates effects through cross-layer rules.
        """
        if not self._built:
            raise RuntimeError("Must call build() before what_if()")

        old_value = self._posture_values.get(variable, 1.0)
        delta = new_value - old_value

        if abs(delta) < 0.001:
            return WhatIfResult(
                description=description or f"No change to {variable}",
                intervention_variable=variable,
                old_value=old_value,
                new_value=new_value,
                risk_before=self._overall_risk,
                risk_after=self._overall_risk,
            )

        # Apply the intervention
        new_postures = dict(self._posture_values)
        new_postures[variable] = new_value

        # Propagate through cross-layer rules
        direct_effects = []
        propagated_effects = []

        for rule in CROSS_LAYER_RULES:
            # Check if this rule's trigger matches our intervention
            trigger_cat = rule.trigger_variable.replace("arch.", "")
            if trigger_cat == variable and delta > 0:  # "improves" condition
                effect_cat = rule.effect_variable.replace("arch.", "")
                propagated_delta = delta * rule.strength

                # Only apply if effect variable exists and would improve
                if effect_cat in new_postures:
                    old_effect = new_postures[effect_cat]
                    new_effect = min(1.0, old_effect + propagated_delta)

                    if new_effect > old_effect:
                        new_postures[effect_cat] = new_effect
                        propagated_effects.append(CausalEffect(
                            intervention_variable=variable,
                            intervention_value=new_value,
                            affected_variable=effect_cat,
                            predicted_change=round(new_effect - old_effect, 4),
                            new_predicted_value=round(new_effect, 4),
                            rule_applied=rule.id,
                            assumptions_required=rule.assumptions,
                        ))

        # Recompute STRIDE postures with new values
        old_stride = dict(self._stride_postures)
        temp_postures = self._posture_values
        self._posture_values = new_postures
        new_stride = self.compute_stride_postures()
        new_risk = 1.0 - (sum(new_stride.values()) / len(new_stride))
        self._posture_values = temp_postures  # Restore

        stride_changes = {
            cat: round(new_stride.get(cat, 0) - old_stride.get(cat, 0), 4)
            for cat in new_stride
            if abs(new_stride.get(cat, 0) - old_stride.get(cat, 0)) > 0.001
        }

        return WhatIfResult(
            description=description or f"Set {variable} to {new_value}",
            intervention_variable=variable,
            old_value=old_value,
            new_value=new_value,
            direct_effects=direct_effects,
            propagated_effects=propagated_effects,
            risk_before=self._overall_risk,
            risk_after=round(new_risk, 4),
            stride_changes=stride_changes,
        )

    def get_cross_layer_rules(self) -> list[CrossLayerRule]:
        """Return all cross-layer dependency rules."""
        return CROSS_LAYER_RULES

    def get_stride_postures(self) -> dict[str, float]:
        """Return current STRIDE postures."""
        return dict(self._stride_postures)

    def get_overall_risk(self) -> float:
        """Return current overall risk."""
        return self._overall_risk

    def get_posture_values(self) -> dict[str, float]:
        """Return current control posture values."""
        return dict(self._posture_values)
