"""Test v3 full engine pipeline against fixtures."""
import sys
sys.path.insert(0, ".")

from src.causal.v3.engine import CausalTMv3Engine
from src.causal.v3.fixtures.juice_shop import (
    JUICE_SHOP_COMPONENT_GRAPH,
    SAMPLE_SAST_FINDINGS,
    EXPECTED_STRIDE_THREATS,
)

# Run full pipeline
engine = CausalTMv3Engine()
result = engine.analyze(
    component_graph=JUICE_SHOP_COMPONENT_GRAPH,
    sast_findings=SAMPLE_SAST_FINDINGS,
    dast_findings=[],
)

print("=" * 60)
print("CausalTM v3 — Full Pipeline Test")
print("=" * 60)

# Results summary
print(f"\nOverall Risk: {result.overall_risk:.3f} ({result.risk_rating})")
print(f"Threats: {result.total_threats}")
print(f"Evidence: {result.evidence_count}")
print(f"Boundaries assessed: {result.boundaries_assessed}")
print(f"Uncertain divergences: {result.uncertain_divergences}")

# STRIDE postures
print(f"\nSTRIDE Posture per Category:")
for cat, posture in result.stride_posture_per_category.items():
    status = "CRITICAL" if posture < 0.3 else "HIGH" if posture < 0.5 else "MEDIUM" if posture < 0.7 else "LOW" if posture < 0.85 else "OK"
    print(f"  {cat}: {posture:.3f} ({status})")

# Fused architectural postures
print(f"\nFused Architectural Postures:")
for ap in result.fused_postures:
    print(f"  {ap.control_category.value}: {ap.posture:.3f} (conf={ap.confidence:.2f}, worst_crit={ap.worst_critical_boundary:.3f} at {ap.worst_critical_boundary_id})")

# Threats
print(f"\nSTRIDE Threats:")
for t in result.threats:
    print(f"  [{t.severity.value}] {t.category.value}")
    print(f"    Posture: {t.triggering_posture_value:.3f} (threshold: {t.posture_threshold_used})")
    print(f"    Boundaries: {t.affected_boundaries}")
    print(f"    Confidence: {t.confidence:.2f}")
    if t.traced_cwes:
        print(f"    CWEs: {t.traced_cwes}")

# Validate against expected threats
print(f"\nValidation against expected threats:")
expected_categories = {t["category"] for t in EXPECTED_STRIDE_THREATS}
actual_categories = {t.category.value for t in result.threats}

for exp in EXPECTED_STRIDE_THREATS:
    found = exp["category"] in actual_categories
    status = "PASS" if found else "FAIL"
    print(f"  [{status}] {exp['category']} ({exp['severity']}): {'detected' if found else 'MISSING'}")

extra = actual_categories - expected_categories
if extra:
    print(f"\n  Extra threats (not in fixture): {extra}")

# What-if test
print(f"\nWhat-If: Fix validation posture to 1.0")
what_if = engine.what_if("validation", 1.0, "Fix all validation issues")
print(f"  Risk before: {what_if.risk_before:.3f}")
print(f"  Risk after: {what_if.risk_after:.3f}")
print(f"  Risk reduction: {what_if.risk_before - what_if.risk_after:.3f}")
print(f"  Propagated effects: {len(what_if.propagated_effects)}")
for eff in what_if.propagated_effects:
    print(f"    {eff.affected_variable}: +{eff.predicted_change:.3f} (via {eff.rule_applied})")
    print(f"      Assumptions: {eff.assumptions_required}")
print(f"  STRIDE changes: {what_if.stride_changes}")

print()
print("=" * 60)
print("ENGINE TEST COMPLETE")
print("=" * 60)
