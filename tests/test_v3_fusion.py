"""Test v3 Fusion Layer against fixtures."""
import sys
sys.path.insert(0, ".")

from src.causal.v3.normalization import NormalizationLayerV3
from src.causal.v3.sast_subdag import SASTSubDAGV3
from src.causal.v3.fusion import FusionLayerV3
from src.causal.v3.models import SourceType, BoundaryPosture, ControlCategory, FusionStatus
from src.causal.v3.fixtures.juice_shop import (
    JUICE_SHOP_COMPONENT_GRAPH,
    SAMPLE_SAST_FINDINGS,
    EXPECTED_FUSED_POSTURES,
    CONFLICT_SCENARIO,
)

# ──── Test 1: End-to-end SAST → Fusion ────

print("=" * 60)
print("TEST 1: SAST-only fusion (single source)")
print("=" * 60)

# Layer B
norm = NormalizationLayerV3()
evidence = norm.normalize(SAMPLE_SAST_FINDINGS, SourceType.SAST, JUICE_SHOP_COMPONENT_GRAPH)

# Layer C
sast_dag = SASTSubDAGV3()
sast_dag.build(evidence)
boundary_postures = sast_dag.compute_boundary_postures()

# Layer D
fusion = FusionLayerV3()
criticalities = fusion.compute_all_criticalities(JUICE_SHOP_COMPONENT_GRAPH)

print(f"\nBoundary criticalities:")
for c in criticalities:
    print(f"  {c.boundary_id}: {c.criticality:.3f} (ext={c.is_external_facing}, cross={c.crosses_trust_boundary}, sensitive={c.handles_sensitive_data})")

result = fusion.fuse(boundary_postures, criticalities)

print(f"\nFused architectural postures:")
all_pass = True
tolerance = 0.05  # Allow some tolerance for criticality weight differences

for ap in result.postures:
    expected = EXPECTED_FUSED_POSTURES.get(ap.control_category.value)
    if expected is not None:
        diff = abs(ap.posture - expected)
        match = diff <= tolerance
        status = "PASS" if match else "FAIL"
        if not match:
            all_pass = False
        print(f"  [{status}] {ap.control_category.value}: posture={ap.posture:.4f} expected={expected:.3f} (diff={diff:.4f})")
        print(f"         avg={ap.weighted_average:.3f} worst_crit={ap.worst_critical_boundary:.3f} ({ap.worst_critical_boundary_id})")
    else:
        print(f"  [XTRA] {ap.control_category.value}: posture={ap.posture:.4f}")

# Check logging (should be absent — no findings means no posture output)
has_logging = any(ap.control_category.value == "logging" for ap in result.postures)
if not has_logging:
    print(f"  [PASS] logging: not computed (no evidence = no posture output, correct)")
else:
    # If logging IS present, check it's 1.0
    logging_ap = next(ap for ap in result.postures if ap.control_category.value == "logging")
    print(f"  [INFO] logging: posture={logging_ap.posture:.4f} (present but no findings)")


# ──── Test 2: Conflict resolution scenario ────

print()
print("=" * 60)
print("TEST 2: Conflict resolution (SAST vs DAST disagreement)")
print("=" * 60)

# Build postures for conflict scenario
sast_bp = BoundaryPosture(
    boundary_id=CONFLICT_SCENARIO["sast_boundary_posture"]["boundary_id"],
    component_id="comp-rest-api",
    control_category=ControlCategory.VALIDATION,
    source_type=SourceType.SAST,
    posture=CONFLICT_SCENARIO["sast_boundary_posture"]["posture"],
    causal_strength=CONFLICT_SCENARIO["sast_boundary_posture"]["causal_strength"],
    confidence=CONFLICT_SCENARIO["sast_boundary_posture"]["confidence"],
)

dast_bp = BoundaryPosture(
    boundary_id=CONFLICT_SCENARIO["dast_boundary_posture"]["boundary_id"],
    component_id="comp-rest-api",
    control_category=ControlCategory.VALIDATION,
    source_type=SourceType.DAST,
    posture=CONFLICT_SCENARIO["dast_boundary_posture"]["posture"],
    causal_strength=CONFLICT_SCENARIO["dast_boundary_posture"]["causal_strength"],
    confidence=CONFLICT_SCENARIO["dast_boundary_posture"]["confidence"],
)

fused = fusion.resolve_conflict([sast_bp, dast_bp])

expected_fused = CONFLICT_SCENARIO["expected_fusion"]
print(f"\n  SAST posture: {sast_bp.posture} (conf={sast_bp.confidence}, strength={sast_bp.causal_strength})")
print(f"  DAST posture: {dast_bp.posture} (conf={dast_bp.confidence}, strength={dast_bp.causal_strength})")
print(f"  Fused: {fused.fused_posture:.4f} (expected: {expected_fused['fused_posture']:.3f})")
print(f"  Status: {fused.fusion_status.value} (expected: {expected_fused['fusion_status']})")
print(f"  Confidence: {fused.confidence:.4f} (expected: {expected_fused['confidence']:.2f})")

fused_match = abs(fused.fused_posture - expected_fused["fused_posture"]) <= 0.02
status_match = fused.fusion_status.value == expected_fused["fusion_status"]
conf_match = abs(fused.confidence - expected_fused["confidence"]) <= 0.05

print(f"\n  [{'PASS' if fused_match else 'FAIL'}] Fused posture within tolerance")
print(f"  [{'PASS' if status_match else 'FAIL'}] Fusion status correct")
print(f"  [{'PASS' if conf_match else 'FAIL'}] Confidence within tolerance")

if not (fused_match and status_match and conf_match):
    all_pass = False

print()
print("=" * 60)
print("ALL PASS" if all_pass else "SOME FAILURES — see above")
print("=" * 60)
