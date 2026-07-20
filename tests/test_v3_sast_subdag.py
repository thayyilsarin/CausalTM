"""Test v3 SAST sub-DAG against fixtures."""
import sys
sys.path.insert(0, ".")

from src.causal.v3.normalization import NormalizationLayerV3
from src.causal.v3.sast_subdag import SASTSubDAGV3
from src.causal.v3.models import SourceType
from src.causal.v3.fixtures.juice_shop import (
    JUICE_SHOP_COMPONENT_GRAPH,
    SAMPLE_SAST_FINDINGS,
    EXPECTED_BOUNDARY_POSTURES,
)

# Step 1: Normalize (Layer B)
norm = NormalizationLayerV3()
evidence = norm.normalize(SAMPLE_SAST_FINDINGS, SourceType.SAST, JUICE_SHOP_COMPONENT_GRAPH)

# Step 2: Compute boundary postures (Layer C)
sast_dag = SASTSubDAGV3()
sast_dag.build(evidence)
postures = sast_dag.compute_boundary_postures()

print(f"Boundary postures computed: {len(postures)}")
print()

all_pass = True
tolerance = 0.02  # Allow small rounding differences

for p in postures:
    key = (p.boundary_id, p.control_category.value)
    expected = EXPECTED_BOUNDARY_POSTURES.get(key)

    if expected is not None:
        diff = abs(p.posture - expected)
        match = diff <= tolerance
        status = "PASS" if match else "FAIL"
        if not match:
            all_pass = False
        print(f"  [{status}] {key[0]}/{key[1]}: posture={p.posture:.4f} expected={expected:.3f} (diff={diff:.4f})")
        print(f"         evidence: {p.evidence_count} findings, deficit={p.weighted_deficit:.2f}")
    else:
        print(f"  [XTRA] {key[0]}/{key[1]}: posture={p.posture:.4f} (no expected value — extra output)")

# Check for missing expected values
computed_keys = {(p.boundary_id, p.control_category.value) for p in postures}
for key, expected in EXPECTED_BOUNDARY_POSTURES.items():
    if key not in computed_keys:
        print(f"  [MISS] {key[0]}/{key[1]}: expected={expected:.3f} but NOT computed")
        all_pass = False

print()
print("=" * 50)
print("ALL PASS" if all_pass else "SOME FAILURES — see above")
