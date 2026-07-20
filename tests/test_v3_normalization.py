"""Test v3 normalization layer against fixtures."""
import sys
sys.path.insert(0, ".")

from src.causal.v3.normalization import NormalizationLayerV3
from src.causal.v3.models import SourceType
from src.causal.v3.fixtures.juice_shop import (
    JUICE_SHOP_COMPONENT_GRAPH,
    SAMPLE_SAST_FINDINGS,
    EXPECTED_BOUNDARY_ASSIGNMENTS,
)

norm = NormalizationLayerV3()
results = norm.normalize(SAMPLE_SAST_FINDINGS, SourceType.SAST, JUICE_SHOP_COMPONENT_GRAPH)

print(f"Normalized {len(results)} findings")
print()

all_pass = True
for ev in results:
    expected = EXPECTED_BOUNDARY_ASSIGNMENTS.get(ev.id)
    if expected:
        exp_comp, exp_boundary, exp_priority = expected
        actual_comp = ev.boundary_assignment.component_id
        actual_boundary = ev.boundary_assignment.boundary_id
        actual_priority = ev.boundary_assignment.priority.value
        match = (
            actual_comp == exp_comp
            and actual_boundary == exp_boundary
            and actual_priority == exp_priority
        )
        status = "PASS" if match else "FAIL"
        if not match:
            all_pass = False
        print(f"  [{status}] {ev.id}: comp={actual_comp} boundary={actual_boundary} priority={actual_priority}")
        if not match:
            print(f"         EXPECTED: comp={exp_comp} boundary={exp_boundary} priority={exp_priority}")
            print(f"         REASON: {ev.boundary_assignment.match_reason}")
    else:
        print(f"  [????] {ev.id}: no expected value defined")

print()
print("=" * 50)
print("ALL PASS" if all_pass else "SOME FAILURES — see above")
