"""Run v2 on full 23+10 findings for comparison."""
import sys, json
from pathlib import Path
sys.path.insert(0, ".")

from src.causal.v2.engine import CausalTMv2Engine
from src.causal.v3.fixtures.juice_shop_full import JUICE_SHOP_FULL_GRAPH, FULL_SAST_FINDINGS, FULL_DAST_FINDINGS

engine = CausalTMv2Engine()
engine.build(JUICE_SHOP_FULL_GRAPH, FULL_SAST_FINDINGS, FULL_DAST_FINDINGS)
result = engine.analyze()
roadmap = engine.roadmap_to_zero()

print(f"v2 Risk: {result.overall_risk:.3f} ({result.risk_rating})")
print(f"v2 Threats: {result.threat_model.total_threats}")
print(f"v2 Roadmap: {len(roadmap)} steps")
print(f"v2 STRIDE Posture:")
for cat, score in result.threat_model.posture_per_category.items():
    print(f"  {cat}: {score:.3f}")

# Compare with v3
v3_data = json.loads(Path("data/eval-v3-full-juice-shop.json").read_text())

print(f"\n{'='*60}")
print(f"  FULL COMPARISON (23 SAST + 10 DAST)")
print(f"{'='*60}")
print(f"  {'Metric':<30} {'v2':<20} {'v3':<20}")
print(f"  {'-'*30} {'-'*20} {'-'*20}")
print(f"  {'Overall Risk':<30} {result.overall_risk:<20.3f} {v3_data['results']['overall_risk']:<20.3f}")
print(f"  {'Risk Rating':<30} {result.risk_rating:<20} {v3_data['results']['risk_rating']:<20}")
print(f"  {'Total Threats':<30} {result.threat_model.total_threats:<20} {v3_data['results']['total_threats']:<20}")
print(f"  {'Roadmap Steps':<30} {len(roadmap):<20} {'4':<20}")
print(f"  {'Boundary Specificity':<30} {'Global':<20} {'Per-boundary':<20}")
print(f"  {'Sources Used':<30} {'SAST+DAST':<20} {'SAST+DAST+Repo':<20}")
print(f"  {'Uncertain Divergences':<30} {'N/A':<20} {v3_data['results']['uncertain_divergences']:<20}")
print(f"  {'Classification':<30} {'Threshold only':<20} {'Hybrid':<20}")
print(f"\n  STRIDE Posture:")
print(f"  {'Category':<30} {'v2':<20} {'v3':<20}")
print(f"  {'-'*30} {'-'*20} {'-'*20}")
for cat, v2_score in result.threat_model.posture_per_category.items():
    v3_score = v3_data['stride_posture'].get(cat, 'N/A')
    v3_str = f"{v3_score:.3f}" if isinstance(v3_score, float) else str(v3_score)
    print(f"  {cat:<30} {v2_score:<20.3f} {v3_str:<20}")
