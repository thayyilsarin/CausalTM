"""
Parameter sensitivity for the AMICT 2026 paper (Section "Parameter Sensitivity").

Re-runs the v3 engine on the same Juice Shop fixtures with the calibration
constant K (SAST and DAST sub-DAGs) and the fusion weight alpha overridden at
import, over 20 combinations: K in {2.0, 3.0, 4.0, 5.0} and alpha in
{0.4, 0.5, 0.6, 0.7, 0.8}. The engine code is not modified.

    python scripts/sensitivity_sweep.py

Writes data/sensitivity-sweep.json and prints one row per setting.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, ".")

import src.causal.v3.dast_subdag as dast_subdag
import src.causal.v3.fusion as fusion
import src.causal.v3.sast_subdag as sast_subdag
from src.causal.v3.engine import CausalTMv3Engine
from src.causal.v3.fixtures.juice_shop_full import (
    FULL_DAST_FINDINGS,
    FULL_SAST_FINDINGS,
    JUICE_SHOP_FULL_GRAPH,
)

K_VALUES = [2.0, 3.0, 4.0, 5.0]
ALPHA_VALUES = [0.4, 0.5, 0.6, 0.7, 0.8]


def run(k: float, alpha: float) -> dict:
    sast_subdag.K = k
    dast_subdag.K = k
    fusion.ALPHA = alpha
    engine = CausalTMv3Engine()
    result = engine.analyze(
        component_graph=JUICE_SHOP_FULL_GRAPH,
        sast_findings=FULL_SAST_FINDINGS,
        dast_findings=FULL_DAST_FINDINGS,
    )
    return {
        "K": k,
        "alpha": alpha,
        "overall_risk": round(result.overall_risk, 3),
        "risk_rating": result.risk_rating,
        "threats": result.total_threats,
        "categories": sorted(t.category.value for t in result.threats),
        "rule_matched": sum(t.classification_method.value == "rule_matched" for t in result.threats),
        "posture_derived": sum(t.classification_method.value == "posture_derived" for t in result.threats),
        "uncertain_divergences": result.uncertain_divergences,
    }


def main() -> None:
    defaults = (sast_subdag.K, dast_subdag.K, fusion.ALPHA)
    rows = []
    try:
        for k in K_VALUES:
            for alpha in ALPHA_VALUES:
                rows.append(run(k, alpha))
    finally:
        sast_subdag.K, dast_subdag.K, fusion.ALPHA = defaults

    print(f"{'K':>4} {'alpha':>6} {'risk':>6} {'rating':>8} {'threats':>8} {'rule/post':>10} {'diverg.':>8}")
    for r in rows:
        print(f"{r['K']:>4} {r['alpha']:>6} {r['overall_risk']:>6.3f} {r['risk_rating']:>8} "
              f"{r['threats']:>8} {str(r['rule_matched']) + '/' + str(r['posture_derived']):>10} "
              f"{r['uncertain_divergences']:>8}")
    risks = [r["overall_risk"] for r in rows]
    print(f"\nOverall risk ranges from {min(risks):.3f} to {max(risks):.3f} over {len(rows)} settings.")
    print("Identical in all settings:",
          ", ".join(name for name, key in [("threat count", "threats"), ("category set", "categories"),
                                           ("classification split", "rule_matched"), ("rating", "risk_rating")]
                    if len({json.dumps(r[key]) for r in rows}) == 1) or "none")

    out = Path("data/sensitivity-sweep.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"Written to {out}")


if __name__ == "__main__":
    main()
