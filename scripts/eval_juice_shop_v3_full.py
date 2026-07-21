"""
CausalTM v3 Full Evaluation — OWASP Juice Shop (23 SAST + 10 DAST)

Runs the v3 engine on production-representative findings and generates:
  - Console summary
  - Polished v3 markdown report
  - Structured JSON for research

This is the evaluation artifact for the paper.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, ".")

from src.causal.v3.engine import CausalTMv3Engine
from src.causal.v3.report_renderer import V3ReportRenderer
from src.causal.v3.fixtures.juice_shop_full import (
    JUICE_SHOP_FULL_GRAPH,
    FULL_SAST_FINDINGS,
    FULL_DAST_FINDINGS,
)


def main():
    print("=" * 70)
    print("  CausalTM v3 Full Evaluation — OWASP Juice Shop")
    print("  23 SAST findings + 10 DAST findings")
    print("=" * 70)
    print()

    # Run v3 engine
    print("[1/4] Running CausalTM v3 engine...")
    engine = CausalTMv3Engine()
    result = engine.analyze(
        component_graph=JUICE_SHOP_FULL_GRAPH,
        sast_findings=FULL_SAST_FINDINGS,
        dast_findings=FULL_DAST_FINDINGS,
    )

    print(f"  Overall Risk: {result.overall_risk:.3f} ({result.risk_rating})")
    print(f"  Threats: {result.total_threats}")
    print(f"  Evidence: {result.evidence_count}")
    print(f"  Boundaries: {result.boundary_count} ({', '.join(result.boundaries_assessed)})")
    print(f"  Uncertain Divergences: {result.uncertain_divergences}")
    print()

    # STRIDE postures
    print("[2/4] STRIDE Posture per Category:")
    for cat, posture in sorted(result.stride_posture_per_category.items(), key=lambda x: x[1]):
        level = "CRITICAL" if posture < 0.3 else "HIGH" if posture < 0.5 else "MEDIUM" if posture < 0.7 else "LOW" if posture < 0.85 else "OK"
        print(f"  {cat:<25} {posture:.3f} ({level})")
    print()

    # Fused postures
    print("  Fused Architectural Postures:")
    for ap in sorted(result.fused_postures, key=lambda x: x.posture):
        print(f"    {ap.control_category.value:<12} {ap.posture:.3f} (conf={ap.confidence:.2f}, worst={ap.worst_critical_boundary:.3f} at {ap.worst_critical_boundary_id})")
    print()

    # Threats
    print("[3/4] STRIDE Threats:")
    for t in result.threats:
        print(f"  [{t.severity.value}] {t.category.value} — {t.classification_method.value}")
        print(f"       Boundaries: {t.affected_boundaries}")
        print(f"       Confidence: {t.confidence:.0%}")
    print()

    # Attack paths
    print("[4/4] Attack Paths:")
    paths = engine.get_attack_paths(max_paths=5)
    for p in paths:
        print(f"  Score {p['score']:.3f}: {' → '.join(p['node_names'])}")
    print()

    # What-if
    wif_validation = engine.what_if("validation", 1.0, "Fix all input validation issues")
    wif_auth = engine.what_if("auth", 1.0, "Fix all authentication issues")
    print("  What-If Analysis:")
    print(f"    Fix validation: risk {wif_validation.risk_before:.3f} → {wif_validation.risk_after:.3f} (−{wif_validation.risk_before - wif_validation.risk_after:.3f})")
    print(f"    Fix auth:       risk {wif_auth.risk_before:.3f} → {wif_auth.risk_after:.3f} (−{wif_auth.risk_before - wif_auth.risk_after:.3f})")
    print()

    # Generate report
    output_dir = Path("data/reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    renderer = V3ReportRenderer()
    report_path = renderer.render_to_file(
        result,
        output_dir / "juice-shop-v3-full-report.md",
        project_name="OWASP Juice Shop (Full Scan)",
        attack_paths=paths,
        what_if_results=[wif_validation, wif_auth],
    )
    print(f"  Report: {report_path}")

    # JSON output
    json_output = {
        "project": "OWASP Juice Shop",
        "engine": "CausalTM v3",
        "inputs": {
            "sast_findings": len(FULL_SAST_FINDINGS),
            "dast_findings": len(FULL_DAST_FINDINGS),
            "components": len(JUICE_SHOP_FULL_GRAPH["components"]),
            "data_flows": len(JUICE_SHOP_FULL_GRAPH["data_flows"]),
            "trust_boundaries": len(JUICE_SHOP_FULL_GRAPH["trust_boundaries"]),
        },
        "results": {
            "overall_risk": result.overall_risk,
            "risk_rating": result.risk_rating,
            "total_threats": result.total_threats,
            "evidence_count": result.evidence_count,
            "boundary_count": result.boundary_count,
            "boundaries_assessed": result.boundaries_assessed,
            "uncertain_divergences": result.uncertain_divergences,
            "average_confidence": result.average_confidence,
        },
        "stride_posture": result.stride_posture_per_category,
        "fused_postures": {
            ap.control_category.value: {
                "posture": ap.posture,
                "confidence": ap.confidence,
                "worst_critical": ap.worst_critical_boundary,
                "worst_critical_id": ap.worst_critical_boundary_id,
            }
            for ap in result.fused_postures
        },
        "threats": [
            {
                "category": t.category.value,
                "severity": t.severity.value,
                "classification_method": t.classification_method.value,
                "confidence": t.confidence,
                "affected_boundaries": t.affected_boundaries,
                "triggering_posture": t.triggering_posture_value,
            }
            for t in result.threats
        ],
        "attack_paths": [
            {"score": p["score"], "path": " → ".join(p["node_names"]), "hops": p.get("hops", 0)}
            for p in paths
        ],
        "what_if": {
            "fix_validation": {"risk_before": wif_validation.risk_before, "risk_after": wif_validation.risk_after},
            "fix_auth": {"risk_before": wif_auth.risk_before, "risk_after": wif_auth.risk_after},
        },
    }

    json_path = Path("data/eval-v3-full-juice-shop.json")
    json_path.write_text(json.dumps(json_output, indent=2, default=str), encoding="utf-8")
    print(f"  JSON: {json_path}")

    print()
    print("=" * 70)
    print("  EVALUATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
