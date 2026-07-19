"""
CausalTM v2 — Generic Project Scanner.

This is the PRODUCTION entry point. Works for ANY project — no custom scripts needed.

Usage:
  python scripts/scan_project.py --repo /path/to/repo --sast results.sarif --dast zap-report.xml
  python scripts/scan_project.py --repo /path/to/repo --sast results.sarif
  python scripts/scan_project.py --repo /path/to/repo

All three inputs are handled:
  - Repo path (required): auto-detects architecture via 6 detectors
  - SAST report (optional): SARIF file from any SAST tool
  - DAST report (optional): ZAP/Netsparker XML file

Output:
  - data/reports/{project}-report.html
  - data/reports/{project}-report.md
  - data/diagrams/{project}-dfd.svg
  - data/diagrams/{project}-sast-subgraph.svg
  - data/diagrams/{project}-dast-subgraph.svg
  - data/diagrams/{project}-repo-subgraph.svg
  - data/diagrams/{project}-master-dag.svg
  - data/{project}-eval.json
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.causal.v2.engine import CausalTMv2Engine
from src.dfd.builder import DFDBuilder
from src.reporter.generator import ReportGenerator


def parse_args():
    parser = argparse.ArgumentParser(
        description="CausalTM v2 — Scan any project for STRIDE threats"
    )
    parser.add_argument(
        "--repo", required=True,
        help="Path to the cloned repository (local directory)"
    )
    parser.add_argument(
        "--sast", default=None,
        help="Path to SAST report (SARIF format)"
    )
    parser.add_argument(
        "--dast", default=None,
        help="Path to DAST report (ZAP XML or Netsparker XML)"
    )
    parser.add_argument(
        "--project-name", default=None,
        help="Project name (auto-detected from repo path if not provided)"
    )
    parser.add_argument(
        "--output-dir", default="data",
        help="Output directory for reports and diagrams (default: data/)"
    )
    return parser.parse_args()


def detect_architecture(repo_path: Path) -> dict:
    """
    Auto-detect architecture from repository using all 6 detectors.
    Note: v2 engine's _ensure_minimum_architecture() handles enrichment internally.
    """
    from src.analyzer.engine import AnalyzerEngine

    print(f"  Running architecture auto-detection on: {repo_path}")
    engine = AnalyzerEngine()

    # Run synchronously (wrap the async call)
    loop = asyncio.new_event_loop()
    component_graph = loop.run_until_complete(engine.analyze(repo_path))
    loop.close()

    return component_graph


def ingest_sast(sarif_path: Path) -> list[dict]:
    """Ingest SAST findings from SARIF file."""
    from src.ingestors.sarif_ingestor import SARIFIngestor

    ingestor = SARIFIngestor()
    findings = ingestor.parse(sarif_path)
    return [f.model_dump() for f in findings]


def ingest_dast(xml_path: Path) -> list[dict]:
    """Ingest DAST findings from ZAP/Netsparker XML."""
    from src.ingestors.zap_ingestor import ZAPIngestor

    ingestor = ZAPIngestor()
    findings = ingestor.parse(xml_path)
    return [f.model_dump() for f in findings]


def main():
    args = parse_args()
    repo_path = Path(args.repo)
    project_name = args.project_name or repo_path.name
    output_dir = Path(args.output_dir)

    print("=" * 70)
    print(f"CausalTM v2 — Scanning: {project_name}")
    print("=" * 70)
    print()

    # ──── Step 1: Auto-detect architecture ────────────────────────────────
    print("[1/5] Detecting architecture from repository...")
    if not repo_path.exists():
        print(f"  ERROR: Repository path does not exist: {repo_path}")
        sys.exit(1)

    component_graph = detect_architecture(repo_path)
    components = [c for c in component_graph.get("components", []) if c.get("metadata", {}).get("type") != "metadata"]
    print(f"  Components detected: {len(components)}")
    print(f"  Data flows: {len(component_graph.get('data_flows', []))}")
    print(f"  Trust boundaries: {len(component_graph.get('trust_boundaries', []))}")
    for comp in components[:5]:
        print(f"    • {comp.get('name', comp.get('id', '?'))} ({comp.get('type', '?')})")
    if len(components) > 5:
        print(f"    ... and {len(components) - 5} more")
    print()

    # ──── Step 2: Ingest SAST findings (optional) ─────────────────────────
    sast_findings = []
    if args.sast:
        sarif_path = Path(args.sast)
        if sarif_path.exists():
            print("[2/5] Ingesting SAST findings (SARIF)...")
            sast_findings = ingest_sast(sarif_path)
            print(f"  Findings: {len(sast_findings)}")
            sev_counts = Counter(f.get("severity", "?") for f in sast_findings)
            print(f"  By severity: {dict(sev_counts)}")
        else:
            print(f"[2/5] SAST file not found: {sarif_path} — skipping")
    else:
        print("[2/5] No SAST report provided — SAST sub-DAG will use repo-only evidence")
    print()

    # ──── Step 3: Ingest DAST findings (optional) ─────────────────────────
    dast_findings = []
    if args.dast:
        xml_path = Path(args.dast)
        if xml_path.exists():
            print("[3/5] Ingesting DAST findings (ZAP/Netsparker XML)...")
            dast_findings = ingest_dast(xml_path)
            print(f"  Findings: {len(dast_findings)}")
            sev_counts = Counter(f.get("severity", "?") for f in dast_findings)
            print(f"  By severity: {dict(sev_counts)}")
        else:
            print(f"[3/5] DAST file not found: {xml_path} — skipping")
    else:
        print("[3/5] No DAST report provided — DAST sub-DAG will be 'not observed'")
    print()

    # ──── Step 4: Run CausalTM v2 Engine ──────────────────────────────────
    print("[4/5] Running CausalTM v2 Engine...")
    engine = CausalTMv2Engine()
    engine.build(component_graph, sast_findings, dast_findings)
    result = engine.analyze()

    print(f"  Overall Risk: {result.overall_risk:.3f} ({result.risk_rating})")
    print(f"  STRIDE Threats: {result.threat_model.total_threats}")
    print(f"  STRIDE Posture:")
    for cat, score in result.threat_model.posture_per_category.items():
        status = "SECURE" if score > 0.85 else "AT RISK" if score < 0.5 else "PARTIAL"
        print(f"    {cat}: {score:.0%} ({status})")
    print()

    # Generate roadmap
    print("  Computing remediation roadmap...")
    roadmap = engine.roadmap_to_zero()
    print(f"  Roadmap: {len(roadmap)} steps to near-zero risk")
    for step in roadmap[:3]:
        cross = f" (+{len(step.get('cross_layer_effects', []))} cross-layer)" if step.get('cross_layer_effects') else ""
        print(f"    Step {step['step']}: {step['name']} ({step['layer']}){cross}")
    print()

    # ──── Step 5: Generate outputs ────────────────────────────────────────
    print("[5/5] Generating outputs...")

    reports_dir = output_dir / "reports"
    diagrams_dir = output_dir / "diagrams"
    reports_dir.mkdir(parents=True, exist_ok=True)
    diagrams_dir.mkdir(parents=True, exist_ok=True)

    # Build DFD
    dfd_builder = DFDBuilder()
    causal_compat = {
        "overall_risk": result.overall_risk, "risk_rating": result.risk_rating,
        "attack_paths": {}, "confirmed_exploitable": [], "confounder_adjustments": {},
        "high_risk_flows": [], "mediators": [], "counterfactuals": [],
        "graph_stats": {}, "threat_counts_by_element": {},
        "causal_attack_graph": {"paths": [], "choke_points": [], "total_paths": 0},
        "federated": {"layer_contributions": {}, "intermediate_scores": {}, "tactical_counterfactuals": []},
    }
    # Build counterfactuals for report from roadmap
    counterfactuals = []
    for step in roadmap:
        counterfactuals.append({
            "intervention": f"Fix {step['name']}",
            "recommendation": f"Fix {step['name']} ({step['layer']} layer): improve to {step['target_value']:.0%}. "
                + (f"Cross-layer: {', '.join(e['reason'] for e in step.get('cross_layer_effects', []))}" if step.get('cross_layer_effects') else ""),
            "risk_reduction_pct": step.get("stride_improvement", 0) * 100,
        })

    # Build attack paths from STRIDE threats for the report
    attack_paths_for_report = []
    for t in result.threat_model.threats:
        attack_paths_for_report.append({
            "path_names": ["Architecture Gap", f"{t.category} Threat", t.title[:40]],
            "score": 1.0 - t.stride_posture_score,
            "crosses_trust_boundary": True,
            "has_confirmed_steps": t.layers_confirming >= 2,
        })

    causal_compat["counterfactuals"] = counterfactuals
    causal_compat["causal_attack_graph"] = {
        "paths": attack_paths_for_report,
        "choke_points": [],
        "total_paths": len(attack_paths_for_report),
    }

    dfd_model = dfd_builder.build(component_graph, causal_compat)

    # Render DFD
    diagram_svg = None
    try:
        from src.renderer.graphviz_renderer import GraphvizRenderer
        renderer = GraphvizRenderer()
        svg_path = renderer.render(dfd_model, diagrams_dir / f"{project_name}-dfd.svg", format="svg")
        print(f"  DFD: {svg_path}")
        diagram_svg = Path(str(svg_path)).read_text(encoding="utf-8")
    except Exception as e:
        print(f"  DFD: SKIPPED ({e})")

    # Render sub-graphs
    master_dag_svg = None
    attack_graph_svg = None
    try:
        from src.renderer.causal_graph_renderer import CausalGraphRenderer
        causal_renderer = CausalGraphRenderer()

        for subdag, label in [
            (engine.sast_subdag, "SAST"),
            (engine.dast_subdag, "DAST"),
            (engine.repo_subdag, "Repo"),
        ]:
            path = causal_renderer.render_subgraph(
                subdag,
                title=f"{label} Sub-Graph — {project_name}",
                output_path=diagrams_dir / f"{project_name}-{label.lower()}-subgraph.svg",
            )
            if path:
                print(f"  {label} Sub-Graph: {path}")

        # Master DAG
        try:
            master_path = causal_renderer.render_subgraph(
                engine.master_dag,
                title=f"Master DAG — {project_name}",
                output_path=diagrams_dir / f"{project_name}-master-dag.svg",
            )
            if master_path:
                print(f"  Master DAG: {master_path}")
                master_dag_svg = Path(str(master_path)).read_text(encoding="utf-8")
        except Exception:
            pass

        # Attack graph (repo topology)
        try:
            ag_path = causal_renderer.render_subgraph(
                engine.repo_subdag,
                title=f"Attack Surface — {project_name}",
                output_path=diagrams_dir / f"{project_name}-attack-graph.svg",
            )
            if ag_path:
                print(f"  Attack Graph: {ag_path}")
                attack_graph_svg = Path(str(ag_path)).read_text(encoding="utf-8")
        except Exception:
            pass

    except Exception as e:
        print(f"  Diagrams: SKIPPED ({e})")

    # Convert threats for report
    threats = []
    for t in result.threat_model.threats:
        threats.append({
            "id": t.id,
            "category": t.category,
            "title": t.title,
            "description": t.description,
            "severity": t.severity,
            "confidence": t.confidence,
            "element_id": "",
            "element_name": "Architecture",
            "element_type": "architecture",
            "source": "STRIDE v2",
            "mitigations": [t.remediation_architecture, t.remediation_code, t.remediation_verification],
            "cwe_ids": t.affected_flows or [],
            "evidence": t.evidence_sast + t.evidence_dast + t.evidence_repo,
            "is_confirmed": t.layers_confirming >= 2,
            "causal_severity_score": t.stride_posture_score,
            "attack_vector": None,
            "prerequisites": [],
            "affected_data": [],
        })

    # Build counterfactuals for report
    counterfactuals = []
    for step in roadmap:
        counterfactuals.append({
            "intervention": f"Fix {step['name']}",
            "recommendation": f"Fix {step['name']} ({step['layer']} layer): improve to {step['target_value']:.0%}.",
            "risk_reduction_pct": step.get("stride_improvement", 0) * 100,
        })
    causal_compat["counterfactuals"] = counterfactuals

    # Generate HTML report
    reporter = ReportGenerator()
    reporter.generate_from_data(
        dfd_model=dfd_model,
        threats=threats,
        causal_result=causal_compat,
        diagram_svg=diagram_svg,
        master_dag_svg=master_dag_svg,
        attack_graph_svg=attack_graph_svg,
        project_name=project_name,
        scan_id=f"{project_name}-scan",
        output_path=reports_dir / f"{project_name}-report.html",
        format="html",
    )
    print(f"  HTML Report: {reports_dir / f'{project_name}-report.html'}")

    # Generate Markdown report
    reporter.generate_from_data(
        dfd_model=dfd_model,
        threats=threats,
        causal_result=causal_compat,
        project_name=project_name,
        scan_id=f"{project_name}-scan",
        output_path=reports_dir / f"{project_name}-report.md",
        format="markdown",
    )
    print(f"  Markdown Report: {reports_dir / f'{project_name}-report.md'}")

    # Save JSON results
    eval_output = {
        "project": project_name,
        "engine": "CausalTM v2",
        "repo_path": str(repo_path),
        "sast_findings": len(sast_findings),
        "dast_findings": len(dast_findings),
        "components_detected": len(components),
        "overall_risk": result.overall_risk,
        "risk_rating": result.risk_rating,
        "stride_threats": result.threat_model.total_threats,
        "stride_posture": result.threat_model.posture_per_category,
        "roadmap_steps": len(roadmap),
        "roadmap": roadmap[:5],
    }
    eval_path = output_dir / f"{project_name}-eval.json"
    eval_path.write_text(json.dumps(eval_output, indent=2, default=str))
    print(f"  Eval JSON: {eval_path}")

    # ──── Summary ─────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print(f"SCAN COMPLETE: {project_name}")
    print("=" * 70)
    print(f"  Risk: {result.overall_risk:.3f} ({result.risk_rating})")
    print(f"  STRIDE Threats: {result.threat_model.total_threats}")
    print(f"  Roadmap: {len(roadmap)} steps to zero")
    print(f"  Outputs: {reports_dir}/")
    print("=" * 70)


if __name__ == "__main__":
    main()
