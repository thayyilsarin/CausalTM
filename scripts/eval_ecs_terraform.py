"""
Evaluate CausalTM v2 against AWS ECS Fullstack App (Terraform).

Architecture modeled from actual Terraform modules:
- ALB (public-facing, HTTPS + HTTP listeners, internet-facing)
- ECS Client Service (React frontend container on Fargate)
- ECS Server Service (Node.js backend container on Fargate)
- DynamoDB (NoSQL database, no encryption at rest configured)
- S3 Bucket (storage for build artifacts)
- VPC with public/private subnets (network trust boundary)
- Security Groups (firewall rules)
- IAM Roles (access management)
- ECR (container registry)
- CodePipeline/CodeBuild/CodeDeploy (CI/CD pipeline)
"""

import json
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, ".")

from src.causal.v2.engine import CausalTMv2Engine
from src.dfd.builder import DFDBuilder
from src.reporter.generator import ReportGenerator
from src.ingestors.sarif_ingestor import SARIFIngestor


def build_ecs_terraform_architecture():
    """Build component graph from actual Terraform module analysis."""
    return {
        "components": [
            # ──── External Entities ────────────────────────────────────────
            {
                "id": "ext-internet-users",
                "name": "Internet Users",
                "type": "external_entity",
                "is_public_facing": True,
                "has_authentication": False,
                "has_encryption": False,
                "technology": "Browser/Mobile",
                "ports": [],
                "source_paths": [],
                "metadata": {},
                "trust_level": "external",
            },
            {
                "id": "ext-developers",
                "name": "Developers (CI/CD)",
                "type": "external_entity",
                "is_public_facing": False,
                "has_authentication": True,
                "has_encryption": True,
                "technology": "Git/CodePipeline",
                "ports": [],
                "source_paths": [],
                "metadata": {},
                "trust_level": "external",
            },
            # ──── DMZ Layer (Public Subnet) ────────────────────────────────
            {
                "id": "process-alb",
                "name": "Application Load Balancer",
                "type": "process",
                "is_public_facing": True,
                "has_authentication": False,
                "has_encryption": True,
                "technology": "AWS ALB (HTTP/HTTPS listeners)",
                "ports": [80, 443],
                "source_paths": ["Infrastructure/Modules/ALB/"],
                "metadata": {"aws_service": "ALB", "internal": "false", "http2": "enabled"},
                "trust_level": "dmz",
            },
            # ──── Application Layer (Private Subnet) ───────────────────────
            {
                "id": "process-ecs-client",
                "name": "ECS Client Service (React Frontend)",
                "type": "process",
                "is_public_facing": False,
                "has_authentication": False,
                "has_encryption": False,
                "technology": "AWS ECS Fargate (React/Node.js)",
                "ports": [80],
                "source_paths": ["Code/client/"],
                "metadata": {"aws_service": "ECS", "launch_type": "Fargate", "autoscaling": "enabled"},
                "trust_level": "internal",
            },
            {
                "id": "process-ecs-server",
                "name": "ECS Server Service (Node.js Backend)",
                "type": "process",
                "is_public_facing": False,
                "has_authentication": True,
                "has_encryption": False,
                "technology": "AWS ECS Fargate (Node.js/Express)",
                "ports": [3000],
                "source_paths": ["Code/server/"],
                "metadata": {"aws_service": "ECS", "launch_type": "Fargate", "autoscaling": "enabled"},
                "trust_level": "internal",
            },
            # ──── Data Layer ───────────────────────────────────────────────
            {
                "id": "data_store-dynamodb",
                "name": "DynamoDB Table",
                "type": "data_store",
                "is_public_facing": False,
                "has_authentication": True,
                "has_encryption": False,
                "technology": "AWS DynamoDB (PAY_PER_REQUEST)",
                "ports": [443],
                "source_paths": ["Infrastructure/Modules/Dynamodb/"],
                "metadata": {"aws_service": "DynamoDB", "billing": "PAY_PER_REQUEST", "encryption_at_rest": "default"},
                "trust_level": "internal",
            },
            {
                "id": "data_store-s3",
                "name": "S3 Bucket (Artifacts)",
                "type": "data_store",
                "is_public_facing": False,
                "has_authentication": True,
                "has_encryption": True,
                "technology": "AWS S3",
                "ports": [443],
                "source_paths": ["Infrastructure/Modules/S3/"],
                "metadata": {"aws_service": "S3"},
                "trust_level": "internal",
            },
            {
                "id": "data_store-ecr",
                "name": "ECR Container Registry",
                "type": "data_store",
                "is_public_facing": False,
                "has_authentication": True,
                "has_encryption": True,
                "technology": "AWS ECR",
                "ports": [443],
                "source_paths": ["Infrastructure/Modules/ECR/"],
                "metadata": {"aws_service": "ECR"},
                "trust_level": "internal",
            },
            # ──── CI/CD Pipeline ───────────────────────────────────────────
            {
                "id": "process-codepipeline",
                "name": "CodePipeline (CI/CD)",
                "type": "process",
                "is_public_facing": False,
                "has_authentication": True,
                "has_encryption": True,
                "technology": "AWS CodePipeline + CodeBuild + CodeDeploy",
                "ports": [],
                "source_paths": ["Infrastructure/Modules/CodePipeline/", "Infrastructure/Modules/CodeBuild/", "Infrastructure/Modules/CodeDeploy/"],
                "metadata": {"aws_service": "CodePipeline"},
                "trust_level": "internal",
            },
        ],
        "data_flows": [
            # User → ALB (public internet to DMZ)
            {
                "id": "flow-user-alb",
                "source_id": "ext-internet-users",
                "target_id": "process-alb",
                "protocol": "HTTPS/443",
                "is_encrypted": True,
                "is_authenticated": False,
                "crosses_trust_boundary": True,
                "data_types": ["http_requests", "user_input"],
                "data_sensitivity": ["credentials", "pii"],
                "description": "User traffic enters via ALB (internet → DMZ)",
            },
            # ALB → ECS Client (DMZ to private)
            {
                "id": "flow-alb-client",
                "source_id": "process-alb",
                "target_id": "process-ecs-client",
                "protocol": "HTTP/80",
                "is_encrypted": False,
                "is_authenticated": False,
                "crosses_trust_boundary": True,
                "data_types": ["proxied_requests"],
                "data_sensitivity": ["credentials"],
                "description": "ALB forwards to frontend (DMZ → private subnet)",
            },
            # ECS Client → ECS Server (internal API calls)
            {
                "id": "flow-client-server",
                "source_id": "process-ecs-client",
                "target_id": "process-ecs-server",
                "protocol": "HTTP/3000",
                "is_encrypted": False,
                "is_authenticated": False,
                "crosses_trust_boundary": False,
                "data_types": ["api_requests", "json_data"],
                "data_sensitivity": ["pii"],
                "description": "Frontend calls backend API (internal, no encryption)",
            },
            # ECS Server → DynamoDB (data access)
            {
                "id": "flow-server-dynamodb",
                "source_id": "process-ecs-server",
                "target_id": "data_store-dynamodb",
                "protocol": "HTTPS/443",
                "is_encrypted": True,
                "is_authenticated": True,
                "crosses_trust_boundary": False,
                "data_types": ["queries", "user_data", "application_data"],
                "data_sensitivity": ["pii", "internal"],
                "description": "Backend reads/writes DynamoDB via AWS SDK (IAM auth)",
            },
            # CodePipeline → ECR (push container images)
            {
                "id": "flow-pipeline-ecr",
                "source_id": "process-codepipeline",
                "target_id": "data_store-ecr",
                "protocol": "HTTPS/443",
                "is_encrypted": True,
                "is_authenticated": True,
                "crosses_trust_boundary": False,
                "data_types": ["container_images"],
                "data_sensitivity": ["internal"],
                "description": "CI/CD pushes built images to ECR",
            },
            # CodePipeline → S3 (artifacts)
            {
                "id": "flow-pipeline-s3",
                "source_id": "process-codepipeline",
                "target_id": "data_store-s3",
                "protocol": "HTTPS/443",
                "is_encrypted": True,
                "is_authenticated": True,
                "crosses_trust_boundary": False,
                "data_types": ["build_artifacts", "source_code"],
                "data_sensitivity": ["confidential"],
                "description": "CI/CD stores build artifacts in S3",
            },
            # Developers → CodePipeline (trigger deployments)
            {
                "id": "flow-dev-pipeline",
                "source_id": "ext-developers",
                "target_id": "process-codepipeline",
                "protocol": "HTTPS",
                "is_encrypted": True,
                "is_authenticated": True,
                "crosses_trust_boundary": True,
                "data_types": ["git_push", "deployment_trigger"],
                "data_sensitivity": ["credentials"],
                "description": "Developers push code triggering pipeline",
            },
        ],
        "trust_boundaries": [
            {
                "id": "tb-internet",
                "name": "Internet (Untrusted)",
                "trust_level": "external",
                "component_ids": ["ext-internet-users", "ext-developers"],
            },
            {
                "id": "tb-dmz",
                "name": "Public Subnet (DMZ)",
                "trust_level": "dmz",
                "component_ids": ["process-alb"],
            },
            {
                "id": "tb-private",
                "name": "Private Subnet (Application + Data)",
                "trust_level": "internal",
                "component_ids": [
                    "process-ecs-client", "process-ecs-server",
                    "data_store-dynamodb", "data_store-s3", "data_store-ecr",
                    "process-codepipeline",
                ],
            },
        ],
        "metadata": {"project_name": "AWS ECS Fullstack App (Terraform)"},
    }


def main():
    print("=" * 70)
    print("CausalTM v2 Evaluation — AWS ECS Fullstack App (Terraform)")
    print("=" * 70)
    print()

    # ──── Step 1: Load architecture ──────────────────────────────────────
    print("[1/5] Building architecture from Terraform analysis...")
    component_graph = build_ecs_terraform_architecture()
    components = [c for c in component_graph["components"] if c.get("metadata", {}).get("type") != "metadata"]
    print(f"  Components: {len(components)}")
    print(f"  Data Flows: {len(component_graph['data_flows'])}")
    print(f"  Trust Boundaries: {len(component_graph['trust_boundaries'])}")
    for c in components:
        print(f"    • {c['name']} ({c['type']})")
    print()

    # ──── Step 2: Ingest SAST ────────────────────────────────────────────
    sast_findings = []
    sarif_path = Path("data/ecs-terraform-semgrep.sarif")
    if sarif_path.exists():
        print("[2/5] Ingesting Semgrep SAST findings...")
        ingestor = SARIFIngestor()
        findings_raw = ingestor.parse(sarif_path)
        sast_findings = [f.model_dump() for f in findings_raw]
        print(f"  Findings: {len(sast_findings)}")
        sev_counts = Counter(f["severity"] for f in sast_findings)
        print(f"  By severity: {dict(sev_counts)}")
    else:
        print("[2/5] No SARIF file — SAST sub-DAG will have no base variables")
    print()

    # ──── Step 3: Run v2 Engine ──────────────────────────────────────────
    print("[3/5] Running CausalTM v2 Engine...")
    engine = CausalTMv2Engine()
    engine.build(component_graph, sast_findings, dast_findings=[])
    result = engine.analyze()

    print(f"  Overall Risk: {result.overall_risk:.3f} ({result.risk_rating})")
    print(f"  STRIDE Threats: {result.threat_model.total_threats}")
    print(f"  STRIDE Posture:")
    for cat, score in result.threat_model.posture_per_category.items():
        status = "SECURE" if score > 0.85 else "AT RISK" if score < 0.5 else "PARTIAL"
        print(f"    {cat}: {score:.0%} ({status})")
    print()

    # Roadmap
    print("  Computing roadmap to zero...")
    roadmap = engine.roadmap_to_zero()
    print(f"  Roadmap: {len(roadmap)} steps")
    for step in roadmap[:5]:
        cross = f" (+{len(step.get('cross_layer_effects', []))} cross-layer)" if step.get('cross_layer_effects') else ""
        print(f"    Step {step['step']}: {step['name']} ({step['layer']}){cross}")
    print()

    # ──── Step 4: Generate outputs ───────────────────────────────────────
    print("[4/5] Generating outputs...")

    output_dir = Path("data/reports")
    diagram_dir = Path("data/diagrams")
    output_dir.mkdir(parents=True, exist_ok=True)
    diagram_dir.mkdir(parents=True, exist_ok=True)

    # Use enriched component graph from engine
    enriched_graph = engine._component_graph

    # Build DFD
    dfd_builder = DFDBuilder()
    try:
        dfd_model = dfd_builder.build(enriched_graph, None)
    except Exception as e:
        print(f"  DFD build error: {e}")
        dfd_model = {"title": "AWS ECS App - DFD", "elements": [], "data_flows": [], "boundaries": [], "metadata": {}}

    # Render DFD
    diagram_svg = None
    try:
        from src.renderer.graphviz_renderer import GraphvizRenderer
        renderer = GraphvizRenderer()
        svg_path = renderer.render(dfd_model, diagram_dir / "ecs-terraform-dfd.svg", format="svg")
        print(f"  DFD: {svg_path}")
        diagram_svg = Path(str(svg_path)).read_text(encoding="utf-8")
    except Exception as e:
        print(f"  DFD render: FAILED ({e})")

    # Render sub-graphs
    master_dag_svg = None
    attack_graph_svg = None
    try:
        from src.renderer.causal_graph_renderer import CausalGraphRenderer
        causal_renderer = CausalGraphRenderer()

        for subdag, label in [(engine.sast_subdag, "SAST"), (engine.dast_subdag, "DAST"), (engine.repo_subdag, "Repo")]:
            p = causal_renderer.render_subgraph(subdag, title=f"{label} Sub-Graph — AWS ECS App", output_path=diagram_dir / f"ecs-terraform-{label.lower()}-subgraph.svg")
            if p:
                print(f"  {label} Sub-Graph: {p}")

        # Master DAG
        try:
            mp = causal_renderer.render_subgraph(engine.master_dag, title="Master DAG — AWS ECS App", output_path=diagram_dir / f"ecs-terraform-master-dag.svg")
            if mp:
                print(f"  Master DAG: {mp}")
                master_dag_svg = Path(str(mp)).read_text(encoding="utf-8")
        except Exception:
            pass

        # Attack graph (repo topology)
        try:
            ap = causal_renderer.render_subgraph(engine.repo_subdag, title="Attack Surface — AWS ECS App", output_path=diagram_dir / f"ecs-terraform-attack-graph.svg")
            if ap:
                print(f"  Attack Graph: {ap}")
                attack_graph_svg = Path(str(ap)).read_text(encoding="utf-8")
        except Exception:
            pass

    except Exception as e:
        print(f"  Graphs: FAILED ({e})")

    # Build report data
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

    # Build counterfactuals + attack paths for report
    counterfactuals = [
        {"intervention": f"Fix {s['name']}", "recommendation": f"Fix {s['name']} ({s['layer']}) to {s['target_value']:.0%}.", "risk_reduction_pct": s.get("stride_improvement", 0) * 100}
        for s in roadmap
    ]
    attack_paths = [
        {"path_names": ["Architecture Gap", f"{t.category}", t.title[:40]], "score": 1.0 - t.stride_posture_score, "crosses_trust_boundary": True, "has_confirmed_steps": t.layers_confirming >= 2}
        for t in result.threat_model.threats
    ]

    causal_compat = {
        "overall_risk": result.overall_risk, "risk_rating": result.risk_rating,
        "attack_paths": {}, "confirmed_exploitable": [], "confounder_adjustments": {},
        "high_risk_flows": [], "mediators": [], "counterfactuals": counterfactuals,
        "graph_stats": {}, "threat_counts_by_element": {},
        "causal_attack_graph": {"paths": attack_paths, "choke_points": [], "total_paths": len(attack_paths)},
        "federated": {"layer_contributions": {}, "intermediate_scores": {}, "tactical_counterfactuals": []},
    }

    # Generate reports
    reporter = ReportGenerator()
    reporter.generate_from_data(
        dfd_model=dfd_model, threats=threats, causal_result=causal_compat,
        diagram_svg=diagram_svg, master_dag_svg=master_dag_svg, attack_graph_svg=attack_graph_svg,
        project_name="AWS ECS Fullstack App (Terraform)", scan_id="ecs-terraform",
        output_path=output_dir / "ecs-terraform-report.html", format="html",
    )
    print(f"  HTML Report: {output_dir / 'ecs-terraform-report.html'}")

    reporter.generate_from_data(
        dfd_model=dfd_model, threats=threats, causal_result=causal_compat,
        project_name="AWS ECS Fullstack App (Terraform)", scan_id="ecs-terraform",
        output_path=output_dir / "ecs-terraform-report.md", format="markdown",
    )
    print(f"  Markdown: {output_dir / 'ecs-terraform-report.md'}")

    # JSON
    eval_output = {
        "project": "AWS ECS Fullstack App (Terraform)",
        "engine": "CausalTM v2",
        "sast_findings": len(sast_findings),
        "components": len(components),
        "overall_risk": result.overall_risk,
        "risk_rating": result.risk_rating,
        "stride_threats": result.threat_model.total_threats,
        "stride_posture": result.threat_model.posture_per_category,
        "roadmap_steps": len(roadmap),
        "roadmap": roadmap[:5],
    }
    Path("data/ecs-terraform-eval.json").write_text(json.dumps(eval_output, indent=2, default=str))

    # ──── Summary ────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("COMPLETE: AWS ECS Fullstack App (Terraform)")
    print("=" * 70)
    print(f"  Risk: {result.overall_risk:.3f} ({result.risk_rating})")
    print(f"  STRIDE Threats: {result.threat_model.total_threats}")
    print(f"  Roadmap: {len(roadmap)} steps")
    print("=" * 70)


if __name__ == "__main__":
    main()
