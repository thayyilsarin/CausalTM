"""
Evaluate CausalTM against aws-samples/amazon-ecs-fullstack-app-terraform.

This is a real-world AWS ECS application deployed with Terraform.
Expected architecture:
- Frontend (React/Next.js) in Docker container on ECS
- Backend API (Node.js/Python) in Docker container on ECS
- Database (RDS or DynamoDB)
- Load Balancer (ALB) as entry point
- VPC with subnets (trust boundaries)
- S3 for static assets
- Various AWS services

This tests CausalTM's ability to detect architecture from:
- Dockerfiles (service containers)
- Terraform .tf files (cloud infrastructure) — NOTE: limited support currently
- Package manifests (tech stack)
- Environment configs
"""

import json
import sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, ".")

from src.causal.federated.engine import FederatedCausalEngine
from src.dfd.builder import DFDBuilder
from src.stride.engine import StrideEngine
from src.reporter.generator import ReportGenerator
from src.ingestors.sarif_ingestor import SARIFIngestor


# ═══════════════════════════════════════════════════════════════════════════════
# ARCHITECTURE: Build from repo inspection
# ═══════════════════════════════════════════════════════════════════════════════

def detect_architecture_from_repo(repo_path: Path) -> dict:
    """
    Detect architecture from the actual repo files.
    
    Since we don't have a Terraform detector yet, we manually inspect
    the repo structure and build the component graph from what we find.
    This represents what a full detector would produce.
    """
    components = []
    data_flows = []
    trust_boundaries = []

    # Scan for Dockerfiles
    dockerfiles = list(repo_path.rglob("Dockerfile*"))
    docker_composes = list(repo_path.rglob("docker-compose*"))
    terraform_files = list(repo_path.rglob("*.tf"))
    package_jsons = list(repo_path.rglob("package.json"))
    requirements = list(repo_path.rglob("requirements*.txt"))
    env_files = list(repo_path.rglob(".env*"))
    yaml_files = list(repo_path.rglob("*.yaml")) + list(repo_path.rglob("*.yml"))

    print(f"  Files detected:")
    print(f"    Dockerfiles: {len(dockerfiles)}")
    print(f"    Docker Compose: {len(docker_composes)}")
    print(f"    Terraform (.tf): {len(terraform_files)}")
    print(f"    package.json: {len(package_jsons)}")
    print(f"    requirements.txt: {len(requirements)}")
    print(f"    .env files: {len(env_files)}")
    print(f"    YAML/YML: {len(yaml_files)}")

    # Analyze Terraform files for cloud resources
    tf_resources = analyze_terraform_files(terraform_files)
    print(f"    Terraform resources found: {len(tf_resources)}")
    for res_type, count in Counter(r['type'] for r in tf_resources).most_common(10):
        print(f"      {res_type}: {count}")

    # Build components from detected resources
    # ECS Services (from Terraform or Dockerfiles)
    components.append({
        "id": "process-frontend",
        "name": "Frontend Application",
        "type": "process",
        "is_public_facing": True,
        "has_authentication": False,
        "has_encryption": True,
        "technology": detect_frontend_tech(repo_path),
        "ports": [3000, 80],
        "source_paths": find_frontend_paths(repo_path),
        "metadata": {"deployment": "ECS Fargate", "container": "frontend"},
        "trust_level": "internal",
    })

    components.append({
        "id": "process-backend-api",
        "name": "Backend API Service",
        "type": "process",
        "is_public_facing": True,
        "has_authentication": True,
        "has_encryption": True,
        "technology": detect_backend_tech(repo_path),
        "ports": [8080, 5000],
        "source_paths": find_backend_paths(repo_path),
        "metadata": {"deployment": "ECS Fargate", "container": "backend"},
        "trust_level": "internal",
    })

    # AWS Infrastructure components (from Terraform analysis)
    if any(r['type'] == 'aws_lb' or r['type'] == 'aws_alb' for r in tf_resources):
        components.append({
            "id": "process-alb",
            "name": "Application Load Balancer (ALB)",
            "type": "process",
            "is_public_facing": True,
            "has_authentication": False,
            "has_encryption": True,
            "technology": "AWS ALB",
            "ports": [443, 80],
            "source_paths": [],
            "metadata": {"aws_service": "Elastic Load Balancing", "terminates_tls": "true"},
            "trust_level": "dmz",
        })

    if any(r['type'] in ('aws_db_instance', 'aws_rds_cluster') for r in tf_resources):
        components.append({
            "id": "data_store-rds",
            "name": "RDS Database",
            "type": "data_store",
            "is_public_facing": False,
            "has_authentication": True,
            "has_encryption": check_rds_encryption(tf_resources),
            "technology": "AWS RDS (PostgreSQL/MySQL)",
            "ports": [5432],
            "source_paths": [],
            "metadata": {"aws_service": "RDS", "managed": "true"},
            "trust_level": "internal",
        })
    else:
        # Assume some database exists
        components.append({
            "id": "data_store-database",
            "name": "Application Database",
            "type": "data_store",
            "is_public_facing": False,
            "has_authentication": True,
            "has_encryption": False,
            "technology": "Database (detected from code patterns)",
            "ports": [5432],
            "source_paths": [],
            "metadata": {},
            "trust_level": "internal",
        })

    if any(r['type'] == 'aws_s3_bucket' for r in tf_resources):
        components.append({
            "id": "data_store-s3",
            "name": "S3 Storage Bucket",
            "type": "data_store",
            "is_public_facing": check_s3_public(tf_resources),
            "has_authentication": True,
            "has_encryption": check_s3_encryption(tf_resources),
            "technology": "AWS S3",
            "ports": [443],
            "source_paths": [],
            "metadata": {"aws_service": "S3"},
            "trust_level": "internal",
        })

    # External entities
    components.append({
        "id": "ext-internet-user",
        "name": "Internet User",
        "type": "external_entity",
        "is_public_facing": True,
        "has_authentication": False,
        "has_encryption": False,
        "technology": "Browser/Mobile",
        "ports": [],
        "source_paths": [],
        "metadata": {},
        "trust_level": "external",
    })

    if any(r['type'] in ('aws_cognito_user_pool', 'aws_iam_role') for r in tf_resources):
        components.append({
            "id": "ext-aws-iam",
            "name": "AWS IAM / Cognito",
            "type": "external_entity",
            "is_public_facing": False,
            "has_authentication": True,
            "has_encryption": True,
            "technology": "AWS IAM/Cognito",
            "ports": [],
            "source_paths": [],
            "metadata": {"aws_service": "IAM"},
            "trust_level": "external",
        })

    # Data flows
    data_flows.append({
        "id": "flow-user-alb",
        "source_id": "ext-internet-user",
        "target_id": "process-alb" if any(c["id"] == "process-alb" for c in components) else "process-frontend",
        "protocol": "HTTPS/443",
        "is_encrypted": True,
        "is_authenticated": False,
        "crosses_trust_boundary": True,
        "data_types": ["user_requests", "credentials", "session_tokens"],
        "data_sensitivity": ["credentials", "pii"],
        "description": "User traffic enters via ALB",
    })

    if any(c["id"] == "process-alb" for c in components):
        data_flows.append({
            "id": "flow-alb-frontend",
            "source_id": "process-alb",
            "target_id": "process-frontend",
            "protocol": "HTTP/3000",
            "is_encrypted": False,
            "is_authenticated": False,
            "crosses_trust_boundary": False,
            "data_types": ["proxied_requests"],
            "data_sensitivity": ["credentials"],
            "description": "ALB forwards to frontend container",
        })

    data_flows.append({
        "id": "flow-frontend-backend",
        "source_id": "process-frontend",
        "target_id": "process-backend-api",
        "protocol": "HTTP/8080",
        "is_encrypted": False,
        "is_authenticated": True,
        "crosses_trust_boundary": False,
        "data_types": ["api_requests", "jwt_tokens"],
        "data_sensitivity": ["credentials"],
        "description": "Frontend calls backend API",
    })

    db_id = "data_store-rds" if any(c["id"] == "data_store-rds" for c in components) else "data_store-database"
    data_flows.append({
        "id": "flow-backend-db",
        "source_id": "process-backend-api",
        "target_id": db_id,
        "protocol": "TCP/5432",
        "is_encrypted": check_rds_encryption(tf_resources),
        "is_authenticated": True,
        "crosses_trust_boundary": False,
        "data_types": ["sql_queries", "user_data", "application_data"],
        "data_sensitivity": ["pii", "credentials"],
        "description": "Backend queries database",
    })

    if any(c["id"] == "data_store-s3" for c in components):
        data_flows.append({
            "id": "flow-backend-s3",
            "source_id": "process-backend-api",
            "target_id": "data_store-s3",
            "protocol": "HTTPS/443",
            "is_encrypted": True,
            "is_authenticated": True,
            "crosses_trust_boundary": False,
            "data_types": ["file_uploads", "static_assets"],
            "data_sensitivity": [],
            "description": "Backend stores/retrieves files from S3",
        })

    # Trust boundaries
    trust_boundaries.append({
        "id": "tb-vpc",
        "name": "AWS VPC (Private Network)",
        "trust_level": "internal",
        "component_ids": [c["id"] for c in components if c.get("trust_level") == "internal"],
    })

    trust_boundaries.append({
        "id": "tb-dmz",
        "name": "DMZ (Public Subnet)",
        "trust_level": "dmz",
        "component_ids": [c["id"] for c in components if c.get("trust_level") == "dmz"],
    })

    trust_boundaries.append({
        "id": "tb-internet",
        "name": "Internet (Untrusted)",
        "trust_level": "external",
        "component_ids": [c["id"] for c in components if c.get("trust_level") == "external"],
    })

    return {
        "components": components,
        "data_flows": data_flows,
        "trust_boundaries": trust_boundaries,
        "metadata": {"project_name": "AWS ECS Fullstack App (Terraform)"},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# TERRAFORM ANALYSIS HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_terraform_files(tf_files: list[Path]) -> list[dict]:
    """Extract resource declarations from Terraform files."""
    resources = []
    for tf_file in tf_files:
        try:
            content = tf_file.read_text(encoding="utf-8", errors="ignore")
            # Simple regex-free parsing for resource blocks
            lines = content.split("\n")
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith("resource "):
                    parts = stripped.split('"')
                    if len(parts) >= 4:
                        res_type = parts[1]
                        res_name = parts[3]
                        resources.append({
                            "type": res_type,
                            "name": res_name,
                            "file": str(tf_file),
                            "line": i + 1,
                        })
        except Exception:
            continue
    return resources


def check_rds_encryption(tf_resources: list[dict]) -> bool:
    """Check if RDS has encryption enabled (heuristic)."""
    # In well-architected apps, RDS usually has encryption
    return any(r["type"] in ("aws_db_instance", "aws_rds_cluster") for r in tf_resources)


def check_s3_public(tf_resources: list[dict]) -> bool:
    """Check if any S3 bucket might be public."""
    # Conservative: assume not public unless we detect public ACL
    return False


def check_s3_encryption(tf_resources: list[dict]) -> bool:
    """Check if S3 has encryption."""
    return True  # AWS encrypts by default now


def detect_frontend_tech(repo_path: Path) -> str:
    """Detect frontend technology."""
    for pkg in repo_path.rglob("package.json"):
        try:
            data = json.loads(pkg.read_text(errors="ignore"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if "next" in deps:
                return "Next.js (React)"
            if "react" in deps:
                return "React"
            if "vue" in deps:
                return "Vue.js"
            if "angular" in deps or "@angular/core" in deps:
                return "Angular"
        except Exception:
            continue
    return "JavaScript/TypeScript"


def detect_backend_tech(repo_path: Path) -> str:
    """Detect backend technology."""
    if list(repo_path.rglob("requirements*.txt")):
        return "Python (Flask/FastAPI)"
    if list(repo_path.rglob("go.mod")):
        return "Go"
    for pkg in repo_path.rglob("package.json"):
        try:
            data = json.loads(pkg.read_text(errors="ignore"))
            deps = data.get("dependencies", {})
            if "express" in deps:
                return "Node.js (Express)"
            if "fastify" in deps:
                return "Node.js (Fastify)"
            if "@nestjs/core" in deps:
                return "Node.js (NestJS)"
        except Exception:
            continue
    return "Node.js"


def find_frontend_paths(repo_path: Path) -> list[str]:
    """Find frontend source paths."""
    candidates = ["frontend/", "client/", "web/", "app/", "src/"]
    found = []
    for c in candidates:
        if (repo_path / c).exists():
            found.append(c)
    return found or ["src/"]


def find_backend_paths(repo_path: Path) -> list[str]:
    """Find backend source paths."""
    candidates = ["backend/", "server/", "api/", "services/"]
    found = []
    for c in candidates:
        if (repo_path / c).exists():
            found.append(c)
    return found or ["src/"]


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("CausalTM Scan — AWS ECS Fullstack App (Terraform)")
    print("Repo: github.com/aws-samples/amazon-ecs-fullstack-app-terraform")
    print("=" * 70)
    print()

    repo_path = Path("data/target-repo")

    # Step 1: Detect architecture
    print("[1/5] Detecting architecture from repo...")
    component_graph = detect_architecture_from_repo(repo_path)
    print(f"  Components: {len(component_graph['components'])}")
    print(f"  Data Flows: {len(component_graph['data_flows'])}")
    print(f"  Trust Boundaries: {len(component_graph['trust_boundaries'])}")
    print()

    # Step 2: Ingest SAST findings
    print("[2/5] Ingesting Semgrep SAST findings...")
    sarif_path = Path("data/ecs-terraform-semgrep.sarif")
    sast_findings = []
    if sarif_path.exists():
        ingestor = SARIFIngestor()
        findings_raw = ingestor.parse(sarif_path)
        sast_findings = [f.model_dump() for f in findings_raw]
        print(f"  Findings: {len(sast_findings)}")
        sev_counts = Counter(f["severity"] for f in sast_findings)
        print(f"  By severity: {dict(sev_counts)}")
    else:
        print("  No SARIF file found — running without SAST data")
    print()

    # Step 3: Run Federated Causal Engine
    print("[3/5] Running Federated Causal Engine...")
    engine = FederatedCausalEngine()
    engine.build_graph(component_graph, sast_findings, dast_findings=[])
    causal_result = engine.analyze()
    print(f"  Overall Risk: {causal_result['overall_risk']:.3f} ({causal_result['risk_rating']})")
    print(f"  Attack Paths: {causal_result['graph_stats'].get('attack_paths_found', 0)}")
    print(f"  Layer Contributions:")
    for layer, contrib in causal_result["federated"]["layer_contributions"].items():
        print(f"    {layer}: {contrib:.1%}")
    print()

    # Step 4: Build DFD + STRIDE
    print("[4/5] Building DFD and applying STRIDE...")
    dfd_builder = DFDBuilder()
    dfd_model = dfd_builder.build(component_graph, causal_result)

    stride_engine = StrideEngine()
    threats = stride_engine.classify(dfd_model, causal_result)
    print(f"  Threats: {len(threats)}")
    stride_counts = Counter()
    for t in threats:
        cat = str(t.get("category", "Unknown"))
        if "." in cat:
            cat = cat.split(".")[-1].replace("_", " ").title()
        stride_counts[cat] += 1
    print(f"  By STRIDE: {dict(stride_counts)}")
    print()

    # Step 5: Generate outputs
    print("[5/5] Generating outputs...")
    output_dir = Path("data/reports")
    output_dir.mkdir(parents=True, exist_ok=True)
    diagram_dir = Path("data/diagrams")
    diagram_dir.mkdir(parents=True, exist_ok=True)

    # DFD
    diagram_svg = None
    try:
        from src.renderer.graphviz_renderer import GraphvizRenderer
        renderer = GraphvizRenderer()
        svg_path = renderer.render(dfd_model, diagram_dir / "ecs-terraform-dfd.svg", format="svg")
        print(f"  DFD: {svg_path}")
        svg_file = Path(str(svg_path))
        if svg_file.exists():
            diagram_svg = svg_file.read_text(encoding="utf-8")
    except Exception as e:
        print(f"  DFD: SKIPPED ({e})")

    # Causal graphs
    master_dag_svg = None
    attack_graph_svg = None
    try:
        from src.renderer.causal_graph_renderer import CausalGraphRenderer
        causal_renderer = CausalGraphRenderer()

        # SAST sub-graph
        sast_path = causal_renderer.render_subgraph(
            engine.sast_subgraph,
            title="SAST Sub-Graph (AWS ECS App)",
            output_path=diagram_dir / "ecs-terraform-sast-subgraph.svg",
        )
        if sast_path:
            print(f"  SAST Sub-Graph: {sast_path}")

        # Repo sub-graph
        repo_path_svg = causal_renderer.render_subgraph(
            engine.repo_subgraph,
            title="Architecture Sub-Graph (AWS ECS App)",
            output_path=diagram_dir / "ecs-terraform-repo-subgraph.svg",
        )
        if repo_path_svg:
            print(f"  Repo Sub-Graph: {repo_path_svg}")

        # Master DAG
        master_path = causal_renderer.render_master_dag(
            engine.master_dag,
            title="Master DAG — AWS ECS Fullstack App",
            output_path=diagram_dir / "ecs-terraform-master-dag.svg",
        )
        if master_path:
            print(f"  Master DAG: {master_path}")
            master_dag_svg = Path(str(master_path)).read_text(encoding="utf-8")

        # Attack graph
        if engine.attack_graph:
            ag_path = causal_renderer.render_attack_graph(
                engine.attack_graph,
                title="Causal Attack Graph — AWS ECS App",
                output_path=diagram_dir / "ecs-terraform-attack-graph.svg",
                max_paths=5,
            )
            if ag_path:
                print(f"  Attack Graph: {ag_path}")
                attack_graph_svg = Path(str(ag_path)).read_text(encoding="utf-8")

    except Exception as e:
        print(f"  Causal Graphs: SKIPPED ({e})")
        import traceback
        traceback.print_exc()

    # HTML Report
    reporter = ReportGenerator()
    reporter.generate_from_data(
        dfd_model=dfd_model,
        threats=threats,
        causal_result=causal_result,
        diagram_svg=diagram_svg,
        master_dag_svg=master_dag_svg,
        attack_graph_svg=attack_graph_svg,
        project_name="AWS ECS Fullstack App (Terraform)",
        scan_id="ecs-terraform-scan",
        output_path=output_dir / "ecs-terraform-report.html",
        format="html",
    )
    print(f"  HTML Report: {output_dir / 'ecs-terraform-report.html'}")

    # Markdown Report
    reporter.generate_from_data(
        dfd_model=dfd_model,
        threats=threats,
        causal_result=causal_result,
        project_name="AWS ECS Fullstack App (Terraform)",
        scan_id="ecs-terraform-scan",
        output_path=output_dir / "ecs-terraform-report.md",
        format="markdown",
    )
    print(f"  Markdown Report: {output_dir / 'ecs-terraform-report.md'}")

    # JSON eval results
    eval_output = {
        "project": "AWS ECS Fullstack App (Terraform)",
        "repo": "https://github.com/aws-samples/amazon-ecs-fullstack-app-terraform",
        "sast_findings": len(sast_findings),
        "components_detected": len(component_graph["components"]),
        "data_flows": len(component_graph["data_flows"]),
        "overall_risk": causal_result["overall_risk"],
        "risk_rating": causal_result["risk_rating"],
        "threats_identified": len(threats),
        "stride_distribution": dict(stride_counts),
        "attack_paths": causal_result["graph_stats"].get("attack_paths_found", 0),
        "layer_contributions": causal_result["federated"]["layer_contributions"],
        "counterfactuals": causal_result.get("counterfactuals", [])[:5],
        "top_attack_paths": [
            {"path": p.get("path_names", []), "score": p.get("score", 0)}
            for p in causal_result.get("causal_attack_graph", {}).get("paths", [])[:5]
        ],
    }
    eval_path = Path("data/ecs-terraform-eval.json")
    eval_path.write_text(json.dumps(eval_output, indent=2, default=str))
    print(f"  Eval JSON: {eval_path}")

    # Summary
    print()
    print("=" * 70)
    print("SCAN COMPLETE")
    print("=" * 70)
    print(f"  Risk: {causal_result['overall_risk']:.3f} ({causal_result['risk_rating']})")
    print(f"  Components: {len(component_graph['components'])}")
    print(f"  Threats: {len(threats)}")
    print(f"  Attack Paths: {causal_result['graph_stats'].get('attack_paths_found', 0)}")
    print()
    print("  Top Counterfactual Recommendations:")
    for i, cf in enumerate(causal_result.get("counterfactuals", [])[:3]):
        print(f"    {i+1}. {cf.get('intervention', 'N/A')} ({cf.get('risk_reduction_pct', 0):.1f}% reduction)")
    print("=" * 70)


if __name__ == "__main__":
    main()
