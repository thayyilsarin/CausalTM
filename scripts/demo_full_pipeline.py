"""
Full Pipeline Demo — Runs CausalTM end-to-end on sample data.

This script demonstrates the complete pipeline:
1. Architecture detection (from sample component graph)
2. SAST/DAST ingestion (simulated findings)
3. Federated Causal Engine (sub-graphs + master DAG + attack graph)
4. DFD Rendering (Graphviz SVG output)
5. Report Generation (HTML output)

Produces:
- data/diagrams/demo-dfd.svg  (Data Flow Diagram)
- data/reports/demo-report.html (Threat Model Report)
- Console output with full analysis results
"""

import sys
import os
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.causal.federated.engine import FederatedCausalEngine
from src.dfd.builder import DFDBuilder
from src.stride.engine import StrideEngine
from src.reporter.generator import ReportGenerator


def get_sample_component_graph():
    """Simulate what the architecture detector would find in OWASP Juice Shop."""
    return {
        "components": [
            {
                "id": "process-web-app",
                "name": "Juice Shop Web App",
                "type": "process",
                "is_public_facing": True,
                "has_authentication": True,
                "has_encryption": True,
                "technology": "Node.js/Express",
                "ports": [3000],
                "source_paths": ["src/", "routes/", "lib/"],
                "metadata": {"image": "bkimminich/juice-shop"},
                "trust_level": "internal",
            },
            {
                "id": "data_store-sqlite",
                "name": "SQLite Database",
                "type": "data_store",
                "is_public_facing": False,
                "has_authentication": False,
                "has_encryption": False,
                "technology": "SQLite",
                "ports": [],
                "source_paths": [],
                "metadata": {"stores": "user_credentials, orders, products"},
                "trust_level": "internal",
            },
            {
                "id": "ext-user",
                "name": "Internet User",
                "type": "external_entity",
                "is_public_facing": True,
                "has_authentication": False,
                "has_encryption": False,
                "technology": "",
                "ports": [],
                "source_paths": [],
                "metadata": {},
                "trust_level": "external",
            },
            {
                "id": "ext-admin",
                "name": "Administrator",
                "type": "external_entity",
                "is_public_facing": True,
                "has_authentication": True,
                "has_encryption": True,
                "technology": "",
                "ports": [],
                "source_paths": [],
                "metadata": {},
                "trust_level": "external",
            },
            {
                "id": "process-api",
                "name": "REST API Backend",
                "type": "process",
                "is_public_facing": True,
                "has_authentication": True,
                "has_encryption": True,
                "technology": "Node.js/Express",
                "ports": [3000],
                "source_paths": ["routes/", "api/"],
                "metadata": {},
                "trust_level": "internal",
            },
            {
                "id": "ext-payment",
                "name": "Payment Gateway",
                "type": "external_entity",
                "is_public_facing": False,
                "has_authentication": True,
                "has_encryption": True,
                "technology": "External API",
                "ports": [443],
                "source_paths": [],
                "metadata": {},
                "trust_level": "external",
            },
        ],
        "data_flows": [
            {
                "id": "flow-user-web",
                "source_id": "ext-user",
                "target_id": "process-web-app",
                "protocol": "HTTPS",
                "is_encrypted": True,
                "is_authenticated": False,
                "crosses_trust_boundary": True,
                "data_types": ["credentials", "search_queries", "orders"],
                "data_sensitivity": ["credentials", "pii"],
                "description": "User browses and interacts with shop",
            },
            {
                "id": "flow-web-api",
                "source_id": "process-web-app",
                "target_id": "process-api",
                "protocol": "HTTP/internal",
                "is_encrypted": False,
                "is_authenticated": False,
                "crosses_trust_boundary": False,
                "data_types": ["api_requests"],
                "data_sensitivity": [],
                "description": "Frontend calls backend API",
            },
            {
                "id": "flow-api-db",
                "source_id": "process-api",
                "target_id": "data_store-sqlite",
                "protocol": "SQLite/file",
                "is_encrypted": False,
                "is_authenticated": False,
                "crosses_trust_boundary": False,
                "data_types": ["sql_queries", "user_data"],
                "data_sensitivity": ["credentials", "pii", "financial"],
                "description": "API queries database for user/product data",
            },
            {
                "id": "flow-admin-web",
                "source_id": "ext-admin",
                "target_id": "process-web-app",
                "protocol": "HTTPS",
                "is_encrypted": True,
                "is_authenticated": True,
                "crosses_trust_boundary": True,
                "data_types": ["admin_commands"],
                "data_sensitivity": ["credentials"],
                "description": "Admin manages the shop",
            },
            {
                "id": "flow-api-payment",
                "source_id": "process-api",
                "target_id": "ext-payment",
                "protocol": "HTTPS",
                "is_encrypted": True,
                "is_authenticated": True,
                "crosses_trust_boundary": True,
                "data_types": ["payment_data", "card_details"],
                "data_sensitivity": ["financial"],
                "description": "Process payments via external gateway",
            },
        ],
        "trust_boundaries": [
            {
                "id": "tb-internal",
                "name": "Internal Application Network",
                "trust_level": "internal",
                "component_ids": ["process-web-app", "process-api", "data_store-sqlite"],
            },
            {
                "id": "tb-external",
                "name": "Internet / External",
                "trust_level": "external",
                "component_ids": ["ext-user", "ext-admin", "ext-payment"],
            },
        ],
        "metadata": {"project_name": "OWASP Juice Shop"},
    }


def get_sample_sast_findings():
    """Simulate Semgrep/CodeQL SARIF findings for Juice Shop."""
    return [
        {"id": "sast-001", "title": "SQL Injection in search query", "severity": "Critical", "cwe_id": "CWE-89", "file_path": "routes/search.js", "line_number": 28, "confidence": 0.95},
        {"id": "sast-002", "title": "SQL Injection in user login", "severity": "Critical", "cwe_id": "CWE-89", "file_path": "routes/login.js", "line_number": 42, "confidence": 0.92},
        {"id": "sast-003", "title": "Cross-Site Scripting (Reflected)", "severity": "High", "cwe_id": "CWE-79", "file_path": "routes/search.js", "line_number": 35, "confidence": 0.88},
        {"id": "sast-004", "title": "Missing authentication on admin endpoint", "severity": "High", "cwe_id": "CWE-287", "file_path": "routes/admin.js", "line_number": 12, "confidence": 0.85},
        {"id": "sast-005", "title": "Hardcoded JWT secret", "severity": "High", "cwe_id": "CWE-798", "file_path": "lib/insecurity.js", "line_number": 5, "confidence": 0.99},
        {"id": "sast-006", "title": "Path traversal in file serve", "severity": "High", "cwe_id": "CWE-22", "file_path": "routes/fileServer.js", "line_number": 18, "confidence": 0.82},
        {"id": "sast-007", "title": "Weak password hashing (MD5)", "severity": "Medium", "cwe_id": "CWE-327", "file_path": "models/user.js", "line_number": 55, "confidence": 0.90},
        {"id": "sast-008", "title": "Missing rate limiting", "severity": "Medium", "cwe_id": "CWE-770", "file_path": "server.js", "line_number": 8, "confidence": 0.60},
        {"id": "sast-009", "title": "Sensitive data in error response", "severity": "Medium", "cwe_id": "CWE-209", "file_path": "routes/api.js", "line_number": 90, "confidence": 0.75},
        {"id": "sast-010", "title": "Open redirect", "severity": "Low", "cwe_id": "CWE-601", "file_path": "routes/redirect.js", "line_number": 7, "confidence": 0.70},
    ]


def get_sample_dast_findings():
    """Simulate OWASP ZAP scan findings for Juice Shop."""
    return [
        {"id": "dast-001", "title": "SQL Injection", "severity": "High", "cwe_id": "CWE-89", "url": "http://localhost:3000/rest/products/search?q=", "confidence": 0.95, "category": "injection"},
        {"id": "dast-002", "title": "Reflected XSS in search", "severity": "High", "cwe_id": "CWE-79", "url": "http://localhost:3000/#/search?q=<script>", "confidence": 0.90, "category": "xss"},
        {"id": "dast-003", "title": "Broken Authentication", "severity": "High", "cwe_id": "CWE-287", "url": "http://localhost:3000/rest/user/login", "confidence": 0.85, "category": "authentication"},
        {"id": "dast-004", "title": "Missing Anti-CSRF Token", "severity": "Medium", "cwe_id": "CWE-352", "url": "http://localhost:3000/api/Users", "confidence": 0.70, "category": "authentication"},
        {"id": "dast-005", "title": "Missing X-Content-Type-Options Header", "severity": "Low", "cwe_id": "CWE-693", "url": "http://localhost:3000/", "confidence": 0.80, "category": "configuration"},
        {"id": "dast-006", "title": "Information Disclosure via Error", "severity": "Medium", "cwe_id": "CWE-209", "url": "http://localhost:3000/api/invalid", "confidence": 0.75, "category": "information_disclosure"},
        {"id": "dast-007", "title": "Directory Listing Enabled", "severity": "Low", "cwe_id": "CWE-548", "url": "http://localhost:3000/ftp/", "confidence": 0.85, "category": "information_disclosure"},
    ]


def main():
    print("=" * 70)
    print("CausalTM — Full Pipeline Demonstration")
    print("Target: OWASP Juice Shop (simulated)")
    print("=" * 70)
    print()

    # ──── Step 1: Get architecture + findings ────────────────────────────
    print("[1/5] Loading architecture and scan findings...")
    component_graph = get_sample_component_graph()
    sast_findings = get_sample_sast_findings()
    dast_findings = get_sample_dast_findings()
    print(f"  Components: {len(component_graph['components'])}")
    print(f"  Data Flows: {len(component_graph['data_flows'])}")
    print(f"  SAST Findings: {len(sast_findings)}")
    print(f"  DAST Findings: {len(dast_findings)}")
    print()

    # ──── Step 2: Run Federated Causal Engine ────────────────────────────
    print("[2/5] Running Federated Causal Engine...")
    engine = FederatedCausalEngine()
    engine.build_graph(component_graph, sast_findings, dast_findings)
    causal_result = engine.analyze()
    print(f"  Overall Risk: {causal_result['overall_risk']:.3f} ({causal_result['risk_rating']})")
    print(f"  Attack Paths: {causal_result['graph_stats'].get('attack_paths_found', 0)}")
    print(f"  Layer Contributions:")
    for layer, contrib in causal_result["federated"]["layer_contributions"].items():
        print(f"    {layer}: {contrib:.1%}")
    print()

    # ──── Step 3: Build DFD ──────────────────────────────────────────────
    print("[3/5] Building Data Flow Diagram...")
    dfd_builder = DFDBuilder()
    dfd_model = dfd_builder.build(component_graph, causal_result)
    print(f"  Elements: {len(dfd_model.get('elements', []))}")
    print(f"  Data Flows: {len(dfd_model.get('data_flows', []))}")
    print(f"  Trust Boundaries: {len(dfd_model.get('boundaries', []))}")
    print()

    # ──── Step 4: Apply STRIDE ───────────────────────────────────────────
    print("[4/5] Applying STRIDE threat classification...")
    stride_engine = StrideEngine()
    threats = stride_engine.classify(dfd_model, causal_result)
    print(f"  Total Threats Identified: {len(threats)}")

    # Count by category
    categories = {}
    severities = {}
    for t in threats:
        cat = str(t.get("category", "Unknown"))
        sev = str(t.get("severity", "Unknown"))
        # Clean enum representations: "StrideCategory.SPOOFING" → "Spoofing"
        if "." in cat:
            cat = cat.split(".")[-1].replace("_", " ").title()
        if "." in sev:
            sev = sev.split(".")[-1].replace("_", " ").title()
        categories[cat] = categories.get(cat, 0) + 1
        severities[sev] = severities.get(sev, 0) + 1

    print(f"  By Category:")
    for cat, count in sorted(categories.items()):
        print(f"    {cat}: {count}")
    print(f"  By Severity:")
    for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
        if sev in severities:
            print(f"    {sev}: {severities[sev]}")
    print()

    # ──── Step 5: Generate Report ────────────────────────────────────────
    print("[5/5] Generating threat model report...")

    # Ensure output directories exist
    output_dir = Path("data/reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    diagram_dir = Path("data/diagrams")
    diagram_dir.mkdir(parents=True, exist_ok=True)

    # Try DFD rendering first (so we can embed SVG in report)
    diagram_svg_content = None
    try:
        from src.renderer.graphviz_renderer import GraphvizRenderer
        renderer = GraphvizRenderer()
        svg_path = renderer.render(dfd_model, diagram_dir / "demo-dfd.svg", format="svg")
        print(f"  DFD Diagram: {svg_path}")
        # Read SVG for embedding in HTML report
        svg_file = Path(str(svg_path))
        if svg_file.exists():
            diagram_svg_content = svg_file.read_text(encoding="utf-8")
    except Exception as e:
        print(f"  DFD Diagram: SKIPPED ({e})")

    # Generate HTML report (with embedded DFD if available)
    reporter = ReportGenerator()
    report_content = reporter.generate_from_data(
        dfd_model=dfd_model,
        threats=threats,
        causal_result=causal_result,
        diagram_svg=diagram_svg_content,
        project_name="OWASP Juice Shop",
        scan_id="demo-001",
        output_path=output_dir / "demo-report.html",
        format="html",
    )
    print(f"  HTML Report: {output_dir / 'demo-report.html'}")

    # Generate Markdown report
    md_content = reporter.generate_from_data(
        dfd_model=dfd_model,
        threats=threats,
        causal_result=causal_result,
        project_name="OWASP Juice Shop",
        scan_id="demo-001",
        output_path=output_dir / "demo-report.md",
        format="markdown",
    )
    print(f"  Markdown Report: {output_dir / 'demo-report.md'}")

    # ──── Summary ────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("PIPELINE COMPLETE — Summary")
    print("=" * 70)
    print(f"  Risk Score:         {causal_result['overall_risk']:.3f} ({causal_result['risk_rating']})")
    print(f"  Components Found:   {len(component_graph['components'])}")
    print(f"  Threats Identified: {len(threats)}")
    print(f"  Attack Paths:       {causal_result['causal_attack_graph']['total_paths']}")
    print(f"  Choke Points:       {causal_result['causal_attack_graph'].get('choke_points', [])}")
    print()
    print("  Top 3 Counterfactual Recommendations:")
    for i, cf in enumerate(causal_result.get("counterfactuals", [])[:3]):
        print(f"    {i+1}. {cf.get('intervention', 'N/A')} ({cf.get('risk_reduction_pct', 0):.1f}% reduction)")
    print()
    print("  Top Attack Path:")
    paths = causal_result["causal_attack_graph"].get("paths", [])
    if paths:
        top = paths[0]
        print(f"    {' -> '.join(top.get('path_names', []))}")
        print(f"    Score: {top.get('score', 0):.3f} | Confirmed: {top.get('has_confirmed_steps', False)}")
    print()
    print(f"  Outputs saved to: data/reports/ and data/diagrams/")
    print("=" * 70)


if __name__ == "__main__":
    main()
