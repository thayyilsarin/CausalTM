"""Quick end-to-end test of the Federated Causal Engine."""

import sys
sys.path.insert(0, ".")

from src.causal.federated.engine import FederatedCausalEngine

# Simulate minimal input data
component_graph = {
    "components": [
        {"id": "process-web", "name": "Web Service", "type": "process", "is_public_facing": True, "has_authentication": False, "has_encryption": True, "technology": "Node.js", "ports": [8080], "source_paths": ["src/"], "metadata": {}, "trust_level": "internal"},
        {"id": "data_store-db", "name": "PostgreSQL", "type": "data_store", "is_public_facing": False, "has_authentication": True, "has_encryption": False, "technology": "PostgreSQL", "ports": [5432], "source_paths": [], "metadata": {}, "trust_level": "internal"},
        {"id": "ext-user", "name": "User", "type": "external_entity", "is_public_facing": True, "has_authentication": False, "has_encryption": False, "technology": "", "ports": [], "source_paths": [], "metadata": {}, "trust_level": "external"},
    ],
    "data_flows": [
        {"id": "flow-1", "source_id": "ext-user", "target_id": "process-web", "protocol": "HTTPS", "is_encrypted": True, "is_authenticated": False, "crosses_trust_boundary": True, "data_types": ["credentials"], "data_sensitivity": ["credentials"], "description": "User login"},
        {"id": "flow-2", "source_id": "process-web", "target_id": "data_store-db", "protocol": "TCP/5432", "is_encrypted": False, "is_authenticated": True, "crosses_trust_boundary": False, "data_types": ["user_data"], "data_sensitivity": ["pii"], "description": "DB query"},
    ],
    "trust_boundaries": [
        {"id": "tb-internal", "name": "Internal Network", "trust_level": "internal", "component_ids": ["process-web", "data_store-db"]},
    ],
    "metadata": {},
}

sast_findings = [
    {"id": "sast-1", "title": "SQL Injection", "severity": "Critical", "cwe_id": "CWE-89", "file_path": "src/routes/users.js", "line_number": 42, "confidence": 0.9},
    {"id": "sast-2", "title": "Missing Auth Check", "severity": "High", "cwe_id": "CWE-287", "file_path": "src/middleware/auth.js", "line_number": 15, "confidence": 0.8},
]

dast_findings = [
    {"id": "dast-1", "title": "SQL Injection Confirmed", "severity": "High", "cwe_id": "CWE-89", "url": "http://localhost:8080/api/users", "confidence": 0.95, "category": "injection"},
    {"id": "dast-2", "title": "Missing Security Headers", "severity": "Medium", "url": "http://localhost:8080/", "confidence": 0.7, "category": "configuration"},
]

print("=" * 60)
print("FEDERATED CAUSAL ENGINE - END-TO-END TEST")
print("=" * 60)

# Run the federated engine
engine = FederatedCausalEngine()
engine.build_graph(component_graph, sast_findings, dast_findings)
result = engine.analyze()

print()
print(f"Overall Risk: {result['overall_risk']:.3f} ({result['risk_rating']})")
print(f"Attack Paths Found: {result['graph_stats'].get('attack_paths_found', 0)}")
print(f"Confirmed Attack Paths: {result['graph_stats'].get('confirmed_attack_paths', 0)}")
print()

print("Layer Contributions:")
for layer, contrib in result["federated"]["layer_contributions"].items():
    print(f"  {layer}: {contrib:.1%}")

print()
print("Intermediate Scores:")
for key, val in result["federated"]["intermediate_scores"].items():
    print(f"  {key}: {val:.3f}")

print()
print(f"Strategic Counterfactuals: {len(result['counterfactuals'])} scenarios")
for i, cf in enumerate(result["counterfactuals"][:3]):
    print(f"  {i+1}. {cf.get('intervention', 'N/A')}")
    print(f"     Risk reduction: {cf.get('risk_reduction_pct', 0):.1f}%")

print()
ag = result["causal_attack_graph"]
print(f"Causal Attack Graph: {ag['total_paths']} paths found")
print(f"Choke Points: {ag.get('choke_points', [])}")
if ag["paths"]:
    print(f"Top Attack Path:")
    top = ag["paths"][0]
    print(f"  Path: {' -> '.join(top.get('path_names', []))}")
    print(f"  Score: {top.get('score', 0):.3f}")
    print(f"  Confirmed: {top.get('has_confirmed_steps', False)}")
    if top.get("narrative"):
        print(f"  Narrative: {top['narrative']}")

print()
print("=" * 60)
print("SUCCESS: Federated Causal Engine runs end-to-end")
print("=" * 60)
