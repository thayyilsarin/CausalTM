"""
v3 Test Fixtures — OWASP Juice Shop

Provides:
  1. Component graph (architecture model)
  2. Sample SAST findings (with file_paths for P1 boundary matching)
  3. Sample DAST findings (with URLs for endpoint matching)
  4. EXPECTED outputs at every layer for validation

These fixtures define what CORRECT behavior looks like BEFORE implementation.
Each layer's expected output is derived by hand from the v3 design rules.
"""

# ═══════════════════════════════════════════════════════════════════════════════
# COMPONENT GRAPH (Architecture Model)
# ═══════════════════════════════════════════════════════════════════════════════

JUICE_SHOP_COMPONENT_GRAPH = {
    "components": [
        {
            "id": "comp-frontend",
            "name": "Juice Shop Angular Frontend",
            "type": "process",
            "is_public_facing": True,
            "has_authentication": False,
            "has_encryption": True,
            "technology": "Angular/Node.js",
            "ports": [3000],
            "source_paths": ["frontend/src/", "frontend/"],
            "metadata": {},
            "trust_level": "dmz",
        },
        {
            "id": "comp-rest-api",
            "name": "REST API (Express)",
            "type": "process",
            "is_public_facing": False,
            "has_authentication": True,
            "has_encryption": False,
            "technology": "Node.js/Express",
            "ports": [3000],
            "source_paths": ["routes/", "lib/", "models/"],
            "metadata": {},
            "trust_level": "internal",
        },
        {
            "id": "comp-sqlite-db",
            "name": "SQLite Database",
            "type": "data_store",
            "is_public_facing": False,
            "has_authentication": False,
            "has_encryption": False,
            "technology": "SQLite",
            "ports": [],
            "source_paths": ["data/"],
            "metadata": {"stores": "users, products, orders, feedback"},
            "trust_level": "internal",
        },
        {
            "id": "comp-file-server",
            "name": "Static File Server",
            "type": "process",
            "is_public_facing": True,
            "has_authentication": False,
            "has_encryption": False,
            "technology": "Express serve-static",
            "ports": [3000],
            "source_paths": ["routes/fileServer.ts", "ftp/", "uploads/"],
            "metadata": {},
            "trust_level": "internal",
        },
        {
            "id": "ext-internet-user",
            "name": "Internet User",
            "type": "external_entity",
            "is_public_facing": True,
            "has_authentication": False,
            "has_encryption": False,
            "technology": "Browser",
            "ports": [],
            "source_paths": [],
            "metadata": {},
            "trust_level": "external",
        },
    ],
    "data_flows": [
        {
            "id": "flow-user-frontend",
            "source_id": "ext-internet-user",
            "target_id": "comp-frontend",
            "protocol": "HTTPS",
            "is_encrypted": True,
            "is_authenticated": False,
            "crosses_trust_boundary": True,
            "data_types": ["http_requests", "credentials"],
            "data_sensitivity": ["credentials", "pii"],
            "description": "User accesses frontend",
        },
        {
            "id": "flow-frontend-api",
            "source_id": "comp-frontend",
            "target_id": "comp-rest-api",
            "protocol": "HTTP",
            "is_encrypted": False,
            "is_authenticated": True,
            "crosses_trust_boundary": True,
            "data_types": ["api_calls", "jwt_tokens"],
            "data_sensitivity": ["credentials"],
            "description": "Frontend calls API",
        },
        {
            "id": "flow-api-db",
            "source_id": "comp-rest-api",
            "target_id": "comp-sqlite-db",
            "protocol": "SQLite",
            "is_encrypted": False,
            "is_authenticated": False,
            "crosses_trust_boundary": False,
            "data_types": ["sql_queries", "user_data"],
            "data_sensitivity": ["pii", "credentials"],
            "description": "API queries database",
        },
        {
            "id": "flow-user-files",
            "source_id": "ext-internet-user",
            "target_id": "comp-file-server",
            "protocol": "HTTPS",
            "is_encrypted": True,
            "is_authenticated": False,
            "crosses_trust_boundary": True,
            "data_types": ["file_requests"],
            "data_sensitivity": ["internal"],
            "description": "User accesses static files",
        },
    ],
    "trust_boundaries": [
        {
            "id": "tb-external",
            "name": "Internet (Untrusted)",
            "trust_level": "external",
            "component_ids": ["ext-internet-user"],
        },
        {
            "id": "tb-dmz",
            "name": "DMZ (Public-facing)",
            "trust_level": "dmz",
            "component_ids": ["comp-frontend", "comp-file-server"],
        },
        {
            "id": "tb-internal",
            "name": "Internal Application",
            "trust_level": "internal",
            "component_ids": ["comp-rest-api", "comp-sqlite-db"],
        },
    ],
    "metadata": {"project_name": "OWASP Juice Shop"},
}


# ═══════════════════════════════════════════════════════════════════════════════
# SAMPLE SAST FINDINGS (Raw, as from SARIF ingestor)
# ═══════════════════════════════════════════════════════════════════════════════

SAMPLE_SAST_FINDINGS = [
    # --- API boundary findings (routes/) ---
    {
        "id": "sast-1",
        "title": "SQL Injection in search endpoint",
        "severity": "High",
        "confidence": 0.9,
        "cwe_id": "CWE-89",
        "rule_id": "javascript.express.security.injection.sql-injection",
        "file_path": "routes/search.ts",
        "line_number": 28,
        "tool_name": "semgrep",
    },
    {
        "id": "sast-2",
        "title": "SQL Injection in login",
        "severity": "High",
        "confidence": 0.9,
        "cwe_id": "CWE-89",
        "rule_id": "javascript.express.security.injection.sql-injection",
        "file_path": "routes/login.ts",
        "line_number": 42,
        "tool_name": "semgrep",
    },
    {
        "id": "sast-3",
        "title": "Cross-Site Scripting via user input",
        "severity": "High",
        "confidence": 0.85,
        "cwe_id": "CWE-79",
        "rule_id": "javascript.express.security.xss.reflected-xss",
        "file_path": "routes/search.ts",
        "line_number": 35,
        "tool_name": "semgrep",
    },
    # --- Lib/internal findings (lib/) ---
    {
        "id": "sast-4",
        "title": "Hardcoded JWT secret key",
        "severity": "High",
        "confidence": 0.99,
        "cwe_id": "CWE-798",
        "rule_id": "javascript.jwt.security.hardcoded-secret",
        "file_path": "lib/insecurity.ts",
        "line_number": 5,
        "tool_name": "semgrep",
    },
    {
        "id": "sast-5",
        "title": "Use of weak hash algorithm MD5",
        "severity": "Medium",
        "confidence": 0.90,
        "cwe_id": "CWE-327",
        "rule_id": "javascript.crypto.security.weak-hash",
        "file_path": "lib/insecurity.ts",
        "line_number": 22,
        "tool_name": "semgrep",
    },
    # --- File server findings ---
    {
        "id": "sast-6",
        "title": "Path traversal in file serving",
        "severity": "High",
        "confidence": 0.82,
        "cwe_id": "CWE-22",
        "rule_id": "javascript.express.security.path-traversal",
        "file_path": "routes/fileServer.ts",
        "line_number": 18,
        "tool_name": "semgrep",
    },
    # --- Missing rate limiting (server-wide) ---
    {
        "id": "sast-7",
        "title": "Missing rate limiting on Express app",
        "severity": "Medium",
        "confidence": 0.60,
        "cwe_id": "CWE-770",
        "rule_id": "javascript.express.security.missing-rate-limit",
        "file_path": "server.ts",
        "line_number": 8,
        "tool_name": "semgrep",
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# SAMPLE DAST FINDINGS (Raw, as from ZAP ingestor)
# ═══════════════════════════════════════════════════════════════════════════════

SAMPLE_DAST_FINDINGS = [
    {
        "id": "dast-1",
        "title": "Missing Anti-CSRF Tokens",
        "severity": "Medium",
        "confidence": 0.8,
        "cwe_id": "CWE-352",
        "url": "http://localhost:3000/rest/user/login",
        "tool_name": "OWASP ZAP",
        "category": "auth",
    },
    {
        "id": "dast-2",
        "title": "X-Frame-Options Header Not Set",
        "severity": "Low",
        "confidence": 0.7,
        "cwe_id": None,
        "url": "http://localhost:3000/",
        "tool_name": "OWASP ZAP",
        "category": "validation",
    },
    {
        "id": "dast-3",
        "title": "Cookie Without Secure Flag",
        "severity": "Low",
        "confidence": 0.8,
        "cwe_id": "CWE-614",
        "url": "http://localhost:3000/rest/user/login",
        "tool_name": "OWASP ZAP",
        "category": "crypto",
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# EXPECTED OUTPUTS — LAYER B (Boundary Assignment)
# ═══════════════════════════════════════════════════════════════════════════════

EXPECTED_BOUNDARY_ASSIGNMENTS = {
    # Finding ID → (component_id, boundary_id, priority)
    "sast-1": ("comp-rest-api", "tb-internal", "P1_direct_match"),   # routes/search.ts matches "routes/"
    "sast-2": ("comp-rest-api", "tb-internal", "P1_direct_match"),   # routes/login.ts matches "routes/"
    "sast-3": ("comp-rest-api", "tb-internal", "P1_direct_match"),   # routes/search.ts matches "routes/"
    "sast-4": ("comp-rest-api", "tb-internal", "P1_direct_match"),   # lib/insecurity.ts matches "lib/"
    "sast-5": ("comp-rest-api", "tb-internal", "P1_direct_match"),   # lib/insecurity.ts matches "lib/"
    "sast-6": ("comp-file-server", "tb-dmz", "P1_direct_match"),    # routes/fileServer.ts matches component source_paths
    "sast-7": ("global", "global/unresolved", "P3_unresolved"),      # server.ts doesn't match any component
}


# ═══════════════════════════════════════════════════════════════════════════════
# EXPECTED OUTPUTS — LAYER C (Boundary-Specific Posture)
# ═══════════════════════════════════════════════════════════════════════════════

# Posture formula: max(0, 1 - Σ w(severity) / K)
# Weights: Critical=1.0, High=0.7, Medium=0.4, Low=0.2
# K = 3.0

EXPECTED_BOUNDARY_POSTURES = {
    # (boundary_id, control_category) → expected posture value
    # 
    # comp-rest-api / tb-internal:
    #   validation findings: sast-1 (High=0.7), sast-2 (High=0.7), sast-3 (High=0.7)
    #   deficit = 0.7 + 0.7 + 0.7 = 2.1
    #   posture = max(0, 1 - 2.1/3.0) = 0.30
    ("tb-internal", "validation"): 0.30,

    #   auth findings: sast-4 (High=0.7) — CWE-798 maps to auth
    #   deficit = 0.7
    #   posture = max(0, 1 - 0.7/3.0) = 0.767
    ("tb-internal", "auth"): 0.767,

    #   crypto findings: sast-5 (Medium=0.4) — CWE-327 maps to crypto
    #   deficit = 0.4
    #   posture = max(0, 1 - 0.4/3.0) = 0.867
    ("tb-internal", "crypto"): 0.867,

    # comp-file-server / tb-dmz:
    #   validation findings: sast-6 (High=0.7) — CWE-22 maps to validation
    #   deficit = 0.7
    #   posture = max(0, 1 - 0.7/3.0) = 0.767
    ("tb-dmz", "validation"): 0.767,

    # global/unresolved:
    #   validation findings: sast-7 (Medium=0.4) — CWE-770 maps to validation
    #   deficit = 0.4
    #   posture = max(0, 1 - 0.4/3.0) = 0.867
    ("global/unresolved", "validation"): 0.867,
}


# ═══════════════════════════════════════════════════════════════════════════════
# EXPECTED OUTPUTS — LAYER D (Fused Architectural Posture)
# ═══════════════════════════════════════════════════════════════════════════════

# Criticality:
#   tb-internal (has data store, handles pii) → crosses_trust_boundary=True,
#     handles_sensitive_data=True → 0.25 + 0.25 = 0.50
#   tb-dmz (public-facing) → is_external_facing=True → 0.35
#   global/unresolved → low criticality → 0.15 (only privilege_level base)
#
# For validation posture (3 boundaries contribute):
#   weighted_avg = (0.50×0.30 + 0.35×0.767 + 0.15×0.867) / (0.50+0.35+0.15)
#                = (0.15 + 0.268 + 0.130) / 1.0 = 0.548
#   worst_critical = min(0.30, 0.767) among high-crit boundaries = 0.30
#     (tb-internal is high-crit because crosses_trust_boundary + sensitive_data)
#   arch_posture = 0.6 × 0.548 + 0.4 × 0.30 = 0.329 + 0.120 = 0.449
#
# For auth posture (only tb-internal has auth findings):
#   weighted_avg = 0.767 (single boundary)
#   worst_critical = 0.767
#   arch_posture = 0.6 × 0.767 + 0.4 × 0.767 = 0.767
#   BUT: single-source penalty on confidence (×0.7), not on value
#
# For crypto posture (only tb-internal):
#   arch_posture = 0.867 (single boundary, single source)

EXPECTED_FUSED_POSTURES = {
    # control_category → expected architectural posture
    "validation": 0.449,   # Worst-case adjusted due to tb-internal critical gap
    "auth": 0.767,         # Single boundary, single source
    "crypto": 0.867,       # Single boundary, single source
    "logging": 1.0,        # No logging findings → no evidence of gap → full posture
}


# ═══════════════════════════════════════════════════════════════════════════════
# EXPECTED OUTPUTS — LAYER F (STRIDE Threats)
# ═══════════════════════════════════════════════════════════════════════════════

# Thresholds: <0.30 = Critical, <0.50 = High, <0.70 = Medium, <0.85 = Low
#
# validation posture = 0.449 → HIGH Tampering threat + HIGH DoS threat
# auth posture = 0.767 → MEDIUM Spoofing threat
# crypto posture = 0.867 → NO threat (0.867 >= 0.85, above all thresholds)
# logging posture = 1.0 → No Repudiation threat
#
# Note: Information Disclosure is determined by BOTH crypto + validation
# in the STRIDE mapping (crypto=0.55, validation=0.45). The blended
# InfoDisc posture = 0.55*0.867 + 0.45*0.449 = 0.477 + 0.202 = 0.679
# which IS below 0.70 → MEDIUM Information Disclosure threat.

EXPECTED_STRIDE_THREATS = [
    {
        "category": "Tampering",
        "severity": "Medium",
        "reason": "blended posture (validation 0.60 + crypto 0.40) < 0.70 threshold",
        "primary_boundary": "tb-internal",
    },
    {
        "category": "Denial of Service",
        "severity": "Medium",
        "reason": "blended posture (validation 0.70 + auth 0.30) < 0.70 threshold",
        "primary_boundary": "tb-internal",
    },
    {
        "category": "Spoofing",
        "severity": "Low",
        "reason": "blended posture (auth 0.60 + crypto 0.40) < 0.85 threshold",
        "primary_boundary": "tb-internal",
    },
    {
        "category": "Information Disclosure",
        "severity": "Medium",
        "reason": "blended posture (crypto 0.55 + validation 0.45) < 0.70 threshold",
        "primary_boundary": "tb-internal",
    },
    {
        "category": "Elevation of Privilege",
        "severity": "Medium",
        "reason": "blended posture (auth 0.50 + validation 0.50) < 0.70 threshold",
        "primary_boundary": "tb-internal",
    },
]

# Note: With only SAST (no DAST), these are single-source assessments.
# When DAST is added, corroboration/conflict will adjust values.


# ═══════════════════════════════════════════════════════════════════════════════
# EXPECTED OUTPUTS — LAYER G (Remediation Roadmap - First 3 Steps)
# ═══════════════════════════════════════════════════════════════════════════════

EXPECTED_ROADMAP_FIRST_STEPS = [
    {
        "step": 1,
        "fix": "Improve input validation at tb-internal (API boundary)",
        "target_category": "validation",
        "target_boundary": "tb-internal",
        "findings_to_fix": ["sast-1", "sast-2", "sast-3"],
        "reason": "Highest deficit (0.70) × highest criticality (0.50) = highest priority",
    },
    {
        "step": 2,
        "fix": "Improve input validation at tb-dmz (file server)",
        "target_category": "validation",
        "target_boundary": "tb-dmz",
        "findings_to_fix": ["sast-6"],
        "reason": "Next highest validation gap at external-facing boundary",
    },
    {
        "step": 3,
        "fix": "Improve authentication at tb-internal",
        "target_category": "auth",
        "target_boundary": "tb-internal",
        "findings_to_fix": ["sast-4"],
        "reason": "Auth gap (hardcoded JWT secret) at sensitive boundary",
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# CONFLICT SCENARIO (SAST + DAST disagreement fixture)
# ═══════════════════════════════════════════════════════════════════════════════

CONFLICT_SCENARIO = {
    "description": "SAST says validation is bad, DAST says it looks fine",
    "sast_boundary_posture": {
        "boundary_id": "tb-internal",
        "control_category": "validation",
        "posture": 0.30,
        "causal_strength": 0.70,
        "confidence": 0.85,
    },
    "dast_boundary_posture": {
        "boundary_id": "tb-internal",
        "control_category": "validation",
        "posture": 0.85,
        "causal_strength": 0.90,
        "confidence": 0.60,  # Low confidence because DAST coverage was limited
    },
    "expected_fusion": {
        # Disagree (0.85 - 0.30 = 0.55 > 0.3 threshold)
        # Weighted average biased toward higher confidence source:
        #   SAST: confidence 0.85, strength 0.70 → weight = 0.85 × 0.70 = 0.595
        #   DAST: confidence 0.60, strength 0.90 → weight = 0.60 × 0.90 = 0.540
        #   fused = (0.595×0.30 + 0.540×0.85) / (0.595 + 0.540)
        #         = (0.1785 + 0.459) / 1.135 = 0.5617
        "fused_posture": 0.562,
        "fusion_status": "uncertain_divergence",
        "confidence": 0.60,  # min(0.85, 0.60)
    },
}
