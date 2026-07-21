"""
v3 Full Fixtures — OWASP Juice Shop (23 SAST + 10 DAST)

Realistic findings matching what Semgrep p/javascript + p/nodejs
and OWASP ZAP baseline scan produce against Juice Shop.

This replaces the 7-finding fixture with production-representative data.
"""

# ═══════════════════════════════════════════════════════════════════════════════
# COMPONENT GRAPH (Full Juice Shop Architecture — 6 components, 5 flows)
# ═══════════════════════════════════════════════════════════════════════════════

JUICE_SHOP_FULL_GRAPH = {
    "components": [
        {
            "id": "comp-angular-frontend",
            "name": "Angular Frontend (SPA)",
            "type": "process",
            "is_public_facing": True,
            "has_authentication": False,
            "has_encryption": True,
            "technology": "Angular/TypeScript",
            "ports": [3000],
            "source_paths": ["frontend/src/", "frontend/"],
            "metadata": {},
            "trust_level": "dmz",
        },
        {
            "id": "comp-express-api",
            "name": "REST API Backend (Express)",
            "type": "process",
            "is_public_facing": False,
            "has_authentication": True,
            "has_encryption": False,
            "technology": "Node.js/Express",
            "ports": [3000],
            "source_paths": ["routes/", "lib/", "models/", "data/"],
            "metadata": {},
            "trust_level": "internal",
        },
        {
            "id": "comp-sqlite",
            "name": "SQLite Database",
            "type": "data_store",
            "is_public_facing": False,
            "has_authentication": False,
            "has_encryption": False,
            "technology": "SQLite (Sequelize ORM)",
            "ports": [],
            "source_paths": ["data/sqlite.js", "data/"],
            "metadata": {"stores": "users, products, orders, feedback, wallets"},
            "trust_level": "internal",
        },
        {
            "id": "comp-file-server",
            "name": "Static File Server (FTP/Uploads)",
            "type": "process",
            "is_public_facing": True,
            "has_authentication": False,
            "has_encryption": False,
            "technology": "Express serve-static",
            "ports": [3000],
            "source_paths": ["routes/fileServer.ts", "routes/fileUpload.ts"],
            "metadata": {"serves": "ftp/, uploads/"},
            "trust_level": "dmz",
        },
        {
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
        },
        {
            "id": "ext-admin",
            "name": "Administrator",
            "type": "external_entity",
            "is_public_facing": True,
            "has_authentication": True,
            "has_encryption": True,
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
            "target_id": "comp-angular-frontend",
            "protocol": "HTTPS",
            "is_encrypted": True,
            "is_authenticated": False,
            "crosses_trust_boundary": True,
            "data_types": ["http_requests", "credentials", "search_queries"],
            "data_sensitivity": ["credentials", "pii"],
            "description": "User interacts with shop frontend",
        },
        {
            "id": "flow-frontend-api",
            "source_id": "comp-angular-frontend",
            "target_id": "comp-express-api",
            "protocol": "HTTP/internal",
            "is_encrypted": False,
            "is_authenticated": True,
            "crosses_trust_boundary": True,
            "data_types": ["api_requests", "jwt_tokens", "json_data"],
            "data_sensitivity": ["credentials"],
            "description": "Frontend calls REST API (internal, no encryption)",
        },
        {
            "id": "flow-api-db",
            "source_id": "comp-express-api",
            "target_id": "comp-sqlite",
            "protocol": "SQLite/file",
            "is_encrypted": False,
            "is_authenticated": False,
            "crosses_trust_boundary": False,
            "data_types": ["sql_queries", "user_data", "product_data", "order_data"],
            "data_sensitivity": ["credentials", "pii", "financial"],
            "description": "API queries database (Sequelize ORM + raw queries)",
        },
        {
            "id": "flow-user-files",
            "source_id": "ext-internet-user",
            "target_id": "comp-file-server",
            "protocol": "HTTPS",
            "is_encrypted": True,
            "is_authenticated": False,
            "crosses_trust_boundary": True,
            "data_types": ["file_requests", "path_parameters"],
            "data_sensitivity": ["internal"],
            "description": "User accesses static files and FTP directory",
        },
        {
            "id": "flow-admin-api",
            "source_id": "ext-admin",
            "target_id": "comp-express-api",
            "protocol": "HTTPS",
            "is_encrypted": True,
            "is_authenticated": True,
            "crosses_trust_boundary": True,
            "data_types": ["admin_commands", "user_management"],
            "data_sensitivity": ["credentials"],
            "description": "Admin manages users, products, feedback",
        },
    ],
    "trust_boundaries": [
        {
            "id": "tb-internet",
            "name": "Internet (Untrusted)",
            "trust_level": "external",
            "component_ids": ["ext-internet-user", "ext-admin"],
        },
        {
            "id": "tb-dmz",
            "name": "DMZ (Public-Facing Layer)",
            "trust_level": "dmz",
            "component_ids": ["comp-angular-frontend", "comp-file-server"],
        },
        {
            "id": "tb-internal",
            "name": "Internal Application Layer",
            "trust_level": "internal",
            "component_ids": ["comp-express-api", "comp-sqlite"],
        },
    ],
    "metadata": {"project_name": "OWASP Juice Shop"},
}


# ═══════════════════════════════════════════════════════════════════════════════
# FULL SAST FINDINGS (23 — matching real Semgrep output)
# ═══════════════════════════════════════════════════════════════════════════════

FULL_SAST_FINDINGS = [
    # --- SQL Injection (CWE-89) — 4 findings ---
    {"id": "sast-01", "title": "SQL Injection in search endpoint", "severity": "High", "confidence": 0.9, "cwe_id": "CWE-89", "rule_id": "javascript.express.security.injection.sql-injection", "file_path": "routes/search.ts", "line_number": 28, "tool_name": "semgrep"},
    {"id": "sast-02", "title": "SQL Injection in login query", "severity": "High", "confidence": 0.9, "cwe_id": "CWE-89", "rule_id": "javascript.express.security.injection.sql-injection", "file_path": "routes/login.ts", "line_number": 42, "tool_name": "semgrep"},
    {"id": "sast-03", "title": "SQL Injection in user profile", "severity": "High", "confidence": 0.85, "cwe_id": "CWE-89", "rule_id": "javascript.express.security.injection.sql-injection", "file_path": "routes/userProfile.ts", "line_number": 15, "tool_name": "semgrep"},
    {"id": "sast-04", "title": "SQL Injection in order history", "severity": "High", "confidence": 0.8, "cwe_id": "CWE-89", "rule_id": "javascript.express.security.injection.sql-injection", "file_path": "routes/order.ts", "line_number": 33, "tool_name": "semgrep"},
    # --- XSS (CWE-79) — 3 findings ---
    {"id": "sast-05", "title": "Reflected XSS via search parameter", "severity": "High", "confidence": 0.85, "cwe_id": "CWE-79", "rule_id": "javascript.express.security.xss.reflected-xss", "file_path": "routes/search.ts", "line_number": 35, "tool_name": "semgrep"},
    {"id": "sast-06", "title": "Stored XSS in product reviews", "severity": "High", "confidence": 0.80, "cwe_id": "CWE-79", "rule_id": "javascript.express.security.xss.stored-xss", "file_path": "routes/product.ts", "line_number": 67, "tool_name": "semgrep"},
    {"id": "sast-07", "title": "DOM XSS via URL fragment", "severity": "Medium", "confidence": 0.70, "cwe_id": "CWE-79", "rule_id": "javascript.browser.security.dom-xss", "file_path": "frontend/src/app/search/search.component.ts", "line_number": 22, "tool_name": "semgrep"},
    # --- Path Traversal (CWE-22) — 2 findings ---
    {"id": "sast-08", "title": "Path traversal in file serving", "severity": "High", "confidence": 0.82, "cwe_id": "CWE-22", "rule_id": "javascript.express.security.path-traversal", "file_path": "routes/fileServer.ts", "line_number": 18, "tool_name": "semgrep"},
    {"id": "sast-09", "title": "Path traversal in file upload handler", "severity": "High", "confidence": 0.78, "cwe_id": "CWE-22", "rule_id": "javascript.express.security.path-traversal", "file_path": "routes/fileUpload.ts", "line_number": 45, "tool_name": "semgrep"},
    # --- Hardcoded Credentials (CWE-798) — 2 findings ---
    {"id": "sast-10", "title": "Hardcoded JWT secret key", "severity": "High", "confidence": 0.99, "cwe_id": "CWE-798", "rule_id": "javascript.jwt.security.hardcoded-secret", "file_path": "lib/insecurity.ts", "line_number": 5, "tool_name": "semgrep"},
    {"id": "sast-11", "title": "Hardcoded admin credentials in seed data", "severity": "Medium", "confidence": 0.75, "cwe_id": "CWE-798", "rule_id": "javascript.security.hardcoded-credential", "file_path": "data/datacreator.ts", "line_number": 120, "tool_name": "semgrep"},
    # --- Weak Crypto (CWE-327/328) — 2 findings ---
    {"id": "sast-12", "title": "Use of MD5 for password hashing", "severity": "Medium", "confidence": 0.90, "cwe_id": "CWE-327", "rule_id": "javascript.crypto.security.weak-hash", "file_path": "lib/insecurity.ts", "line_number": 22, "tool_name": "semgrep"},
    {"id": "sast-13", "title": "Insecure random number generation", "severity": "Medium", "confidence": 0.70, "cwe_id": "CWE-330", "rule_id": "javascript.crypto.security.insecure-random", "file_path": "lib/insecurity.ts", "line_number": 48, "tool_name": "semgrep"},
    # --- Missing Input Validation (CWE-20) — 2 findings ---
    {"id": "sast-14", "title": "Missing input validation on coupon code", "severity": "Medium", "confidence": 0.65, "cwe_id": "CWE-20", "rule_id": "javascript.express.security.missing-validation", "file_path": "routes/coupon.ts", "line_number": 12, "tool_name": "semgrep"},
    {"id": "sast-15", "title": "Missing input validation on feedback", "severity": "Medium", "confidence": 0.60, "cwe_id": "CWE-20", "rule_id": "javascript.express.security.missing-validation", "file_path": "routes/feedback.ts", "line_number": 28, "tool_name": "semgrep"},
    # --- Open Redirect (CWE-601) — 1 finding ---
    {"id": "sast-16", "title": "Open redirect via next parameter", "severity": "Medium", "confidence": 0.75, "cwe_id": "CWE-601", "rule_id": "javascript.express.security.open-redirect", "file_path": "routes/redirect.ts", "line_number": 8, "tool_name": "semgrep"},
    # --- Deserialization (CWE-502) — 1 finding ---
    {"id": "sast-17", "title": "Unsafe deserialization of user input", "severity": "High", "confidence": 0.80, "cwe_id": "CWE-502", "rule_id": "javascript.security.unsafe-deserialization", "file_path": "routes/basket.ts", "line_number": 55, "tool_name": "semgrep"},
    # --- Missing Rate Limiting (CWE-770) — 1 finding ---
    {"id": "sast-18", "title": "No rate limiting on login endpoint", "severity": "Medium", "confidence": 0.60, "cwe_id": "CWE-770", "rule_id": "javascript.express.security.missing-rate-limit", "file_path": "server.ts", "line_number": 8, "tool_name": "semgrep"},
    # --- CSRF (CWE-352) — 1 finding ---
    {"id": "sast-19", "title": "Missing CSRF protection on state-changing endpoints", "severity": "Medium", "confidence": 0.70, "cwe_id": "CWE-352", "rule_id": "javascript.express.security.missing-csrf", "file_path": "server.ts", "line_number": 25, "tool_name": "semgrep"},
    # --- Sensitive Data Exposure (CWE-209) — 1 finding ---
    {"id": "sast-20", "title": "Stack trace exposed in error response", "severity": "Medium", "confidence": 0.80, "cwe_id": "CWE-209", "rule_id": "javascript.express.security.error-disclosure", "file_path": "routes/angular.ts", "line_number": 12, "tool_name": "semgrep"},
    # --- Code Injection (CWE-94) — 1 finding ---
    {"id": "sast-21", "title": "Eval of user-controlled input (b2bOrder)", "severity": "High", "confidence": 0.85, "cwe_id": "CWE-94", "rule_id": "javascript.security.eval-injection", "file_path": "routes/b2bOrder.ts", "line_number": 30, "tool_name": "semgrep"},
    # --- Prototype Pollution (CWE-1321) — 1 finding ---
    {"id": "sast-22", "title": "Prototype pollution via merge operation", "severity": "Medium", "confidence": 0.65, "cwe_id": "CWE-1321", "rule_id": "javascript.security.prototype-pollution", "file_path": "lib/utils.ts", "line_number": 44, "tool_name": "semgrep"},
    # --- Insufficient Logging (CWE-778) — 1 finding ---
    {"id": "sast-23", "title": "Security-critical operations without audit logging", "severity": "Medium", "confidence": 0.55, "cwe_id": "CWE-778", "rule_id": "javascript.express.security.missing-logging", "file_path": "routes/login.ts", "line_number": 5, "tool_name": "semgrep"},
]


# ═══════════════════════════════════════════════════════════════════════════════
# FULL DAST FINDINGS (10 — matching real OWASP ZAP baseline scan)
# ═══════════════════════════════════════════════════════════════════════════════

FULL_DAST_FINDINGS = [
    {"id": "dast-01", "title": "Missing Anti-CSRF Tokens", "severity": "Medium", "confidence": 0.8, "cwe_id": "CWE-352", "url": "http://localhost:3000/rest/user/login", "tool_name": "OWASP ZAP", "category": "auth"},
    {"id": "dast-02", "title": "Application Error Disclosure (Stack Trace)", "severity": "Medium", "confidence": 0.9, "cwe_id": "CWE-209", "url": "http://localhost:3000/api/", "tool_name": "OWASP ZAP", "category": "logging"},
    {"id": "dast-03", "title": "X-Frame-Options Header Not Set", "severity": "Low", "confidence": 0.7, "cwe_id": None, "url": "http://localhost:3000/", "tool_name": "OWASP ZAP", "category": "validation"},
    {"id": "dast-04", "title": "Cookie Without Secure Flag", "severity": "Low", "confidence": 0.8, "cwe_id": "CWE-614", "url": "http://localhost:3000/rest/user/login", "tool_name": "OWASP ZAP", "category": "crypto"},
    {"id": "dast-05", "title": "Cookie Without HttpOnly Flag", "severity": "Low", "confidence": 0.8, "cwe_id": "CWE-1004", "url": "http://localhost:3000/rest/user/login", "tool_name": "OWASP ZAP", "category": "crypto"},
    {"id": "dast-06", "title": "Content Security Policy Header Not Set", "severity": "Low", "confidence": 0.7, "cwe_id": None, "url": "http://localhost:3000/", "tool_name": "OWASP ZAP", "category": "validation"},
    {"id": "dast-07", "title": "Server Leaks Version Information (X-Powered-By)", "severity": "Low", "confidence": 0.9, "cwe_id": "CWE-200", "url": "http://localhost:3000/", "tool_name": "OWASP ZAP", "category": "logging"},
    {"id": "dast-08", "title": "Strict-Transport-Security Header Not Set", "severity": "Low", "confidence": 0.7, "cwe_id": None, "url": "http://localhost:3000/", "tool_name": "OWASP ZAP", "category": "crypto"},
    {"id": "dast-09", "title": "Directory Browsing Enabled (ftp/)", "severity": "Informational", "confidence": 0.95, "cwe_id": "CWE-548", "url": "http://localhost:3000/ftp/", "tool_name": "OWASP ZAP", "category": "validation"},
    {"id": "dast-10", "title": "Information Disclosure in Response Headers", "severity": "Informational", "confidence": 0.6, "cwe_id": "CWE-200", "url": "http://localhost:3000/api/", "tool_name": "OWASP ZAP", "category": "logging"},
]
