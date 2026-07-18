# CausalTM

**Automated STRIDE Threat Modeling powered by a Federated Structural Causal Model**

---

## What Is CausalTM?

CausalTM is a security tool that automatically produces a threat model for a software system. You give it your code repository and security scan reports. It gives you back a Data Flow Diagram, a list of STRIDE threats ranked by causal severity, concrete attack paths showing how an attacker could move through your system, and specific recommendations telling you which fix blocks the most threats.

The core innovation is the **Federated Structural Causal Model (FSCM)** — a causal AI architecture that reasons about cause and effect rather than statistical correlation. It does not require historical training data, does not suffer from concept drift, and produces explanations that auditors and regulators can follow.

---

## Inputs

CausalTM accepts three inputs. All three are optional — the tool works with whatever you provide, degrading gracefully when sources are missing.

### 1. Source Code Repository (Git URL)

What it is:
- A Git repository URL (HTTPS or SSH) containing application source code

What CausalTM extracts from it:
- System architecture (services, databases, external APIs)
- Data flows between components
- Trust boundaries (network zones, access levels)
- Technology stack
- Security patterns present in code (authentication, encryption, logging)

Files it looks at:
| File Type | What It Reveals |
|---|---|
| `Dockerfile`, `docker-compose.yml` | Services, databases, ports, dependencies between containers |
| Kubernetes manifests (`deployment.yaml`, `service.yaml`, `ingress.yaml`) | Namespaces, exposed services, network policies |
| API specifications (`openapi.yaml`, `swagger.json`, `schema.graphql`) | Endpoints, authentication schemes, data models |
| Configuration files (`.env`, `appsettings.json`, `application.yml`) | Database connections, external service URLs, secrets |
| Dependency manifests (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`) | Technology stack, security libraries in use |
| Source code (any language) | HTTP client calls, database queries, auth patterns, crypto usage |

### 2. SAST Report (Static Analysis)

What it is:
- Output from a static analysis security tool in **SARIF format** (JSON)
- Contains: vulnerability type (CWE), file path, line number, severity

Compatible tools:
- Semgrep (free, open-source)
- CodeQL (free for open-source)
- Coverity (enterprise)
- Bandit (Python-specific)
- SpotBugs/FindSecBugs (Java-specific)

What CausalTM uses it for:
- Identifies which components have code-level vulnerabilities
- Maps vulnerability types (CWE) to potential impacts via domain knowledge
- Computes vulnerability density, injection risk, auth coverage gaps
- Feeds the SAST sub-graph of the causal engine

### 3. DAST Report (Dynamic Analysis)

What it is:
- Output from a dynamic analysis security tool in **XML format**
- Contains: confirmed exploitable vulnerabilities, URLs, request/response evidence

Compatible tools:
- OWASP ZAP (free, open-source)
- Netsparker / Invicti (enterprise)
- Nuclei (free, template-based)

What CausalTM uses it for:
- Confirms which vulnerabilities are actually exploitable at runtime
- Maps the real attack surface (what endpoints exist and are reachable)
- Identifies authentication bypass, TLS issues, information leakage
- DAST findings carry higher causal weight (0.95) because they are runtime-proven

---

## Outputs

CausalTM produces five outputs from a single analysis run.

### 1. Data Flow Diagram (DFD)

**Format:** SVG (vector graphic, embeddable in reports)

**What it shows:**
- All discovered components using standard DFD notation:
  - Circles = Processes (services, APIs)
  - Cylinders = Data Stores (databases, caches)
  - Rectangles = External Entities (users, third-party APIs)
- Data flows as labeled arrows (protocol, data types)
- Trust boundaries as dashed boxes
- Color coding: red = public-facing, green = encrypted, purple = crosses boundary
- Security indicators on flows (lock = encrypted, key = authenticated, warning = boundary crossing)

### 2. STRIDE Threat Report

**Format:** HTML (self-contained, professional, printable) + Markdown

**What it contains:**
1. Executive Summary — risk score (0-10), critical/high/medium/low counts
2. Component Inventory — table of all detected elements with security properties
3. Data Flow Diagram — embedded SVG
4. STRIDE Threat Catalog — all identified threats grouped by category, with:
   - Severity and confidence score
   - Affected component
   - Evidence (why this threat was identified)
   - CWE references
   - Recommended mitigations
5. Attack Paths — top causal chains from attacker entry to business impact
6. Counterfactual Recommendations — "if you fix X, risk drops by Y%"
7. Confounder Warnings — factors that may inflate or deflate perceived risk

### 3. Causal Attack Graph

**Format:** JSON (structured data) + narrative descriptions

**What it shows:**
- Concrete attacker-movement paths through the system:
  ```
  Attacker → Web Service → exploits CWE-89 → Database → Data Breach
  ```
- Each path scored (0-1) based on: edge weights, path length, boundary crossings, DAST confirmation
- Choke points — components that appear on the most paths (fix these first)
- Narratives in plain English: "Attacker targets Web Service, exploits SQL injection, accesses database, resulting in data breach."

### 4. Counterfactual Mitigation Recommendations

**Format:** Ranked list with quantified impact

**What it provides:**
- Strategic interventions (cross-layer): "Fix all critical SAST findings → 29.8% risk reduction"
- Tactical interventions (specific): "Add API gateway → 15.4% risk reduction"
- Each recommendation shows: risk before, risk after, percentage reduction, affected layers
- Ranked by effectiveness — highest impact first

### 5. Risk Analysis Summary

**Format:** JSON (machine-readable for integration)

**What it provides:**
- Overall risk score: 0.0 to 1.0 with rating (Minimal/Low/Medium/High/Critical)
- Layer contributions: how much each data source drives the risk (e.g., SAST: 42%, DAST: 23%, Repo: 35%)
- Intermediate scores: exploitability, exposure, impact severity, blast radius, mitigation posture
- Graph statistics: nodes, edges, paths found per layer

---

## What Happens Inside (The Processing Pipeline)

```
INPUT                           PROCESSING                              OUTPUT
─────                           ──────────                              ──────

Git Repo URL ──────┐
                   │
SAST Report ───────┤
(SARIF)            │
                   ▼
DAST Report ───────┤     ┌─────────────────────────────────────┐
(ZAP XML)          ├────▶│         CausalTM Pipeline            │
                   │     │                                     │
                   │     │  Step 1: CLONE & DETECT             │──▶ Component Graph
                   │     │  Step 2: INGEST REPORTS             │──▶ Normalized Findings
                   │     │  Step 3: BUILD CAUSAL MODEL         │──▶ Federated SCM
                   │     │  Step 4: ANALYZE (causal reasoning) │──▶ Risk + Paths
                   │     │  Step 5: CLASSIFY (STRIDE rules)    │──▶ Threat List
                   │     │  Step 6: RENDER (Graphviz)          │──▶ DFD Diagram
                   │     │  Step 7: REPORT (Jinja2)            │──▶ HTML Report
                   │     │                                     │
                   │     └─────────────────────────────────────┘
                   │
                   └─────────────────────────────────────────────────▶ Artifacts
```

### Step 1: Clone & Detect Architecture

```
Git clone (shallow) → Walk all files → Run 6 detectors:
  - Docker/Compose detector → services, databases, ports
  - Kubernetes detector → deployments, ingress, namespaces
  - API spec detector → endpoints, auth schemes, data models
  - Config detector → DB connections, external services, secrets
  - Dependency detector → tech stack, security libraries
  - Code pattern detector → HTTP calls, DB queries, auth/crypto usage

Output: ComponentGraph (components + data_flows + trust_boundaries)
```

### Step 2: Ingest SAST/DAST Reports

```
SARIF file → Parse JSON → Extract: CWE, file, line, severity, confidence
ZAP XML → Parse XML → Extract: URL, vuln type, severity, evidence, confirmed

Output: List of NormalizedFindings (common schema regardless of source tool)
```

### Step 3: Build Federated Causal Model

This is the core innovation. Three independent causal sub-graphs are built:

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  SAST Sub-Graph (code-level reasoning)                              │
│  ──────────────────────────────────────                             │
│  Nodes: findings, CWE categories, components, root causes          │
│  Internal reasoning: shared root causes, coverage gaps              │
│  Produces 6 edge nodes:                                             │
│    • vulnerability_density (weighted severity score)                │
│    • injection_risk (injection-type CWE ratio)                      │
│    • auth_coverage (how much code has auth patterns)                │
│    • crypto_usage (encryption implementation quality)               │
│    • affected_components (ratio of components with findings)        │
│    • root_cause_concentration (how clustered are the vulns)         │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  DAST Sub-Graph (runtime-level reasoning)                           │
│  ───────────────────────────────────────                            │
│  Nodes: confirmed exploits, endpoints, categories                   │
│  Internal reasoning: attack surface mapping, confirmation chains    │
│  Produces 6 edge nodes:                                             │
│    • confirmed_exploitable (ratio of runtime-proven vulns)          │
│    • attack_surface (number of exposed endpoints)                   │
│    • auth_bypass_evidence (auth issues found at runtime)            │
│    • tls_posture (TLS/SSL configuration quality)                    │
│    • information_leakage (data exposed in responses)                │
│    • severity_score (weighted critical+high findings)               │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Repo Sub-Graph (architecture-level reasoning)                      │
│  ─────────────────────────────────────────────                      │
│  Nodes: services, databases, external entities, flows, boundaries   │
│  Internal reasoning: exposure, dependency chains, defense layers    │
│  Produces 7 edge nodes:                                             │
│    • public_exposure (ratio of internet-facing components)          │
│    • trust_boundary_crossings (density of cross-zone flows)         │
│    • data_sensitivity (highest sensitivity level in system)         │
│    • dependency_depth (longest service chain)                       │
│    • defense_depth (layered security indicators)                    │
│    • single_point_of_failure (most-connected component risk)        │
│    • segmentation (network isolation quality)                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                              │
                    19 edge nodes total
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  Master DAG (cross-layer causal reasoning)                          │
│  ─────────────────────────────────────────                          │
│                                                                     │
│  Receives 19 edge nodes → Computes 5 intermediate causal variables: │
│                                                                     │
│    Exploitability = f(SAST.density, SAST.injection, DAST.confirmed) │
│    Exposure = f(Repo.public, Repo.crossings, DAST.surface)          │
│    Impact Severity = f(Repo.sensitivity, SAST.affected, Repo.SPOF)  │
│    Blast Radius = f(Repo.depth, Repo.SPOF, SAST.affected)           │
│    Mitigation Posture = f(Repo.defense, SAST.auth, DAST.tls)        │
│                                                                     │
│  Overall Risk = (Exploitability×0.4 + Exposure×0.3 + Impact×0.3)   │
│                 × (1 - Mitigation × 0.4)                            │
│                                                                     │
│  Also performs:                                                      │
│    • Strategic counterfactuals (set edge nodes to 0, recompute)     │
│    • Cross-layer confounder detection                               │
│    • Layer contribution analysis (which source drives risk)         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  Causal Attack Graph (concrete path composition)                    │
│  ───────────────────────────────────────────────                    │
│                                                                     │
│  Composes all three sub-graphs into concrete attacker paths:        │
│    • Repo provides: topology (who connects to whom)                 │
│    • SAST provides: exploitable steps (which components have vulns) │
│    • DAST provides: confirmed entry points (what's proven reachable)│
│                                                                     │
│  Enumerates: Attacker → Entry → Exploit → Pivot → Target → Impact  │
│  Scores paths by: edge weight × length × boundary × confirmation   │
│  Identifies choke points: components on the most paths              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Step 4: Analyze (Causal Reasoning)

The federated engine performs:
- **Attack path enumeration** — all causal chains from entry to impact
- **Counterfactual analysis** — "if we fix X, how many paths break?"
- **Confounder detection** — "is internet exposure inflating this risk?"
- **Impact propagation** — "if this component falls, what else is affected?"
- **Layer contribution** — "is risk driven by code vulns, runtime exploits, or architecture?"

### Step 5: Classify (STRIDE Rules)

16 built-in YAML rules evaluate each DFD element against STRIDE categories:
- Rules check element properties (is_public_facing, has_authentication, has_encryption)
- Rules check flow properties (crosses_trust_boundary, is_encrypted, data_sensitivity)
- Causal enrichment adjusts severity based on attack path position and DAST confirmation

### Step 6: Render (Graphviz DFD)

The DFD model is rendered to SVG using Graphviz with:
- Standard DFD notation (circles, cylinders, rectangles)
- Trust boundary clusters (dashed boxes)
- Color-coded flows by security status
- Legend explaining notation

### Step 7: Report (Jinja2 Templates)

All results are assembled into an HTML report using Jinja2 templates:
- Executive summary with risk score
- Embedded DFD diagram
- Threat catalog grouped by STRIDE category
- Attack paths with narratives
- Counterfactual recommendations ranked by impact

---

## Why Causal AI Instead of Machine Learning?

| Question | Correlation AI (ML) | CausalTM (Causal AI) |
|---|---|---|
| "What's our risk?" | Outputs a score | Outputs a score **with explanation** |
| "Why is it risky?" | "The model says so" | "Because CWE-89 in the web service enables access to the database which stores PII" |
| "What should we fix first?" | Can't answer this | "Fix SAST critical findings → 29.8% risk reduction" |
| "What if we add a gateway?" | Can't answer this | "Risk drops from 0.45 to 0.38 (15.4% reduction)" |
| Needs training data? | Yes (thousands of labeled examples) | **No** (works from first scan) |
| Degrades over time? | Yes (concept drift) | **No** (causal mechanisms are stable) |
| Works at new organisation? | Must retrain | **Works immediately** |
| Auditor-friendly? | No (black box) | **Yes** (full causal chain visible) |

---

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Language | Python 3.11 | Core implementation |
| Causal graphs | NetworkX | Directed graph operations, path enumeration |
| Data models | Pydantic v2 | Type-safe schemas, serialization |
| API | FastAPI | REST endpoints for triggering scans |
| Architecture detection | Custom detectors | Docker, K8s, OpenAPI, config, deps, code patterns |
| SAST ingestion | SARIF v2.1.0 parser | Standard format for all SAST tools |
| DAST ingestion | XML parser (ZAP/Netsparker) | Standard format for DAST tools |
| DFD rendering | Graphviz | Professional SVG/PNG diagram output |
| Reports | Jinja2 templates | HTML and Markdown threat reports |
| Git operations | GitPython | Repository cloning |
| CI/CD | GitHub Actions | Automated testing and artifact generation |

---

## Project Structure

```
CausalTM/
├── src/
│   ├── main.py                          # FastAPI application entry point
│   ├── api/                             # REST API layer
│   │   ├── routes/                      # Endpoints: scans, reports, health
│   │   └── models/                      # Request/response schemas
│   ├── intake/                          # Git clone + pipeline orchestration
│   │   ├── git_client.py               # Repository cloning
│   │   └── scan_manager.py             # Full pipeline orchestrator
│   ├── analyzer/                        # Architecture auto-detection
│   │   ├── engine.py                   # Runs all detectors, merges results
│   │   ├── detectors/                  # Docker, K8s, API, config, deps, code
│   │   └── models/                     # Component, DataFlow, TrustBoundary
│   ├── ingestors/                       # SAST/DAST report parsing
│   │   ├── sarif_ingestor.py           # SARIF v2.1.0 (any SAST tool)
│   │   └── zap_ingestor.py            # ZAP XML + Netsparker XML
│   ├── causal/                          # Causal AI engine
│   │   ├── federated/                  # ← CORE INNOVATION
│   │   │   ├── base.py                # EdgeNode contract, CausalSubGraph ABC
│   │   │   ├── sast_subgraph.py       # Code-level causal reasoning
│   │   │   ├── dast_subgraph.py       # Runtime-level causal reasoning
│   │   │   ├── repo_subgraph.py       # Architecture-level causal reasoning
│   │   │   ├── master_dag.py          # Cross-layer reasoning + counterfactuals
│   │   │   ├── attack_graph.py        # Concrete attack path composition
│   │   │   └── engine.py             # FederatedCausalEngine orchestrator
│   │   ├── engine.py                   # Legacy flat engine (backward compatible)
│   │   └── models.py                   # Legacy models
│   ├── dfd/                             # Data Flow Diagram construction
│   │   ├── models.py                   # DFDElement, DFDDataFlow, DFDBoundary
│   │   └── builder.py                 # ComponentGraph → DFDModel
│   ├── stride/                          # STRIDE threat classification
│   │   ├── engine.py                   # Applies rules to DFD elements
│   │   ├── rules/                     # Rule loader + evaluator
│   │   └── models/                    # Threat, ThreatModelResult
│   ├── renderer/                        # Diagram rendering
│   │   └── graphviz_renderer.py       # Graphviz DFD → SVG/PNG
│   └── reporter/                        # Report generation
│       ├── generator.py               # Assembles report from all data
│       └── templates/                 # Jinja2 HTML/Markdown templates
├── rules/
│   └── default.yaml                    # 16 built-in STRIDE rules
├── scripts/
│   ├── test_engine.py                  # Quick causal engine test
│   └── demo_full_pipeline.py          # End-to-end demo with sample data
├── .github/workflows/
│   └── ci.yml                          # GitHub Actions: lint, test, demo
├── docs/                                # Research documents, paper drafts
├── Dockerfile                           # Container deployment
├── docker-compose.yml                   # Full stack (API + Redis + Postgres)
└── pyproject.toml                       # Dependencies and build config
```

---

## Quick Start

### Run the Demo (GitHub Actions)

Push to `main` → CI automatically runs the full pipeline → Download artifacts (DFD + Report) from the Actions tab.

### Run Locally

```bash
# Clone
git clone https://github.com/thayyilsarin/CausalTM.git
cd CausalTM

# Install (requires Python 3.11+ and Graphviz)
pip install networkx pydantic pyyaml jinja2 fastapi uvicorn gitpython lxml graphviz httpx python-multipart

# Run the demo
python scripts/demo_full_pipeline.py

# Output appears in:
#   data/diagrams/demo-dfd.svg
#   data/reports/demo-report.html
#   data/reports/demo-report.md
```

### Run the API Server

```bash
uvicorn src.main:app --reload --port 8000
# API docs at: http://localhost:8000/docs
```

---

## Research Context

This tool is the artifact for a DBA dissertation at Rushford Business School, exploring whether Federated Structural Causal Models can improve cybersecurity risk decision-making compared to traditional approaches. The research is also being prepared for publication at AMICT 2026 (IEEE Xplore + Scopus indexed).

**Key research question:** Does causal counterfactual analysis improve the quality of cybersecurity investment decisions over traditional severity-based prioritisation?

---

## License

MIT
