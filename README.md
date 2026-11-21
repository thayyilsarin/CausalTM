# CausalTM

**Automated STRIDE Threat Modeling powered by a Federated Structural Causal Model**

> **Paper artifact.** This repository is the artifact for the paper *"A Federated Structural Causal Model for Automated STRIDE Threat Modeling from Multi-Source Security Intelligence"* (AMICT 2026). To regenerate every result reported in the paper, see [Reproducing the AMICT 2026 paper](#reproducing-the-amict-2026-paper). To cite it, see [How to cite](#how-to-cite).

---

## What Is CausalTM?

CausalTM is a security tool that automatically produces a threat model for a software system. You give it your code repository and security scan reports. It gives you back a Data Flow Diagram, a list of STRIDE threats ranked by causal severity, concrete attack paths showing how an attacker could move through your system, and specific recommendations telling you which fix blocks the most threats.

The core idea is the **Federated Structural Causal Model (FSCM)**: separate causal sub-models for code, runtime and architecture evidence, combined by explicit rules. It treats each scanner finding as evidence of a gap in control coverage at a specific trust boundary, rather than counting vulnerabilities. It does not require historical training data, and every result can be traced back to the findings and rules that produced it.

---

## Engine Versions

The repository contains three engines. Only the boundary-specific engine (v3) is evaluated in the paper.

| Engine | Location | Used by | Description |
|---|---|---|---|
| Federated (v1) | `src/causal/federated/` | API server, `scripts/demo_full_pipeline.py` | Three sub-graphs (SAST, DAST, repository) feeding a master DAG; described in detail below |
| Global posture (v2) | `src/causal/v2/` | `scripts/run_v2_full.py` | One posture value per control category across the whole system; the baseline in the paper |
| Boundary-specific (v3) | `src/causal/v3/` | `scripts/eval_juice_shop_v3_full.py` | Posture per control category **and** trust boundary, fusion with worst-case adjustment, hybrid STRIDE classification; the engine evaluated in the paper |

---

## Reproducing the AMICT 2026 paper

All results in the paper regenerate from fixtures committed to this repository. No scanner, network access or clone of the target application is needed.

**Requirements:** Python 3.11 or later, plus `networkx` and `pydantic`:

```bash
git clone https://github.com/thayyilsarin/CausalTM.git
cd CausalTM
pip install networkx pydantic
```

**Inputs (fixtures):** `src/causal/v3/fixtures/juice_shop_full.py` holds the OWASP Juice Shop component graph (6 components, 5 data flows, 3 trust boundaries), the 23 SAST findings (Semgrep, rule sets p/javascript and p/nodejs) and the 10 DAST findings (OWASP ZAP baseline scan of a running instance).

**Run, from the repository root, in this order:**

| Step | Command | Regenerates |
|---|---|---|
| 1 | `python scripts/eval_juice_shop_v3_full.py` | Canonical v3 results, STRIDE threats, fused posture per control category and boundary, attack paths, what-if analysis. Writes `data/eval-v3-full-juice-shop.json` and `data/reports/juice-shop-v3-full-report.md` |
| 2 | `python scripts/run_v2_full.py` | v2 (global) results and the v2 vs v3 comparison, including roadmap length and STRIDE posture per category. Reads the JSON written in step 1 |
| 3 | `python scripts/sensitivity_sweep.py` | Parameter sensitivity: the 20 combinations of K in {2.0, 3.0, 4.0, 5.0} (SAST and DAST sub-DAGs) and alpha in {0.4, 0.5, 0.6, 0.7, 0.8} (fusion layer) |

**Expected key values:** v3 overall risk 0.404 (Medium) against 0.431 for v2; 6 STRIDE threats (5 rule-matched, 1 posture-derived); 5 uncertain divergences; remediation roadmap of 4 steps for v3 against 8 for v2. Across the 20 sensitivity settings, overall risk ranges from 0.336 to 0.473, while threats, categories, classification split and roadmap length are unchanged.

**Scope of the evaluation:** the paper compares global (v2) and boundary-specific (v3) aggregation on identical inputs. It does not measure detection accuracy, analyst effort or cost. The component graph is supplied directly from the fixtures; automatic derivation of the architecture from a repository (`src/analyzer/detectors/`) is implemented but not evaluated in the paper.

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
1. Executive Summary — threat-based risk score out of 10, critical/high/medium/low counts
2. Component Inventory — table of all detected elements with security properties
3. Data Flow Diagram — embedded SVG
4. STRIDE Threat Catalog — all identified threats grouped by category, with:
   - Severity and confidence score
   - Affected component
   - Evidence (why this threat was identified)
   - CWE references
   - Recommended mitigations
5. Attack Paths — top causal chains from attacker entry to business impact
6. What-If Recommendations — "if you fix X, modelled risk drops by Y%"
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

### 4. What-If (Interventional) Mitigation Recommendations

**Format:** Ranked list with quantified impact

**What it provides:**
- Strategic interventions (cross-layer), for example: "Fix all critical SAST findings → X% modelled risk reduction"
- Tactical interventions (specific), for example: "Add API gateway → Y% modelled risk reduction"
- Reductions are computed by the causal model, not measured on a running system
- Each recommendation shows: risk before, risk after, percentage reduction, affected layers
- Ranked by effectiveness — highest impact first

### 5. Risk Analysis Summary

**Format:** JSON (machine-readable for integration)

**What it provides:**
- Overall causal risk: 0.0 to 1.0 with rating (Minimal/Low/Medium/High/Critical). This is separate from the threat-based score out of 10 shown in the HTML report
- Layer contributions: how much each data source drives the risk (e.g., SAST: 42%, DAST: 23%, Repo: 35%)
- Intermediate scores: exploitability, exposure, impact severity, blast radius, mitigation posture
- Graph statistics: nodes, edges, paths found per layer

---

## What Happens Inside (The Processing Pipeline)

This section describes the full pipeline used by the API server and the demo, which runs the federated (v1) engine. The paper's v3 engine shares the inputs and STRIDE stage but computes posture per trust boundary; see [Engine Versions](#engine-versions).

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
│    • Strategic what-if interventions (set edge nodes to 0, recompute)│
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
- **What-if (interventional) analysis** — "if we fix X, how many paths break?"
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
- What-if recommendations ranked by impact

---

## How CausalTM Differs from ML-Based Prioritisation

Machine-learning approaches to vulnerability prioritisation learn from historical exploitation data and rank individual vulnerabilities. CausalTM takes a different route:

- **No training data.** It reasons from the system's own architecture and scan findings, so it can run on the first scan of a new system.
- **Architecture-aware.** Findings are attached to the trust boundaries and data flows they affect, so results are localised to where a control is missing.
- **Traceable.** Each threat and recommendation can be traced back to the findings, boundaries and rules that produced it.
- **What-if questions.** It can estimate how modelled risk changes if a control is fixed (an interventional query).

**Limitations.** The severity weights, the calibration constant K, the fusion weight alpha and the cross-layer rule strengths are set by expert judgement, not calibrated from data. What-if results are model predictions; they have not been compared with measurements on a running system. Counterfactual queries in the formal sense (reasoning about what would have happened in a specific past case) are not implemented. See the paper's limitations section for details.

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
│   │   │   ├── master_dag.py          # Cross-layer reasoning + what-if analysis
│   │   │   ├── attack_graph.py        # Concrete attack path composition
│   │   │   └── engine.py             # FederatedCausalEngine orchestrator
│   │   ├── v2/                         # Global-posture engine (paper baseline)
│   │   ├── v3/                         # Boundary-specific engine (evaluated in the paper)
│   │   │   └── fixtures/              # Juice Shop graph + 23 SAST and 10 DAST findings
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
│   ├── eval_juice_shop_v3_full.py      # Paper: v3 evaluation on Juice Shop
│   ├── run_v2_full.py                  # Paper: v2 baseline and v2 vs v3 comparison
│   ├── sensitivity_sweep.py            # Paper: K and alpha sensitivity (20 settings)
│   ├── test_engine.py                  # Quick causal engine test
│   └── demo_full_pipeline.py          # End-to-end demo with sample data
├── .github/workflows/
│   └── ci.yml                          # GitHub Actions: lint, test, demo
├── data/                                # Evaluation outputs (JSON, Markdown)
├── tests/                               # Unit tests for the v3 engine
├── CITATION.cff                         # Citation metadata (used by GitHub and Zenodo)
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

## How to Cite

If you use CausalTM, please cite the paper:

> S. K. Thayyilsubramanian, R. Srinivasan, and S. Chamarajanagar Ramachandra Rao, "A Federated Structural Causal Model for Automated STRIDE Threat Modeling from Multi-Source Security Intelligence," in *Proceedings of the 2026 International Conference on Advances in Machine Intelligence, and Cybersecurity Technologies (AMICT)*, IEEE, 2026.

Citation metadata is also provided in [`CITATION.cff`](CITATION.cff); GitHub's "Cite this repository" button uses it.

---

## Research Context

CausalTM was developed as part of doctoral research (DBA) at Rushford Business School on whether Federated Structural Causal Models can improve cybersecurity risk decisions compared with severity-based prioritisation. The evaluation reported in the paper is deliberately narrow: it isolates the effect of boundary-specific aggregation on threat localisation and remediation roadmap length.

---

## License

MIT
