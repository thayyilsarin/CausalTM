# CausalTM — Causal AI-Driven STRIDE Threat Modeling

Automated threat modeling platform that combines **Static Analysis (SAST)**, **Dynamic Analysis (DAST)**, and **source code architecture detection** with a **Causal AI inference engine** to generate Data Flow Diagrams and STRIDE threat reports.

## What It Does

```
Git Repo + Coverity/Semgrep (SAST) + Netsparker/ZAP (DAST)
    │
    ▼
┌──────────────────────────────────────────────────┐
│              CausalTM Pipeline                    │
│                                                  │
│  1. Clone & analyze repo architecture            │
│  2. Ingest SAST/DAST scan reports                │
│  3. Build causal graph (attack paths, impacts)   │
│  4. Apply STRIDE threat classification           │
│  5. Detect confounders & mediators               │
│  6. Run counterfactual mitigation analysis       │
│  7. Generate DFD diagram + threat report         │
└──────────────────────────────────────────────────┘
    │
    ▼
DFD Diagram (SVG/PNG) + STRIDE Report (HTML/PDF/MD)
```

## Key Features

- **Language-agnostic architecture detection** — Docker, Kubernetes, OpenAPI, env files, dependency manifests
- **Multi-source SAST/DAST ingestion** — SARIF (Coverity, Semgrep, CodeQL) + ZAP/Netsparker XML
- **Causal AI correlation engine** — Not just rule-based; uses causal graphs for attack path reasoning
- **Confounder detection** — Identifies factors that inflate/deflate perceived risk
- **Counterfactual analysis** — "If we apply mitigation X, does attack path Y break?"
- **Professional DFD rendering** — Graphviz-based with standard DFD notation and color coding
- **Comprehensive STRIDE reports** — HTML, Markdown, JSON with executive summary and evidence

## Quick Start

### Prerequisites

- Python 3.11+
- Graphviz (`apt install graphviz` or `brew install graphviz`)
- Docker (optional, for containerized deployment)

### Local Development

```bash
# Clone (or navigate to project directory)
cd CausalTM

# Create virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/Mac
# .venv\Scripts\activate    # Windows

# Install dependencies
pip install -e ".[dev]"

# Run the API server
uvicorn src.main:app --reload --port 8000
```

### Docker Deployment

```bash
docker-compose up -d
```

This starts:
- **API** on `http://localhost:8000`
- **Redis** for task queue
- **PostgreSQL** for scan storage
- **Celery worker** for async processing

## API Usage

### Trigger a Scan

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/juice-shop/juice-shop.git",
    "branch": "main",
    "project_name": "OWASP Juice Shop"
  }'
```

### Upload SAST Report

```bash
curl -X POST http://localhost:8000/api/v1/scans/{scan_id}/reports/sast \
  -F "file=@results.sarif"
```

### Upload DAST Report

```bash
curl -X POST http://localhost:8000/api/v1/scans/{scan_id}/reports/dast \
  -F "file=@zap-report.xml"
```

### Get Results

```bash
# Scan status
curl http://localhost:8000/api/v1/scans/{scan_id}

# Threat findings
curl http://localhost:8000/api/v1/scans/{scan_id}/threats

# HTML report
curl http://localhost:8000/api/v1/reports/{scan_id}?format=html

# DFD diagram
curl http://localhost:8000/api/v1/reports/{scan_id}/diagram?format=svg

# Causal graph data
curl http://localhost:8000/api/v1/reports/{scan_id}/causal-graph
```

## Architecture

```
src/
├── main.py                  # FastAPI entry point
├── api/                     # REST API layer
│   ├── routes/              # Endpoint definitions
│   └── models/              # Request/response schemas
├── intake/                  # Git clone + scan orchestration
├── analyzer/                # Architecture detection
│   └── detectors/           # Docker, K8s, API spec, config, deps, code patterns
├── ingestors/               # SAST/DAST report parsers
│   ├── sarif_ingestor.py    # SARIF v2.1.0 (Coverity, Semgrep, CodeQL)
│   └── zap_ingestor.py      # ZAP XML, Netsparker/Invicti XML
├── dfd/                     # Data Flow Diagram model + builder
├── stride/                  # STRIDE rule engine
│   └── rules/               # YAML-based threat rules
├── causal/                  # Causal AI engine (core innovation)
│   ├── engine.py            # Graph construction, attack paths, counterfactuals
│   └── models.py            # Causal nodes, edges, analysis results
├── renderer/                # DFD diagram rendering (Graphviz)
└── reporter/                # Report generation (Jinja2 templates)
```

## Causal Engine — The Core Innovation

Unlike traditional rule-based threat modeling, CausalTM uses a **Structural Causal Model (SCM)** to reason about threats:

| Capability | What It Does |
|-----------|-------------|
| Attack Path Enumeration | Finds all causal chains from entry points to impacts |
| Confounder Detection | Identifies factors that create spurious risk correlations |
| Mediator Identification | Finds intervention points that break attack chains |
| Impact Propagation | Calculates blast radius if a component is compromised |
| Counterfactual Analysis | "If we fix X, how many attack paths are eliminated?" |

This enables **quantifiable, evidence-based threat prioritization** rather than just severity labels.

## STRIDE Rules

Built-in rules are defined in `rules/default.yaml`. Each rule specifies:
- STRIDE category
- Applicable element types (process, data_store, external_entity)
- Conditions (checked against element and flow properties)
- Severity and confidence scores
- CWE mappings
- Suggested mitigations

Custom rules can be added by creating additional YAML files in the `rules/` directory.

## Supported Input Formats

| Source | Format | Tool |
|--------|--------|------|
| SAST | SARIF v2.1.0 | Coverity, Semgrep, CodeQL, Bandit |
| DAST | ZAP XML | OWASP ZAP |
| DAST | Netsparker XML | Netsparker/Invicti |
| Architecture | Docker/Compose | docker-compose.yml, Dockerfile |
| Architecture | Kubernetes | Deployments, Services, Ingress |
| Architecture | API Specs | OpenAPI/Swagger, GraphQL |
| Architecture | Config Files | .env, appsettings.json, application.yml |
| Architecture | Dependencies | package.json, requirements.txt, go.mod |

## Development

```bash
# Run tests
pytest

# Type checking
mypy src/

# Linting
ruff check src/

# Format
ruff format src/
```

## Roadmap

- [ ] Phase 1: Working prototype with open-source tool evaluation (current)
- [ ] Phase 2: tree-sitter code analysis, Visio export, CI/CD webhooks
- [ ] Phase 3: LLM-augmented analysis, custom rule UI, compliance mapping

## Research

This project explores the application of causal inference to automated threat modeling — a novel combination suitable for academic publication. See `docs/DESIGN.md` for the full system design document.

## License

MIT
