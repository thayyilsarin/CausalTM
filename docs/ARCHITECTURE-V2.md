# CausalTM Architecture v2 — Definitive Design

*Last updated: July 2026 (reflects implemented and tested state)*

## Core Principle

CausalTM is a **STRIDE-based Threat Modeling** tool. It does NOT fix vulnerabilities — that is the job of SAST and DAST tools. CausalTM consumes their outputs to **understand the application's architecture** and then applies **STRIDE threat analysis** to that architecture using a **Federated Structural Causal Model** for reasoning.

The tool answers one question: *"Given this application's design, what are the architectural threats, and what is the optimal sequence of fixes to eliminate them all?"*

---

## The Five-Layer Stack

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 5: STRIDE THREAT MODEL (The Cream Layer)                     │
│  ═══════════════════════════════════════════════                     │
│  Identifies DESIGN-LEVEL threats from the architecture.             │
│  Does NOT need vulnerabilities — architecture alone is sufficient.  │
│  Evaluates all 6 categories using multi-layer posture evidence.     │
│  Traces CWEs from base variables for ground truth validation.       │
│  Output: Threat Model + Posture per Category + Risk Score           │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 4: MASTER DAG (Cross-Layer Causal Reasoning)                 │
│  ══════════════════════════════════════════════════                  │
│  Combines 12 edge nodes from 3 sub-DAGs.                            │
│  Applies 6 cross-layer dependency rules.                            │
│  Graph includes: edge nodes → STRIDE posture → Overall Risk.        │
│  Performs: What-If, Counterfactual, Roadmap to Zero.                │
│  Tracks fixed_nodes to avoid duplicate recommendations.             │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 3: SUB-DAGs (Per-Source Architecture Extraction)             │
│  ═════════════════════════════════════════════════════               │
│  Each sub-DAG extracts ARCHITECTURAL POSTURE, not vuln counts.      │
│  Base variables (causes) = individual findings/facts                │
│  Edge nodes (effects) = aggregated security posture scores          │
│  Posture is SEVERITY-WEIGHTED (Critical=1.0, High=0.7, Medium=0.4) │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 2: INGESTORS (Parse & Normalize)                             │
│  ═══════════════════════════════════════                             │
│  SARIF parser (any SAST tool) → normalized findings                 │
│  ZAP/Netsparker XML parser → normalized findings                    │
│  Repo file walker + detectors → component graph                     │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 1: INPUT SOURCES (External — Not Our Job)                    │
│  ═══════════════════════════════════════════════                     │
│  SAST tool: Finds & tracks code vulnerabilities (their job)         │
│  DAST tool: Finds & tracks runtime vulnerabilities (their job)      │
│  Git repository: Contains source + infrastructure configs           │
│  We CONSUME their output to understand the application design.      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Layer 3: Sub-DAGs — How Posture Is Calculated

### SAST Sub-DAG: "What Security Controls Exist in the Code?"

**Input:** SARIF report from any SAST tool (Semgrep, Coverity, CodeQL, Bandit)

**What it does:** Classifies each finding as evidence of an architectural control gap:

| Finding's CWE | Maps To | Meaning |
|---|---|---|
| CWE-287, CWE-306, CWE-862, CWE-798, CWE-352 | `auth` posture gap | Architecture lacks authentication at this boundary |
| CWE-311, CWE-319, CWE-327, CWE-347 | `crypto` posture gap | Architecture lacks proper encryption |
| CWE-89, CWE-79, CWE-78, CWE-22, CWE-20, CWE-502 | `validation` posture gap | Architecture lacks input validation at this boundary |
| CWE-778, CWE-532, CWE-209 | `logging` posture gap | Architecture lacks audit trail |

**When CWE is not available** (common with Semgrep rules): The sub-DAG classifies by keyword matching on the finding's title and rule ID (e.g., "inject" → validation, "auth" → auth, "crypto" → crypto).

**Posture calculation (severity-weighted):**

```
severity_weights = {Critical: 1.0, High: 0.7, Medium: 0.4, Low: 0.2}
max_deficit = 3.0  (calibration: 3 Critical findings = 0% posture)

weighted_deficit = sum(severity_weight for each gap in this category)
posture = max(0.0, 1.0 - (weighted_deficit / max_deficit))
```

**Why severity-weighted is defensible:** A single Critical authentication bypass (weight 1.0) damages posture more than three Low informational findings (weight 0.6 combined). This aligns with industry severity classification (CVSS).

**Edge nodes produced (4):**

| Edge Node | What It Represents | STRIDE Relevance |
|---|---|---|
| `sast.auth_posture` | How complete is authentication in code? | Spoofing, Elevation of Privilege |
| `sast.crypto_posture` | Is encryption properly implemented? | Information Disclosure, Tampering |
| `sast.validation_posture` | Are inputs validated at boundaries? | Tampering, Elevation of Privilege |
| `sast.logging_posture` | Is audit logging present? | Repudiation |

### DAST Sub-DAG: "What Does the Application Actually Look Like Running?"

**Input:** ZAP XML or Netsparker XML report

**What it does:** Determines runtime architectural reality — whether controls that may exist in code are actually ENFORCED at runtime.

**Classification:** DAST findings are categorised by their type:
- `authentication` category → reveals gaps in runtime auth enforcement
- `cryptography` / `configuration` → reveals TLS/encryption failures
- `information_disclosure` → reveals data leakage
- `injection` / `xss` → reveals runtime validation gaps

**Key distinction:** All DAST findings have higher causal strength (0.85-0.9) than SAST findings because they are RUNTIME-PROVEN, not theoretical.

**When DAST is not available:** Edge nodes are still produced (value=0.0, causal_strength=0.0, observed=False). This preserves the causal graph structure for counterfactual queries: "What WOULD risk be if DAST found issues?"

**Edge nodes produced (4):**

| Edge Node | What It Represents | STRIDE Relevance |
|---|---|---|
| `dast.runtime_auth_enforcement` | Is auth actually enforced at runtime? | Spoofing, Elevation of Privilege |
| `dast.runtime_encryption_status` | Is TLS/encryption working? | Information Disclosure, Tampering |
| `dast.exposed_attack_surface` | How much is reachable from outside? | Spoofing, DoS, Information Disclosure |
| `dast.information_leakage` | What leaks in responses? | Information Disclosure |

### Repo Sub-DAG: "What Is the Structural Design?"

**Input:** Component graph from architecture auto-detection (Docker, K8s, API specs, configs)

**What it does:** Evaluates the architectural topology itself — independent of any vulnerabilities.

**Edge nodes produced (4):**

| Edge Node | What It Represents | STRIDE Relevance |
|---|---|---|
| `repo.topology_exposure` | How much of the system is externally reachable? | Spoofing, DoS, Information Disclosure |
| `repo.data_sensitivity` | How sensitive is the data the system handles? | Information Disclosure, Tampering |
| `repo.trust_boundary_integrity` | Are boundaries properly controlled? | Spoofing, Tampering, Info Disclosure, EoP |
| `repo.defense_depth` | How many defense layers exist? | Spoofing, Tampering, DoS, EoP |

---

## Layer 4: Master DAG — Cross-Layer Reasoning

### What It Contains

The Master DAG's NetworkX graph has:
- **12 edge nodes** (4 per sub-DAG) as input layer
- **6 STRIDE posture nodes** (intermediate reasoning layer)
- **1 Overall Risk node** (final effect)
- **Cross-layer edges** (6 dependency rules between edge nodes)
- **STRIDE determination edges** (edge nodes → STRIDE posture nodes → risk)

### Cross-Layer Dependency Rules (6 Implemented)

| Trigger | Effect | Strength | Reason |
|---|---|---|---|
| SAST auth_posture ↑ | DAST runtime_auth ↑ | 0.7 | Fixing auth in code makes runtime auth work |
| SAST crypto_posture ↑ | DAST runtime_encryption ↑ | 0.6 | Implementing encryption in code activates it at runtime |
| SAST validation_posture ↑ | DAST attack_surface ↓ | 0.5 | Better validation makes endpoints less exploitable |
| Repo defense_depth ↑ | DAST attack_surface ↓ | 0.6 | Defense layers (gateway, WAF) reduce reachability |
| Repo topology_exposure ↓ | DAST attack_surface ↓ | 0.8 | Fewer public components = smaller attack surface |
| Repo trust_boundary_integrity ↑ | DAST information_leakage ↓ | 0.5 | Better boundaries reduce unintended exposure |

### Roadmap to Zero

The Master DAG iteratively computes the optimal fix sequence:

```
1. For each unfixed edge node, simulate fixing it (what_if → target value)
2. Compute cross-layer effects of each candidate fix
3. Compute STRIDE posture improvement for each
4. Select the fix with highest total impact
5. Mark it as fixed, update current state including cross-layer effects
6. Repeat until all STRIDE postures > threshold or no more improvements possible
```

Deduplication: each edge node can only be fixed once (tracked via `fixed_nodes` set).

---

## Layer 5: STRIDE — The Cream Layer

### How Threats Are Generated

For each STRIDE category, the layer:
1. Collects relevant edge node posture scores from the Master DAG
2. Computes a composite category posture (inverts exposure/leakage metrics)
3. If posture < threshold (0.85 for Low, 0.7 for Medium, 0.5 for High, 0.3 for Critical), generates a threat
4. Severity is determined by how far below threshold the posture falls
5. Confidence increases with the number of layers that corroborate the threat

### CWE Tracing (Automated)

Each generated STRIDE threat automatically traces back to specific CWE IDs from the SAST base variables:

```
STRIDE category → relevant posture types → base variables with those types → CWE IDs

Example:
  "Tampering" threat → needs crypto + validation posture
  → SAST base vars with posture_type="crypto" → CWE-311, CWE-319
  → SAST base vars with posture_type="validation" → CWE-89, CWE-79
  → Threat carries: [CWE-89, CWE-79, CWE-311, CWE-319]
```

This enables ground truth comparison against known vulnerabilities (CVEs).

### Multi-Layer Evidence

Each threat carries evidence from ALL layers that contributed:

```
StrideThreathV2:
  evidence_sast: ["Auth posture: 37%, Validation: 0%"]
  evidence_dast: ["Runtime auth: 80%"]
  evidence_repo: ["Topology exposure: 83%, Boundary integrity: 40%"]
  layers_confirming: 3  (all three layers agree this is a problem)
```

### Remediation at Three Levels

Each threat includes HOW to fix it at each architectural level:

```
remediation_architecture: "Add authentication requirement to all trust boundary crossings"
remediation_code: "Implement authentication middleware on all public-facing endpoints"  
remediation_verification: "Re-run DAST to confirm auth is enforced at runtime"
```

---

## Bidirectional Propagation

### Forward: Fix → Impact Across All Layers

```
Fix "sast.validation_posture" (0.0 → 1.0):
  Direct: SAST layer validation improves
  Cross-layer rule triggers: DAST attack_surface decreases (strength 0.5)
  STRIDE re-evaluates: Tampering posture improves, EoP posture improves
  Net: Overall risk decreases
```

### Backward: Target → What Must Be Fixed

```
Query: "What base variables must change to achieve auth_posture = 1.0?"
  → List all SAST findings with posture_type = "auth"
  → Each one is a fix candidate
  → Ordered by severity (fix Critical first = biggest posture improvement per fix)
```

---

## Implementation Summary

```
src/causal/v2/
├── __init__.py          # Module documentation
├── base.py              # ArchitecturalEdgeNode, ArchitecturalSubDAG ABC
│                          forward_propagate(), backward_query()
├── sast_subdag.py       # Severity-weighted posture, CWE + keyword classification
├── dast_subdag.py       # Runtime posture, observed/not-observed handling
├── repo_subdag.py       # Structural posture from component graph
├── master_dag.py        # 6 cross-layer rules, what_if(), roadmap_to_zero()
├── stride_layer.py      # STRIDE cream layer, CWE tracing, 3-level remediation
└── engine.py            # CausalTMv2Engine orchestrator
```

---

## Validated Results (OWASP Juice Shop)

With real Semgrep SAST (23 findings) + real ZAP DAST (10 findings) + architecture model:

- **Overall Risk:** 0.462 (Medium)
- **STRIDE Threats:** 6 (one per category)
- **Posture:** Spoofing 62%, Tampering 56%, Repudiation 67%, Info Disclosure 43%, DoS 26%, EoP 69%
- **Roadmap:** 11 steps to near-zero (no duplicates, with cross-layer effects)
- **Ground Truth Match:** 53%+ of known Juice Shop challenges identified
- **All 4 SVGs rendered:** DFD, SAST sub-graph, DAST sub-graph, Repo sub-graph, Master DAG

---

## What CausalTM IS and IS NOT

### IS:
- A STRIDE-based threat modeling tool for application ARCHITECTURE
- Consumes SAST/DAST to UNDERSTAND the design (not to fix vulnerabilities)
- Uses Federated Causal AI with severity-weighted posture and cross-layer reasoning
- Produces a sequenced remediation ROADMAP (architecture fixes first)
- Accounts for cross-layer side effects of every fix
- Generic — works on any project with SARIF + ZAP XML + repo

### IS NOT:
- A vulnerability scanner (SAST/DAST tools do that)
- A vulnerability manager (those tools track their own fixes)
- A code fixer (developers do that)
- A replacement for SAST/DAST (it consumes them, doesn't replace them)

### The Value Proposition:
> "SAST tells you what's wrong in code. DAST tells you what's wrong at runtime. CausalTM tells you what's wrong with the ARCHITECTURE — and gives you the exact sequence of design changes that eliminates all threats, accounting for the fact that fixing one thing can affect everything else."
