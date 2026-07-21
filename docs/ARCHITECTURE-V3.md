# CausalTM v3 Architecture — Frozen Design

*Frozen: July 2026. Incorporates external review feedback on causal validity, boundary-specific posture, and fusion layer.*

---

## Core Causal Claim (Revised from v2)

The causal claim is NOT: "a vulnerability causes absence of a control."

The causal claim IS:

> Each security finding provides **evidence of a control coverage gap at a specific architectural boundary**. The aggregation of boundary-level gaps **determines** the system-wide posture for that control. Posture gaps **determine** STRIDE threat existence.

**Three-level causal chain:**

```
Level 1: Evidence         → Boundary Posture       (Layer C)
Level 2: Boundary Posture → Architectural Posture  (Layer D)
Level 3: Architectural Posture → STRIDE Threat     (Layer F)
```

Key distinction from v2: findings are NOT direct causes of architectural posture. They are **observations** that support a **causal hypothesis** about control coverage at a specific boundary. Four layers of abstraction separate a raw finding from a STRIDE classification.

---

## The Stack (8 Layers)

```
┌─────────────────────────────────────────────────────────────────────┐
│  H. OUTPUT & REPORTING                                              │
│  Reports, DFD diagrams, attack paths, roadmap, what-if results      │
├─────────────────────────────────────────────────────────────────────┤
│  G. REMEDIATION PLANNER                                             │
│  Sequences fixes by cross-layer impact. Boundary-level traceability.│
│  Distinguishes: architecture fix / code fix / config fix            │
├─────────────────────────────────────────────────────────────────────┤
│  F. STRIDE THREAT LAYER (Hybrid: Rules + Causal)                    │
│  Rule-based: known STRIDE patterns (weak auth + exposed = Spoofing) │
│  Causal: posture below threshold → threat with multi-layer evidence │
├─────────────────────────────────────────────────────────────────────┤
│  E. MASTER CAUSAL DAG                                               │
│  Cross-domain reasoning. What-if. Counterfactual. Propagation.      │
│  Operates ONLY on fused posture variables from Layer D.             │
├─────────────────────────────────────────────────────────────────────┤
│  D. FUSION / INTERFACE LAYER                                        │
│  Aligns sub-DAG outputs into shared variables.                      │
│  Resolves conflicting evidence. Confidence-weighted merge.          │
│  Computes ARCHITECTURAL posture from BOUNDARY postures.             │
│  Applies worst-case-adjusted aggregation.                           │
├─────────────────────────────────────────────────────────────────────┤
│  C. FEDERATED CAUSAL SUB-DAGs                                       │
│  Each sub-DAG: evidence → boundary-specific posture (local scope)   │
│  SAST: code-level control coverage per component/boundary           │
│  DAST: runtime enforcement per endpoint/flow                        │
│  Repo: structural design properties per boundary/zone               │
├─────────────────────────────────────────────────────────────────────┤
│  B. NORMALIZATION & EVIDENCE LAYER                                  │
│  Common evidence schema. Deduplication. Metadata attachment.         │
│  Boundary assignment (file_path → component → boundary).            │
├─────────────────────────────────────────────────────────────────────┤
│  A. SOURCE ADAPTERS                                                 │
│  SARIF, ZAP XML, Terraform HCL, Docker, K8s, API specs, SBOM       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Layer A: Source Adapters

**Responsibility:** Parse tool-specific formats into raw findings.

**Supports:**
- SAST: SARIF v2.1.0 (Semgrep, CodeQL, Coverity, Bandit)
- DAST: ZAP XML, Netsparker XML, Burp
- IaC: Terraform HCL, CloudFormation, Kubernetes YAML
- Architecture: Docker Compose, OpenAPI, environment files
- Future: SBOM (CycloneDX/SPDX), cloud config, IAM policies, runtime logs

**Must NOT do:**
- No scoring
- No STRIDE mapping
- No causal inference
- No boundary assignment

---

## Layer B: Normalization & Evidence Layer

**Responsibility:** Convert all sources into one evidence schema with boundary context.

**Key v3 addition:** Each normalized finding carries a **boundary assignment** — which architectural boundary or component does this finding relate to?

**Boundary Assignment Policy:**

| Priority | Rule | Confidence Multiplier |
|---|---|---|
| P1: Direct match | finding.file_path startsWith component.source_paths[i] | 1.0 |
| P2: Pattern inference | file_path contains "routes/", "controllers/", "api/" → public process; "models/", "db/" → data_store; IaC resource type → infrastructure boundary | 0.7 |
| P3: Unresolved | Cannot determine → assign to "global/unresolved" bucket. Does NOT diffuse to all boundaries. Contributes only to global posture at reduced weight. | 0.5 |

**MVP scope:** Priority 1 only. Priority 2 for repo/IaC optionally.

**Must NOT do:**
- No architectural conclusions
- No cross-source reasoning
- No posture computation

---

## Layer C: Federated Causal Sub-DAGs

**Responsibility:** Model LOCAL cause-effect relationships within ONE domain. Produce **boundary-specific** posture estimates.

**v3 change from v2:** Sub-DAGs no longer produce global posture. They produce per-boundary posture within their domain.

### SAST Sub-DAG

**Causal claim:**

> "Multiple code-level findings of type X at boundary B provide evidence that control X has incomplete coverage at boundary B. The degree of incompleteness is proportional to the severity and count of findings."

**Posture formula (per boundary, per control category):**

```
For boundary B, control category C:
  findings_at_B_of_type_C = {f1, f2, ...}
  coverage_gap(B, C) = Σ w(severity_i) / K
  boundary_posture(B, C) = max(0, 1 - coverage_gap(B, C))

Where:
  w(Critical) = 1.0, w(High) = 0.7, w(Medium) = 0.4, w(Low) = 0.2
  K = 3.0 (calibration: 3 Critical findings = 0% posture at that boundary)
```

**Example:**
- 1 Critical SQLi in routes/search.ts → validation posture at "API boundary" reduced by 33%
- Same finding does NOT reduce validation posture at "CI/CD boundary"
- 3 Medium SQLi across API routes → validation posture at "API boundary" reduced by 40%

**Edge node output format:**
```
sast.boundary.<boundary_id>.<control_category>_posture = float [0,1]
```

### DAST Sub-DAG

**Causal claim:**

> "Runtime-confirmed findings at endpoint E provide strong evidence that a control is not enforced at that endpoint's boundary. DAST evidence has higher causal strength because it represents observed runtime behavior for tested paths."

**Causal strength:** 0.85-0.90 (vs SAST at 0.60-0.75)

**Important qualifier:** DAST provides strong runtime evidence for **tested paths**, not absolute proof for the entire system. DAST has blind spots: untested endpoints, auth-dependent paths, hidden functionality, business logic.

### Repo/IaC Sub-DAG

**Causal claim:**

> "Architectural configuration at boundary B determines the designed security properties of that boundary. IaC findings reveal gaps between intended design and secure design."

**Must NOT do (all sub-DAGs):**
- Must NOT claim knowledge beyond their domain
- SAST must NOT make runtime claims
- DAST must NOT make code-structure claims
- Repo must NOT make implementation claims
- Must NOT pretend to know everything about the full system

---

## Layer D: Fusion / Interface Layer

**Responsibility:** Aggregate boundary-specific postures from all sub-DAGs into architectural-level posture variables for the Master DAG.

**Why this layer exists:**
1. Sub-DAGs produce potentially dozens of boundary-specific values
2. Master DAG needs a manageable set of architectural posture variables
3. Multiple sub-DAGs may report on the same boundary — needs reconciliation
4. Conflicting evidence needs explicit resolution with uncertainty tracking

### Fusion Rules (Locked for MVP)

**If both sources observed and agree (within 0.3 of each other):**
```
fused_posture = weighted_average(postures, by causal_strength)
confidence = max(conf_source1, conf_source2) × 1.1  (corroboration boost, capped 1.0)
```

**If both sources observed and disagree (>0.3 apart):**
```
fused_posture = weighted_average biased toward source with:
  - higher coverage
  - higher confidence
  - stronger boundary assignment
confidence = min(conf_source1, conf_source2)
flag = "uncertain_divergence"
```

**If only one source observed:**
```
fused_posture = observed_value
confidence = observed_confidence × 0.7  (single-source penalty)
```

### Architectural Aggregation (Boundary → System)

```
arch_posture(C) = α × weighted_avg(C) + (1-α) × worst_critical(C)

Where:
  α = 0.6
  weighted_avg(C) = Σ (criticality(B) × boundary_posture(B,C)) / Σ criticality(B)
  worst_critical(C) = min(boundary_posture(B,C)) for B where B is high-criticality

High-criticality boundary = is_external_facing OR handles_sensitive_data OR is_trust_boundary_crossing
```

**Why worst-case adjustment:** Averages hide severe local risk. One critical exposed boundary (posture=0.1) can get diluted by many safe internal ones (posture=1.0). The worst-case term prevents this dilution for security-relevant boundaries.

### Criticality Formula

```
criticality(B) = 
    0.35 × is_external_facing +
    0.25 × crosses_trust_boundary +
    0.25 × handles_sensitive_data +
    0.15 × privilege_level_normalized

Range: [0, 1]
```

### Coverage (Metadata, Minimal MVP Influence)

Coverage is recorded as metadata on each sub-DAG contribution:
- SAST coverage = fraction of component source files scanned
- DAST coverage = fraction of component endpoints tested
- IaC coverage = fraction of infrastructure resources represented

> "Coverage will be recorded in MVP metadata, with only minimal or optional influence on fusion; full coverage-aware weighting will be a later enhancement."

### Output to Master DAG

```
Fused posture variables (one set, not per-boundary):
  arch.auth_posture         (confidence: float)
  arch.crypto_posture       (confidence: float)
  arch.validation_posture   (confidence: float)
  arch.logging_posture      (confidence: float)
  arch.topology_exposure    (confidence: float)
  arch.boundary_integrity   (confidence: float)
  arch.defense_depth        (confidence: float)
  arch.data_sensitivity     (confidence: float)
```

**Must NOT do:**
- Do not introduce new causal semantics
- Do not emit threats directly
- Do not consume raw findings (only sub-DAG outputs)

---

## Layer E: Master Causal DAG

**Responsibility:** Cross-domain reasoning over fused architectural posture variables.

**Operates on:** Fused posture variables from Layer D only (NOT raw findings, NOT boundary-specific values).

**Causal claim (v3, with assumptions):**

> "Architectural posture variables have causal relationships: improving code-level auth posture can improve runtime auth enforcement, assuming the updated code is deployed and exercised in the runtime path. These cross-domain dependencies are modelable and predictable."

### Cross-Layer Dependency Rules

| # | Trigger | Effect | Strength | Assumptions |
|---|---|---|---|---|
| 1 | Code auth improves | Runtime auth improves | 0.70 | Code deployed via CI/CD; improved code in active runtime path |
| 2 | Code crypto improves | Runtime crypto improves | 0.60 | Crypto code is reachable at runtime |
| 3 | Code validation improves | Attack surface decreases | 0.50 | Validation code is on input processing path |
| 4 | Defense-in-depth added | Attack surface decreases | 0.60 | Architectural change is deployed |
| 5 | Topology exposure decreases | Attack surface decreases | 0.80 | Network/infra change is applied |
| 6 | Boundary integrity improves | Data leakage decreases | 0.50 | Boundary enforcement is active at runtime |

**Why these are causal (not correlational):** The relationship "code auth improves → runtime auth improves" satisfies the interventional criterion: if you DO improve code auth (intervention), runtime auth WILL improve (predicted outcome), given the assumptions hold. This is mechanism-based prediction, not observed correlation.

**Supports:**
- What-if: "What happens to overall risk if we fix validation?"
- Counterfactual: "Would this threat exist if crypto posture were 0.9?"
- Roadmap: "What's the optimal fix sequence considering cross-layer effects?"

**Must NOT do:**
- Do not consume raw findings directly
- Do not become source-specific
- Do not replace the sub-DAGs' local reasoning

---

## Layer F: STRIDE Threat Layer (Hybrid)

**Responsibility:** Classify architectural threats using BOTH rule-based pattern matching AND posture-derived assessment.

### Rule-Based Component (Known Patterns)

```
IF arch.auth_posture < 0.7 AND component.is_public_facing
   → Spoofing threat (High confidence, pattern-matched)

IF arch.validation_posture < 0.5 AND flow.crosses_trust_boundary
   → Tampering threat (High confidence, pattern-matched)

IF arch.crypto_posture < 0.6 AND flow.data_sensitivity == "pii"
   → Information Disclosure threat (High confidence, pattern-matched)

IF arch.logging_posture < 0.5 AND component.handles_sensitive_operations
   → Repudiation threat (pattern-matched)
```

### Posture-Derived Component (Threshold-Based)

```
Severity from posture level:
  posture < 0.30 → Critical
  posture < 0.50 → High  
  posture < 0.70 → Medium
  posture < 0.85 → Low
```

### Each Threat Carries

- Category (Spoofing/Tampering/Repudiation/InfoDisc/DoS/EoP)
- Severity (from posture level or pattern rule)
- Confidence (propagated from fusion layer)
- Multi-layer evidence (which sub-DAGs contribute, which boundaries)
- Classification method (rule-matched vs posture-derived)
- Traced CWEs (back through the full chain for validation)
- Remediation at 3 levels (architecture / code / config)

**Must NOT do:**
- Do not use STRIDE as a scoring engine
- Do not bypass the causal model with direct CWE→STRIDE mapping
- Do not generate threats without evidence traceability

---

## Layer G: Remediation Planner

**Responsibility:** Sequence fixes by cross-layer impact with boundary-level traceability.

**Algorithm:**
1. Find fused posture variable with highest deficit × criticality
2. Simulate fixing it → propagate cross-layer effects (Layer E rules, respecting assumptions)
3. Record step with direct + propagated improvements
4. Trace back to WHICH boundaries need fixing and WHICH findings to address
5. Mark fixed; repeat until deficit < 0.05 everywhere

**v3 addition:** Each step traces to specific boundaries and specific findings. Not "improve validation globally" but "improve validation at API external boundary — fix CWE-89 in routes/search.ts and routes/login.ts."

**Must NOT do:**
- Do not invent new findings
- Do not overwrite evidence provenance
- Do not recommend fixes without traceability

---

## Layer H: Output & Reporting

**Responsibility:** Present results with full evidence trails and confidence indicators.

- STRIDE threat report with evidence chains (finding → boundary → posture → threat)
- DFD with boundary-specific posture annotations
- Attack path visualization (graph traversal)
- Causal graph views (sub-DAGs, master DAG)
- What-if results with before/after states
- Remediation roadmap with sequencing rationale and boundary traceability
- Confidence indicators throughout (no hidden aggregation)

---

## Separation of Concerns (Design Principle)

| Concept | Definition | Lives In | NOT The Same As |
|---|---|---|---|
| Evidence | A raw finding/observation from a tool | Layers A-B | Posture |
| Boundary Posture | Control coverage state at one boundary | Layer C | Architecture posture |
| Architecture Posture | System-wide control state (fused, aggregated) | Layers D-E | Threat |
| Threat | STRIDE classification from posture + context | Layer F | Evidence |
| Causal Effect | Predicted change after intervention | Layer E | Correlation |
| Confidence | Certainty level, propagated through layers | All layers | Truth |

These concepts must remain separate in the data model. Do not collapse them prematurely.

---

## Changes from v2 → v3

| Aspect | v2 | v3 |
|---|---|---|
| Causal claim | "Findings CAUSE posture" | "Findings provide EVIDENCE of control coverage gaps at boundaries" |
| Posture granularity | Global (per control category) | Boundary-specific → fused to architectural |
| Finding → STRIDE path | 2 layers of abstraction | 4 layers of abstraction |
| Multi-source reconciliation | Implicit in Master DAG | Explicit Fusion Layer (D) with conflict resolution |
| STRIDE approach | Pure threshold | Hybrid (rules for known patterns + thresholds for posture-derived) |
| Boundary assignment | Not explicit | Formal policy with priority levels |
| Confidence tracking | Not present | Propagated through all layers as metadata |
| Aggregation | Simple weighted average | Worst-case-adjusted (α=0.6) for security-relevant boundaries |
| Cross-layer rules | Unconditional | Carry explicit assumptions/qualifiers |
| Remediation traceability | "Fix validation" | "Fix validation at API boundary — specifically CWE-89 in routes/search.ts" |

---

## MVP Scope

### Implemented (All Complete)
- Priority 1 boundary matching (direct file_path → source_paths) ✓
- Boundary-specific posture (same formula, scoped per boundary) ✓
- Fusion layer (weighted average + single-source penalty + corroboration boost + conflict detection) ✓
- Worst-case-adjusted architectural aggregation (α=0.6) ✓
- Hybrid STRIDE (5 rule-based patterns + posture-derived fallback) ✓
- Roadmap with boundary-level traceability (4 steps for Juice Shop) ✓
- DAST sub-DAG (runtime posture, causal strength 0.87) ✓
- Repo sub-DAG (structural posture from component graph) ✓
- Report renderer (polished markdown with evidence chains) ✓
- What-if analysis with cross-layer propagation ✓
- Attack path graph traversal ✓
- Confidence tracking and uncertainty flagging ✓

### Out of Scope (Future Work)
- Complex Bayesian conflict reasoning
- Temporal modeling (posture evolution over time)
- Multi-hop boundary inference
- Automated trust boundary discovery from every artifact
- Full coverage-aware fusion weighting (coverage recorded but not yet weighted)
- Supply chain sub-DAG (SBOM/SCA as 4th sub-DAG)

---

## Evaluation Results (23 SAST + 10 DAST, Juice Shop)

### v2 vs v3 Comparison (Same Inputs)

| Metric | v2 | v3 |
|---|---|---|
| Overall Risk | 0.431 | 0.404 |
| Threats | 6 | 6 (5 rule-matched + 1 posture-derived) |
| Roadmap Steps | 8 | 4 |
| Sources | 2 (SAST+DAST) | 3 (SAST+DAST+Repo) |
| Boundaries Assessed | 1 (global) | 4 |
| Uncertain Divergences | N/A | 5 flagged |
| Classification | Threshold only | Hybrid |

### Key Finding
DoS posture: v2 = 0.353 (Critical), v3 = 0.541 (Medium). Same findings, but v3's boundary-specific aggregation prevents localized weaknesses from catastrophically reducing system-wide posture.

---

## Research Questions

1. **RQ1:** Does boundary-specific posture improve threat localization and remediation prioritization over global posture?
   - **Evidence:** Yes. v3 produces 50% fewer roadmap steps (4 vs 8), boundary-targeted fixes, and avoids DoS over-generalization (0.353→0.541).
2. **RQ2:** Does multi-source fusion with confidence tracking reduce false generalization compared to single-source analysis?
   - **Evidence:** Yes. 5 uncertain divergences flagged where sources disagree. Repo sub-DAG detects structural gaps invisible to SAST/DAST.
3. **RQ3:** Does worst-case-adjusted aggregation produce better risk prioritization than simple averaging?
   - **Evidence:** Yes. Validation worst-case at tb-internal (0.376) correctly dominates over safe boundaries, preventing dilution.
4. **RQ4:** Does cross-layer propagation with deployment assumptions produce actionable remediation sequences?
   - **Evidence:** Partially demonstrated. What-if shows validation fix reduces risk by 45%. Cross-layer propagation rules exist but were not triggered in this evaluation (all fixes were direct).

---

## Gaps / Future Work

1. Boundary auto-detection heuristics (beyond P1 file_path matching)
2. Empirical calibration of K=3.0 and α=0.6 constants via expert panel
3. Full coverage-aware fusion weighting (coverage is recorded but not used in weighting)
4. Formal confidence propagation model (currently heuristic)
5. Temporal dynamics (posture evolution over time, incremental analysis)
6. Empirical validation of cross-layer rule strengths (currently expert-specified)
7. Supply chain sub-DAG (SBOM/SCA as 4th sub-DAG)
8. Incremental/differential analysis for CI/CD gates
9. Enterprise-scale validation (multiple diverse applications)
10. Formal do-calculus for interventional queries (currently graph-based approximation)
