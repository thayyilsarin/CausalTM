# A Federated Structural Causal Model for Automated STRIDE Threat Modeling from Multi-Source Security Intelligence

**International Conference on Advances in Machine Intelligence and Cybersecurity Technologies (AMICT) 2026**

---

## Abstract

Threat modeling remains largely manual despite the availability of rich automated security data from static and dynamic analysis tools. This paper introduces CausalTM, a framework that automates STRIDE-based architectural threat modeling through a Federated Structural Causal Model (FSCM). The system employs an eight-layer architecture where source adapters, normalization, and boundary assignment feed into domain-specific causal sub-graphs that compute boundary-specific security posture — treating findings as evidence of control coverage gaps at specific architectural boundaries rather than as direct causes of global weakness. A fusion layer reconciles multi-source evidence with confidence tracking and worst-case-adjusted aggregation before a master DAG applies cross-layer dependency rules with explicit deployment assumptions. A hybrid STRIDE evaluation layer combines rule-based patterns (posture weakness + architectural context) with posture-derived thresholds to classify threats with full evidence traceability. We evaluate two versions of the prototype against OWASP Juice Shop: (1) a global-posture approach (v2) and (2) a boundary-specific approach (v3) using the same inputs. Results demonstrate that boundary-specific posture improves threat localization (identifying WHERE weaknesses exist, not just WHAT), provides 4-layer traceability (vs 2-layer), adds confidence tracking with single-source penalties, and enables risk-averse aggregation that prevents dilution of severe local risk. Both versions identify threats across all applicable STRIDE categories, but v3 produces contextually grounded threats (rule-matched with architectural exposure requirements) while v2 produces threshold-only classifications.

**Keywords:** causal inference, STRIDE, federated structural causal model, threat modeling, automated security analysis, boundary-specific security posture, attack path analysis, counterfactual reasoning, multi-source evidence fusion

---

## I. Introduction

Software teams that deploy changes multiple times daily cannot wait weeks for a threat model. Industry estimates place the cost of a single manual threat modeling exercise between fifteen and fifty thousand US dollars, requiring specialised expertise that most organisations lack [1]. The consequences of forgoing the practice are documented — the average data breach now costs USD 4.88 million and takes 277 days to identify and contain [2].

The STRIDE framework, developed at Microsoft in 1999, remains the prevailing method for classifying application-level threats [3]. Its strength lies in architectural focus: by examining system topology, data flows, and trust boundaries against six threat categories — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege — an analyst identifies threats that exist by design, regardless of whether any specific vulnerability has been discovered [4]. The weakness is that both the diagram construction and the threat analysis remain human-driven activities [5].

Modern development pipelines produce considerable security intelligence automatically. Static analysis tools report code-level weaknesses in standardised formats (SARIF). Dynamic analysis tools confirm exploitability against running applications. Infrastructure-as-Code (IaC) configurations document system architecture in machine-readable form. The gap is not in data availability but in the absence of a reasoning layer that can synthesise these sources into architectural understanding suitable for STRIDE analysis.

Machine learning has been proposed for vulnerability prioritisation [6], but these approaches count and rank individual vulnerabilities rather than reasoning about architecture. They cannot answer the question STRIDE actually asks: "Given this design, what can go wrong?" — a question about structure, not about individual bugs. They require historical training data [7], cannot answer interventional questions ("what happens if we fix X?") [8], and degrade as patterns shift [9].

This paper proposes a fundamentally different approach. Rather than counting vulnerabilities, we extract architectural security posture from each data source. Rather than applying rules to individual components, we evaluate the complete architecture against STRIDE as a holistic assessment. Rather than producing a flat threat list, we generate a sequenced remediation roadmap that accounts for cross-layer side effects. The framework, CausalTM, employs an eight-layer Federated Structural Causal Model:

1. **Source adapters** parse tool-specific outputs (SARIF, ZAP XML, Terraform HCL).
2. **Normalization & boundary assignment** converts findings into a common evidence schema and assigns each to a specific architectural boundary.
3. **Federated causal sub-DAGs** compute boundary-specific posture per control category (authentication, cryptography, validation, logging) — treating findings as evidence of control coverage gaps, not proof of absence.
4. **A fusion layer** reconciles multi-source evidence with confidence-weighted merge, conflict resolution, and worst-case-adjusted aggregation (preventing dilution of severe local risk).
5. **A master DAG** applies cross-layer dependency rules with explicit deployment assumptions, supporting what-if and counterfactual queries.
6. **A hybrid STRIDE evaluation layer** combines rule-based patterns (posture + architectural context) with posture-derived thresholds.
7. **A remediation planner** sequences fixes by cross-layer impact with boundary-level traceability.
8. **Attack path analysis and reporting** produce concrete multi-hop paths through the component graph and structured outputs with full evidence chains.

The contributions of this work are:

- A boundary-specific posture architecture where findings are treated as evidence of control coverage gaps at specific architectural boundaries — not as direct causes of global weakness. This avoids false generalization of localized weaknesses to the entire system.
- A fusion layer that reconciles multi-source evidence with confidence tracking, conflict resolution (corroboration/divergence/single-source), and worst-case-adjusted aggregation that prevents dilution of severe risk at critical boundaries.
- Cross-layer dependency rules with explicit deployment assumptions that predict how fixing an issue in one layer (code, runtime, architecture) affects posture in other layers.
- A hybrid STRIDE classification that requires both posture weakness AND architectural exposure (public-facing components, trust boundary crossings, sensitive data flows) — producing contextually grounded threats rather than threshold-only classifications.
- A comparative evaluation (v2 global-posture vs v3 boundary-specific) on OWASP Juice Shop demonstrating improved threat localization, traceability, and confidence handling.


## II. Related Work

### A. Automated Threat Modeling Tools

Tools such as Microsoft's Threat Modeling Tool, OWASP Threat Dragon, and PyTM [10] reduce the mechanical burden of threat enumeration once a system model exists. However, every tool in this category requires a human analyst to construct the Data Flow Diagram manually. No existing tool extracts architecture directly from source code repositories or deployment configurations [5]. Tuma et al. [4] confirm in their systematic literature review that this architecture extraction step remains the principal unsolved bottleneck. IriusRisk and ThreatModeler offer library-based automation but still require manual component selection and relationship definition.

Recent work on code-to-DFD extraction [11] demonstrates feasibility for simple applications but struggles with microservice architectures, Infrastructure-as-Code deployments, and polyglot repositories where architecture is distributed across multiple configuration formats (Docker Compose, Kubernetes YAML, Terraform HCL).

### B. Vulnerability Prioritisation via Machine Learning

The Exploit Prediction Scoring System (EPSS) applies logistic regression to historical exploitation data [6]. Other researchers employ random forests and deep learning for severity prediction [12]. These systems rank vulnerabilities by exploitation likelihood, but they operate at Pearl's associational level [8] — they observe correlations between features and outcomes without modelling the generative mechanism.

Critically, these approaches cannot perform the architectural reasoning that STRIDE requires. STRIDE asks whether a *design* permits spoofing, regardless of whether any spoofing vulnerability has been found. ML vulnerability rankers answer a different question: "given this bug exists, how likely is exploitation?" The distinction is between reasoning about individual bugs (ML) versus reasoning about architectural adequacy (STRIDE).

Furthermore, ML approaches require historical training data that may not exist for novel architectures [7], cannot answer interventional questions ("what happens if we add authentication here?") without retraining [8], and degrade as adversarial patterns shift over time [9].

### C. Causal Inference in Cybersecurity

Pearl's causal hierarchy [8] distinguishes three levels of inference: (1) associational — observing correlations, (2) interventional — predicting the effect of actions via the *do*-operator, and (3) counterfactual — reasoning about what would have happened under different conditions. Traditional vulnerability scoring operates at level 1. Our framework operates at levels 2 and 3.

Recent work applies causal methods to intrusion detection [13], incident root cause analysis [14], and network attack graph analysis [15]. MulVAL [16] uses logic-based network vulnerability analysis with attack graphs but focuses on network-level exploits rather than application-level architectural threats. No published research applies causal inference to application-level STRIDE threat modeling — the present work fills this gap by using causal sub-graphs to represent architectural posture and a master DAG for cross-layer interventional reasoning.

### D. Attack Graph Analysis

Attack graphs enumerate possible attack paths through a system [16][17]. Traditional approaches (MulVAL, NetSPA) construct graphs from network vulnerability scans and firewall rules. These operate at the network layer and cannot reason about application-level data flows, trust boundaries, or business logic.

Our approach differs in three ways: (1) we construct attack paths from the application's Data Flow Diagram rather than network topology; (2) we score paths by architectural properties (encryption, authentication, boundary crossings) rather than CVE exploitability; and (3) paths are integrated with the causal model so that counterfactual queries ("which path is eliminated if we add encryption here?") are answerable.

### E. Structural Causal Models and Modularity

Schölkopf et al. [18] argue that independent causal mechanisms can be combined without mutual interference — a theoretical result that supports federated architectures where sub-models are developed independently. However, in security, fixing code *does* affect what is observable at runtime, violating strict mechanism independence. We extend beyond full independence by introducing explicit cross-layer dependency rules that model these predictable interactions, preserving the benefits of modularity while acknowledging inter-layer coupling.


## III. Proposed Architecture

### A. Design Philosophy: Posture, Not Vulnerability Counts

Traditional security tools count vulnerabilities: "you have 23 findings." CausalTM instead asks: "what is the state of your security controls?" A system with 23 low-severity findings in well-defended areas may be architecturally safer than one with 3 critical findings at unprotected trust boundaries. By computing *posture* — the degree to which security controls are implemented and effective — we align the analysis with what STRIDE actually evaluates: architectural adequacy.

The fundamental causal claim is:

> Individual vulnerabilities (base variables) **cause** architectural security posture (edge nodes), which **determines** STRIDE threat existence (final assessment).

This three-level causal chain distinguishes CausalTM from aggregation engines that merely sum findings.

### B. Eight-Layer Architecture Overview

Fig. 1 illustrates the complete architecture. Information flows upward from raw inputs through increasingly abstract reasoning layers.

```
┌─────────────────────────────────────────────────────────────────────┐
│  H. OUTPUT & REPORTING                                              │
│  Reports, DFD diagrams, attack paths, roadmap, what-if results      │
├─────────────────────────────────────────────────────────────────────┤
│  G. REMEDIATION PLANNER                                             │
│  Sequences fixes by cross-layer impact. Boundary-level traceability.│
├─────────────────────────────────────────────────────────────────────┤
│  F. STRIDE THREAT LAYER (Hybrid: Rules + Posture-Derived)           │
│  Rule-based: posture + architectural context (5 patterns)           │
│  Posture-derived: threshold fallback for remaining categories       │
├─────────────────────────────────────────────────────────────────────┤
│  E. MASTER CAUSAL DAG                                               │
│  Cross-domain reasoning. What-if. Counterfactual. Propagation.      │
│  Operates ONLY on fused posture variables from Layer D.             │
├─────────────────────────────────────────────────────────────────────┤
│  D. FUSION / INTERFACE LAYER                                        │
│  Resolves multi-source conflicts. Confidence-weighted merge.        │
│  Worst-case-adjusted aggregation (α=0.6). Flags divergences.        │
├─────────────────────────────────────────────────────────────────────┤
│  C. FEDERATED CAUSAL SUB-DAGs                                       │
│  SAST: code-level control coverage per boundary                     │
│  DAST: runtime enforcement per boundary (higher causal strength)    │
│  Repo: structural design properties per boundary                    │
├─────────────────────────────────────────────────────────────────────┤
│  B. NORMALIZATION & BOUNDARY ASSIGNMENT                             │
│  Common evidence schema. P1 file_path matching → boundary.          │
│  Control category classification (CWE or keyword).                  │
├─────────────────────────────────────────────────────────────────────┤
│  A. SOURCE ADAPTERS                                                 │
│  SARIF v2.1.0 │ ZAP XML │ Terraform HCL │ Component Graph          │
└─────────────────────────────────────────────────────────────────────┘
```
**Fig. 1.** CausalTM eight-layer Federated Structural Causal Model architecture.

### C. Sub-DAGs: Domain-Specific Posture Extraction

Each sub-DAG is a self-contained structural causal model that transforms raw findings into four severity-weighted posture scores (edge nodes). The edge nodes represent the *effect* of base variables (individual findings) on the architectural state of specific security controls.

**SAST Sub-DAG** answers: "What security controls exist in the code?" Findings are classified by CWE identifier into four posture categories: authentication, cryptography, input validation, and audit logging. When CWE identifiers are unavailable (common with pattern-based tools), keyword analysis of rule titles and file paths provides classification. For IaC findings (Terraform, CloudFormation), specialised keyword sets detect infrastructure-specific security controls (security groups, encryption settings, IAM policies, WAF configuration).

**DAST Sub-DAG** answers: "Are controls actually enforced at runtime?" DAST findings carry higher causal strength (0.85–0.90) than SAST findings because they represent proven runtime behaviour rather than static code patterns. When DAST has not been performed, edge nodes exist with zero values and zero causal strength — preserving graph structure for counterfactual completeness while contributing nothing to current risk assessment.

**Repo Sub-DAG** answers: "What is the structural design?" Architecture is extracted from deployment configurations (Docker, Kubernetes, Terraform), API specifications, environment files, and code structure. Posture scores capture: topology exposure (public-facing surface area), data sensitivity (credential and PII handling), trust boundary integrity (enforcement at boundaries), and defense-in-depth (layered controls).

### D. Master DAG: Cross-Layer Reasoning

The master DAG receives 12 edge nodes (4 per sub-DAG), constructs 6 STRIDE category posture nodes as weighted combinations of relevant edge nodes, and produces 1 overall risk score. The key innovation is 6 cross-layer dependency rules (Table I) that model how interventions in one layer predict effects in others.

**TABLE I**
CROSS-LAYER DEPENDENCY RULES IN THE MASTER DAG

| # | Trigger Condition | Predicted Effect | Strength |
|---|---|---|---|
| 1 | Code auth posture improves (SAST) | Runtime auth posture improves (DAST) | 0.70 |
| 2 | Code crypto posture improves (SAST) | Runtime encryption posture improves (DAST) | 0.60 |
| 3 | Code validation posture improves (SAST) | Attack surface decreases (Repo) | 0.50 |
| 4 | Architecture adds defense-in-depth (Repo) | Attack surface decreases (Repo) | 0.60 |
| 5 | Topology exposure decreases (Repo) | Attack surface decreases (Repo) | 0.80 |
| 6 | Boundary integrity improves (Repo) | Information leakage risk decreases (DAST) | 0.50 |

These rules enable the system to predict: "If you fix input validation in code (SAST layer), the attack surface at runtime (DAST layer) will also decrease — you get two improvements from one fix." This cross-layer propagation is what makes the model *causal* rather than merely associational.

### E. STRIDE Evaluation Layer

STRIDE sits above the master DAG as a "cream layer" that evaluates posture scores against threshold criteria for each of the six categories. A threat is generated when posture falls below the threshold:

- Posture < 0.85: Low severity threat
- Posture < 0.70: Medium severity threat
- Posture < 0.50: High severity threat
- Posture < 0.30: Critical severity threat

Each generated threat carries: (1) multi-layer evidence documenting what each sub-DAG contributes; (2) corroboration count indicating how many independent layers agree the threat exists; (3) traced CWE identifiers automatically mapped from contributing base variables; and (4) three-level remediation guidance (architecture fix, code fix, runtime verification).

### F. Attack Path Graph Traversal

Beyond per-category threat identification, CausalTM performs graph-based attack path analysis directly on the component graph (DFD). The algorithm:

1. **Builds a directed adjacency graph** from the component graph's data flows.
2. **Identifies entry points**: external entities and public-facing components.
3. **Identifies high-value targets**: data stores containing sensitive data.
4. **Performs depth-first search** from each entry point to each target, recording all paths up to a configurable maximum depth.
5. **Scores each path** using a composite formula (detailed in Section IV-C).

This produces concrete attack narratives such as "Internet User → ALB → ECS Frontend → Backend API → DynamoDB (PII)" rather than abstract threat descriptions, enabling security teams to prioritise defenses at architectural choke points.

### G. Remediation Roadmap

The system iteratively identifies the single fix with the highest cross-layer impact, applies it (including propagated effects via Table I rules), marks it complete, and repeats until no further meaningful improvement is achievable. This produces a sequenced roadmap where each step builds on the previous state — accounting for the reality that fixing one thing changes the landscape for everything else. The roadmap answers: "In what order should we fix things to reach zero risk with minimum effort?"


## IV. Implementation

### A. Technology Stack

The prototype is implemented in Python 3.11 using NetworkX [19] for graph operations, Pydantic v2 for data validation and schema enforcement, and Graphviz for diagram rendering. The system is deployed via GitHub Actions CI/CD pipelines that execute the full analysis automatically on each commit.

SAST findings are ingested via a SARIF v2.1.0 parser compatible with Semgrep, CodeQL, Coverity, and Bandit. DAST findings are ingested via parsers for OWASP ZAP XML and Netsparker XML formats. Architecture extraction supports Docker Compose, Kubernetes manifests, Terraform HCL, OpenAPI specifications, and environment configuration files.

### B. Posture Computation: The Structural Equation

The core posture computation is a structural equation in the causal sense — it defines a deterministic functional relationship between causes (findings) and effect (posture state):

```
P_C := max(0, 1 - (1/K) · Σᵢ∈G_C w(sᵢ))                    (1)
```

where:
- *P_C* = posture for security control category *C* ∈ {auth, crypto, validation, logging}
- *G_C* = set of base variables (findings) classified into category *C*
- *w(s_i)* = severity weight of finding *i* according to Table II
- *K* = 3.0 (calibration constant)

**TABLE II**
SEVERITY WEIGHTS AND CALIBRATION

| Severity Level | Weight *w(s)* | Interpretation |
|---|---|---|
| Critical | 1.0 | Complete control failure at boundary |
| High | 0.7 | Significant control weakness |
| Medium | 0.4 | Partial control gap |
| Low | 0.2 | Minor deficiency |

The calibration constant *K* = 3.0 is chosen such that three Critical findings (total weight 3.0) bring posture to zero — representing complete architectural failure for that control. This makes the formula interpretable: one Critical authentication bypass (*w* = 1.0) reduces auth posture by 33%, which is more damaging than three Medium findings (total *w* = 1.2, reducing posture by 40%) combined — reflecting security reality where a single critical bypass negates multiple partial controls.

**Properties of Equation (1):**
- Monotonically decreasing (more/worse findings → lower posture)
- Bounded in [0, 1]
- Severity-sensitive (Critical dominates Low)
- Interpretable: "posture = 0.37 means 63% of the calibrated maximum deficit is present"

### C. CWE-to-Posture Classification

Findings are classified into posture categories using a two-stage process. When CWE identifiers are available in the SARIF output, direct mapping is applied:

**TABLE III**
CWE-TO-POSTURE CATEGORY MAPPING (REPRESENTATIVE SUBSET)

| Posture Category | CWE Identifiers | Example Weakness |
|---|---|---|
| Authentication | CWE-287, CWE-306, CWE-862, CWE-863, CWE-798, CWE-352, CWE-522 | Missing auth, hardcoded credentials, CSRF |
| Cryptography | CWE-311, CWE-319, CWE-327, CWE-328, CWE-330, CWE-347 | Missing encryption, broken crypto, weak hash |
| Input Validation | CWE-89, CWE-79, CWE-78, CWE-22, CWE-20, CWE-502, CWE-94, CWE-917 | SQLi, XSS, path traversal, deserialization |
| Audit Logging | CWE-778, CWE-532, CWE-209 | Insufficient logging, sensitive data in logs |

When CWE identifiers are unavailable — common with Semgrep pattern-based rules and IaC scanners — keyword analysis of the finding's title, rule identifier, and file path provides fallback classification. For Infrastructure-as-Code findings specifically, the system detects IaC context (`.tf` file paths, `terraform.*` rule IDs) and applies specialised keyword matching:

| IaC Pattern | Posture Category | Example |
|---|---|---|
| Open security groups, permissive IAM, `0.0.0.0/0` | Authentication | `terraform.aws.security.security-group-open-ingress` |
| Missing encryption, no KMS, cleartext | Cryptography | `terraform.aws.security.missing-encryption-at-rest` |
| Missing WAF, no rate limiting | Input Validation | Missing web application firewall |
| Missing CloudTrail, no access logging | Audit Logging | `terraform.aws.security.missing-cloudtrail` |

### D. Attack Path Scoring Formula

Each attack path discovered by the graph traversal algorithm (Section III-F) is scored using a composite exploitability formula:

```
S(path) = (α · B_norm + β · E_norm + γ · A_norm + δ · D_max) · L_factor    (2)
```

where:
- *B_norm* = boundary_crossings / hops (normalised trust boundary violations)
- *E_norm* = unencrypted_hops / hops (normalised encryption gaps)
- *A_norm* = unauthenticated_hops / hops (normalised authentication gaps)
- *D_max* = max sensitivity weight across all flows in the path
- *L_factor* = 1 / √(hops) (shorter paths are more exploitable)
- *α* = 0.30, *β* = 0.25, *γ* = 0.25, *δ* = 0.20 (empirically assigned)

Data sensitivity weights used in *D_max*:

| Sensitivity Label | Weight | Rationale |
|---|---|---|
| credentials, secret | 1.0 | Direct authentication material |
| pii | 0.9 | Regulated personal data |
| financial | 0.8 | Monetary impact |
| confidential | 0.7 | Business-sensitive |
| internal | 0.3 | Low-sensitivity internal data |
| public | 0.1 | No confidentiality requirement |

### E. Cross-Layer Propagation

When a fix is applied to an edge node, the master DAG propagates effects to connected nodes using the dependency rules from Table I. For each rule *r* with trigger condition matching the fixed node:

```
Δ_effect = (new_value - old_value) · strength(r)              (3)
```

This propagation is applied iteratively during roadmap generation. The roadmap algorithm:
1. Identify the edge node with highest deficit (1.0 - value) weighted by its STRIDE impact.
2. Simulate fixing it to 1.0 (full posture).
3. Propagate cross-layer effects using Equation (3).
4. Record the step with its direct and cross-layer improvements.
5. Mark the node as fixed; repeat from step 1.
6. Terminate when no remaining node has deficit > 0.05.

### F. STRIDE Posture Aggregation

Each STRIDE category's posture is computed as a weighted combination of relevant edge nodes from the master DAG. The mapping from edge nodes to STRIDE categories reflects which security controls defend against which threat types:

| STRIDE Category | Contributing Edge Nodes | Weights |
|---|---|---|
| Spoofing | SAST auth, DAST auth, Repo boundary integrity | 0.4, 0.35, 0.25 |
| Tampering | SAST validation, DAST validation, Repo defense-in-depth | 0.35, 0.35, 0.30 |
| Repudiation | SAST logging, DAST logging, Repo topology | 0.5, 0.3, 0.2 |
| Information Disclosure | SAST crypto, DAST crypto, Repo data sensitivity | 0.35, 0.35, 0.30 |
| Denial of Service | SAST validation, Repo topology exposure, Repo defense | 0.3, 0.4, 0.3 |
| Elevation of Privilege | SAST auth, SAST validation, DAST auth | 0.35, 0.30, 0.35 |


## V. Evaluation

We evaluate CausalTM against two distinct targets to demonstrate generalisability across application types: (1) a deliberately vulnerable web application with known ground truth, and (2) a production-style AWS infrastructure deployment using Infrastructure-as-Code.

### A. Evaluation Target 1: OWASP Juice Shop

OWASP Juice Shop [20] is a deliberately vulnerable web application containing over one hundred documented security challenges mapped to vulnerability types, providing ground truth for comparison. Its architecture comprises a Node.js/Express REST API, Angular frontend, SQLite database, and static file server — representative of modern single-page applications.

### B. Evaluation Target 2: AWS ECS Terraform Deployment

The second target is a full-stack AWS deployment defined in Terraform: Application Load Balancer (ALB), two ECS Fargate services (React frontend, Node.js backend), DynamoDB, S3, ECR, and a CodePipeline CI/CD pipeline. This evaluates the system's ability to model cloud-native infrastructure and detect IaC security misconfigurations.

### C. Methodology

**Juice Shop evaluation** uses three real input sources processed by the v3 engine (8-layer architecture with boundary-specific posture):
1. **Architecture:** Modeled from actual application structure — 6 components, 5 data flows, 3 trust boundaries
2. **SAST:** Semgrep scan with `p/javascript` and `p/nodejs` rulesets producing 23 findings (7 High, 16 Medium) across 7 unique CWE types
3. **DAST:** OWASP ZAP baseline scan against a live Docker container producing 10 findings (2 Medium, 5 Low, 3 Informational)

Additionally, the v3 Repo sub-DAG derives structural posture directly from the component graph (no external findings needed), providing a third assessment source alongside SAST and DAST.

**AWS ECS evaluation** uses:
1. **Architecture:** Modeled from Terraform modules — 9 components, 8 data flows, 3 trust boundaries (external, DMZ, internal)
2. **SAST:** Semgrep scan with `p/terraform` ruleset against IaC files
3. **DAST:** Not applicable (no live deployment in CI)

Both evaluations run end-to-end in GitHub Actions CI pipelines, producing reports, diagrams, and evaluation metrics as downloadable artifacts.

### D. Results: Juice Shop (Canonical v3 Evaluation)

**TABLE IV**
CAUSTALTM v3 ENGINE OUTPUT — OWASP JUICE SHOP (23 SAST + 10 DAST)

| Metric | Result |
|---|---|
| Overall risk score | 0.404 (Medium) |
| STRIDE threats identified | 6 (5 rule-matched + 1 posture-derived) |
| Evidence ingested | 33 findings (23 SAST + 10 DAST) |
| Boundaries assessed | 4 (tb-internal, tb-dmz, tb-internet, global/unresolved) |
| Uncertain divergences | 5 (flagged, not silently resolved) |
| Sources contributing | 3 (SAST + DAST + Repo structural) |
| Remediation roadmap steps | 4 (boundary-targeted) |
| Average confidence | 68% |
| Analysis execution time | < 2 seconds |

**TABLE V**
STRIDE POSTURE PER CATEGORY — JUICE SHOP (v3)

| STRIDE Category | Posture Score | Threat Severity | Classification Method |
|---|---|---|---|
| Denial of Service | 54.1% | Medium | Rule-matched (validation + public-facing) |
| Elevation of Privilege | 55.5% | Medium | Rule-matched (auth + validation + crossing) |
| Tampering | 57.1% | Medium | Rule-matched (validation + trust crossing) |
| Information Disclosure | 59.0% | Medium | Rule-matched (crypto + sensitive data) |
| Spoofing | 61.3% | Medium | Rule-matched (auth + unauthenticated public) |
| Repudiation | 70.5% | Low | Posture-derived (no rule pattern matches) |

**Fused Architectural Postures (from Fusion Layer D):**

| Control Category | Posture | Confidence | Worst Critical Boundary |
|---|---|---|---|
| Validation | 52.1% | 59% | 37.6% at tb-internal |
| Auth | 59.0% | 59% | 53.3% at tb-internet |
| Crypto | 64.7% | 72% | 53.8% at tb-internal |
| Logging | 75.4% | 80% | 72.0% at tb-internal |

```
STRIDE Posture (Juice Shop v3)
═══════════════════════════════════════════════════
Denial of Service     |█████████████████░░░░░░░░| 54%  ← Medium
Elev. of Privilege    |█████████████████░░░░░░░░| 56%  ← Medium
Tampering             |██████████████████░░░░░░░| 57%  ← Medium
Info. Disclosure      |██████████████████░░░░░░░| 59%  ← Medium
Spoofing              |███████████████████░░░░░░| 61%  ← Medium
Repudiation           |██████████████████████░░░| 71%  ← Low
                      0%                       100%
                          ← Threshold: 85% (secure) →
```
**Fig. 2.** STRIDE posture scores for Juice Shop (v3 engine). All categories except Repudiation fall below 70% (Medium threat level). Repudiation is the only posture-derived threat (no rule pattern fired).

**Attack Paths Discovered (Juice Shop v3):**

| Score | Path | Hops |
|---|---|---|
| 0.750 | Angular Frontend → REST API Backend | 1 |
| 0.750 | Internet User → Angular Frontend | 1 |
| 0.530 | Internet User → Angular Frontend → REST API Backend | 2 |
| 0.513 | Angular Frontend → REST API Backend → SQLite Database | 2 |
| 0.500 | Administrator → REST API Backend | 1 |

The highest-scoring paths (0.750) identify the unencrypted, unauthenticated internal hop between the Angular frontend and Express API — crossing a trust boundary without protection. This is directly actionable: add mutual TLS or service mesh encryption between frontend and API.

### E. Results: AWS ECS Terraform

**TABLE VI**
CAUSTALTM v2 ENGINE OUTPUT — AWS ECS TERRAFORM

| Metric | Result |
|---|---|
| Components modeled | 9 (ALB, 2×ECS, DynamoDB, S3, ECR, CodePipeline, 2×External) |
| Data flows | 8 |
| Trust boundaries | 3 (External, DMZ, Internal) |
| SAST findings (IaC) | Variable (depends on Semgrep p/terraform scan) |
| STRIDE threats identified | 6 |
| Attack paths discovered | 4 concrete paths |

**Attack Paths Discovered (AWS ECS):**

| Score | Path | Hops | Key Risk |
|---|---|---|---|
| 0.720 | Internet Users → ALB → ECS Client → ECS Server → DynamoDB | 4 | Unencrypted internal traffic + PII |
| 0.550 | Internet Users → ALB → ECS Client → ECS Server | 3 | No auth between services |
| 0.350 | Developers → CodePipeline → S3 | 2 | Source code in artifacts |
| 0.300 | Developers → CodePipeline → ECR | 2 | Container image supply chain |

The highest-scoring path (0.720) reveals that while the ALB terminates HTTPS from the internet, traffic between ALB → ECS Client and Client → Server is unencrypted HTTP within the VPC. This is a real finding — the Terraform modules configure ALB listeners on port 443 but target groups forward to port 80 without re-encryption. The path crosses two trust boundaries (External→DMZ, DMZ→Internal) while handling credential and PII data without end-to-end encryption.

### F. Ground Truth Comparison (Juice Shop)

Of 15 known Juice Shop challenges manually mapped to STRIDE categories, the system matched 8 (53%) through CWE tracing and STRIDE category alignment:

**TABLE VII**
GROUND TRUTH COMPARISON — SELECTED JUICE SHOP CHALLENGES

| Challenge | CWE | STRIDE | Detected | Method |
|---|---|---|---|---|
| SQL Injection (search) | CWE-89 | Tampering | Yes | SAST CWE match |
| SQL Injection (login) | CWE-89 | Tampering | Yes | SAST CWE match |
| Path Traversal | CWE-22 | Information Disclosure | Yes | SAST CWE match |
| Directory Listing | CWE-548 | Information Disclosure | Yes | STRIDE category |
| Missing Rate Limiting | CWE-770 | Denial of Service | Yes | SAST keyword |
| Weak Crypto (MD5) | CWE-327 | Information Disclosure | Yes | SAST CWE match |
| Hardcoded JWT Secret | CWE-798 | Spoofing | Yes | SAST CWE match |
| IDOR | CWE-639 | Elevation of Privilege | Yes | STRIDE category |
| JWT Forgery | CWE-347 | Spoofing | No | Requires semantic analysis |
| CSRF | CWE-352 | Spoofing | No | Token present, logic flaw |
| XSS (DOM) | CWE-79 | Tampering | No | Client-side, not in server SAST |
| Prototype Pollution | CWE-1321 | Tampering | No | CWE not in mapping |
| Race Condition | CWE-362 | Tampering | No | Requires dynamic analysis |
| Broken Anti-Automation | CWE-799 | Denial of Service | No | Business logic |
| Sensitive Data in URL | CWE-598 | Information Disclosure | No | Requires runtime context |

**Detection rate: 53% (8/15).** Missed challenges primarily require semantic understanding of business logic (JWT forgery, CSRF token bypass) or client-side analysis not performed by server-side SAST tools — confirming that posture-based analysis excels at structural/architectural threats but requires extension for application-specific logic threats.

### G. Comparative Analysis

**TABLE VIII**
COMPARISON WITH EXISTING APPROACHES

| Capability | Manual STRIDE | ML Vuln Rankers | Rule-Based (PyTM) | CausalTM |
|---|---|---|---|---|
| Architecture extraction | Manual | N/A | Manual | Semi-automated |
| Input evidence | Expert knowledge | CVE databases | Analyst input | SAST + DAST + IaC |
| Reasoning type | Human judgment | Associational (L1) | Rule matching | Causal (L2/L3) |
| Attack path analysis | Manual | No | No | Graph traversal |
| "What-if" queries | No | No | No | Yes (counterfactual) |
| Cross-layer effects | No | No | No | Yes (6 rules) |
| Remediation sequencing | No | Priority list | No | Optimal roadmap |
| IaC support | No | No | Limited | Full (Terraform, K8s) |
| Execution time | Days–weeks | Minutes | Minutes | < 2 seconds |
| Cost per analysis | $15K–$50K | Tool license | Free | Free (open source) |

### H. v2 vs v3 Comparative Evaluation

To evaluate whether boundary-specific posture improves threat localization over global posture (RQ1), we run both v2 (global) and v3 (boundary-specific) engines on the same Juice Shop inputs — 23 SAST findings from Semgrep and 10 DAST findings from OWASP ZAP.

**TABLE IX**
v2 vs v3 COMPARISON — SAME INPUTS (23 SAST + 10 DAST, 6 COMPONENTS, 5 FLOWS, 3 BOUNDARIES)

| Metric | v2 (Global) | v3 (Boundary-Specific) | Improvement |
|---|---|---|---|
| Overall Risk | 0.431 (Medium) | 0.404 (Medium) | Less over-generalization |
| Total Threats | 6 | 6 | Same coverage |
| Roadmap Steps | 8 | 4 | More efficient (boundary-targeted) |
| Boundary Specificity | Global only | Per-boundary (4 assessed) | Localization |
| Sources Used | SAST + DAST | SAST + DAST + Repo | +structural assessment |
| Traceability Depth | 2 layers | 4 layers | +2 abstraction layers |
| Confidence Tracking | None | Yes (avg 68%) | Uncertainty awareness |
| Uncertain Divergences | N/A | 5 flagged | Multi-source conflict detection |
| Fusion Layer | None | Yes (worst-case adjusted) | Prevents dilution |
| Classification | Threshold only | Hybrid (5 rule + 1 posture-derived) | Contextual + fallback |

**TABLE X**
STRIDE POSTURE COMPARISON (23 SAST + 10 DAST)

| STRIDE Category | v2 Posture | v3 Posture | Delta | Interpretation |
|---|---|---|---|---|
| Denial of Service | 0.353 | 0.541 | +0.188 | v3 avoids global crash from localized findings |
| Tampering | 0.563 | 0.571 | +0.008 | Similar |
| Spoofing | 0.571 | 0.613 | +0.042 | Repo adds positive structural signal |
| Information Disclosure | 0.592 | 0.590 | −0.002 | Nearly identical |
| Elevation of Privilege | 0.602 | 0.555 | −0.047 | Repo found unauthenticated exposure |
| Repudiation | 0.733 | 0.705 | −0.028 | Repo detected logging gap |

**Key RQ1 findings:**

1. **Over-generalization avoidance (DoS):** v2 rates DoS posture as 0.353 (Critical) because all validation findings globally reduce posture. v3 rates it 0.541 (Medium) because findings are localized to tb-internal — other boundaries retain better posture and the worst-case-adjusted average is less catastrophic. This demonstrates the core v3 advantage.
2. **Roadmap efficiency:** v2 requires 8 remediation steps; v3 requires only 4. Because v3 knows WHICH boundary is weakest, it recommends targeted fixes (e.g., "fix validation at tb-internal") rather than broad system-wide improvements.
3. **Hybrid classification demonstrated:** v3 produces 5 rule-matched threats (posture weakness + architectural context required) and 1 posture-derived threat (Repudiation — logging posture 0.705 < 0.85 threshold, no rule pattern matches because no public-facing logging exposure). This proves both classification modes operate in practice.
4. **Multi-source enrichment:** v3's Repo sub-DAG detects structural weaknesses invisible to SAST/DAST — unencrypted internal flows (crypto drops from 0.87 to 0.65), unauthenticated public components (auth drops from 0.77 to 0.59). The 5 uncertain divergences where sources disagree are flagged rather than silently resolved.
5. **Boundary localization:** Every v3 threat traces to specific boundaries (tb-internal, tb-dmz, tb-internet) with confidence scores. v2 attributes all threats to global "Architecture."

**v3 Remediation Roadmap (4 steps to zero risk):**

| Step | Fix | Boundary | Posture Change | Risk Reduction |
|---|---|---|---|---|
| 1 | Fix input validation | tb-internal | 52% → 100% | −0.180 |
| 2 | Fix authentication | tb-internet | 59% → 100% | −0.116 |
| 3 | Fix encryption | tb-internal | 65% → 100% | −0.080 |
| 4 | Fix audit logging | tb-internal | 75% → 100% | −0.029 |

**RQ1 supported claim:** Boundary-specific posture improves threat LOCALIZATION and REMEDIATION PRIORITIZATION over global posture. With the same inputs, v3 produces the same threat coverage but with: (1) boundary-level traceability, (2) 50% fewer roadmap steps (more efficient fixes), (3) hybrid classification demonstrating both modes, (4) multi-source enrichment via Repo sub-DAG, and (5) explicit uncertainty tracking.

**Methodology notes:**
- Traceability depth is a design-based measure: v2 (finding → posture → STRIDE) vs v3 (finding → boundary_posture → fused_posture → STRIDE).
- Repudiation is posture-derived because no rule pattern requires public-facing logging exposure — the threshold alone triggers the threat. This demonstrates the hybrid fallback mechanism.
- Equal threat count is expected; the improvement is in localization and efficiency, not raw detection.


## VI. Discussion

### A. Posture-Based Reasoning vs. Vulnerability Counting

The shift from counting vulnerabilities to computing architectural posture fundamentally changes what the tool can reason about. A vulnerability counter reports "23 findings — fix them." CausalTM reports "your validation posture at the API boundary is 30%, meaning 70% of the expected validation coverage is absent at this specific trust boundary — this causes a Tampering threat because unvalidated data crosses that boundary."

The v3 refinement — treating findings as evidence of boundary-specific control coverage gaps — makes the causal claim more precise and defensible. A single SQL injection finding does not prove the entire architecture lacks validation; it proves validation is incomplete at THAT boundary. Other boundaries where no findings exist retain full posture. This avoids the false generalization problem inherent in global aggregation approaches.

### B. Value of Cross-Layer Propagation

The cross-layer dependency rules (Table I) produced 3 triggered effects in the Juice Shop evaluation. When the roadmap recommended fixing input validation in code (Step 2), the system predicted that attack surface at runtime would also decrease (Rule 3, strength 0.50). This prediction is actionable: a development team can justify investing in code-level fixes by demonstrating that a single fix provides measurable improvement across two observable layers.

Without cross-layer rules, a sequenced roadmap cannot account for the fact that fixing code changes what DAST can observe. The system would either over-recommend (suggesting fixes to both layers when one suffices) or under-predict improvement (crediting only the directly-fixed layer).

### C. Attack Path Analysis

The graph-traversal attack path algorithm provides concrete architectural narratives that flat threat lists cannot. The finding "Internet Users → ALB → ECS Client → ECS Server → DynamoDB" with score 0.720 immediately communicates: (1) the attack surface (ALB), (2) the intermediate processing (two ECS services), (3) the target (DynamoDB with PII), and (4) the specific weakness (unencrypted internal hops). This is directly actionable — add service mesh encryption between ALB and ECS, or mutual TLS between ECS services.

The scoring formula (Equation 2) prioritises paths that are short (high *L_factor*), cross trust boundaries (high *B_norm*), lack encryption (high *E_norm*), and target sensitive data (high *D_max*). This approximates real attacker economics: shorter paths with fewer controls are more likely to be exploited.

### D. IaC Security Integration

The IaC-specific keyword classification in the SAST sub-DAG demonstrates that the same posture framework generalises from application code to infrastructure code. A Terraform finding like `security-group-open-ingress` maps to authentication posture (access control gap) using the same structural equation that maps a code-level CWE-287 (missing authentication). This unification means that application security and infrastructure security are assessed on the same scale — enabling cross-domain prioritisation.

### E. Hybrid STRIDE Classification: The Repudiation Case

The v3 evaluation demonstrates both modes of the hybrid STRIDE classification operating on the same application. Of 6 threats generated, 5 are rule-matched and 1 (Repudiation) is posture-derived. This distinction is architecturally significant.

**Rule-matched threats** require two conditions to fire: (1) the relevant posture falls below a severity threshold, AND (2) an architectural context condition is satisfied. For example, the Spoofing rule requires weak auth posture AND the presence of public-facing unauthenticated components. The Denial of Service rule requires weak validation posture AND public-facing components exposed to external traffic. These dual requirements ensure that threats are contextually grounded — posture weakness alone is insufficient.

**Repudiation is posture-derived** because the logging posture (70.5%) falls below the 85% threshold, triggering a Low-severity threat. However, no rule-based pattern fires for Repudiation because the existing rules check for conditions like "public-facing logging exposure" — which does not apply to Juice Shop's internal logging gap. The system correctly identifies the architectural weakness (insufficient audit logging) via posture threshold alone, without requiring a specific architectural pattern.

This demonstrates a key design feature: the hybrid approach ensures **no threat category is missed** when architectural patterns are incomplete, while still providing higher-confidence contextually-grounded assessments where patterns do apply. A pure rule-based system would miss the Repudiation threat entirely; a pure threshold system would lack the contextual grounding of the other five threats.

### F. Limitations

1. **Posture calibration**: The constant *K* = 3.0 in Equation (1) is expert-specified. Different organisations may have different risk tolerances. Empirical calibration through expert panel studies or historical incident correlation is needed.

2. **Architecture extraction**: The Juice Shop architecture was modeled rather than fully auto-detected from source. While the AWS ECS architecture was derived from Terraform modules, complete automated extraction from arbitrary repositories remains an open challenge.

3. **Ground truth coverage**: 53% detection against Juice Shop challenges is encouraging but incomplete. Missed challenges (JWT forgery, CSRF bypass, race conditions) require semantic analysis of business logic that static posture assessment cannot provide.

4. **Single-application validation**: Two evaluation targets demonstrate feasibility but cannot prove generalisability across all application types. Enterprise applications with hundreds of services need validation.

5. **Static posture thresholds**: The STRIDE severity thresholds (0.85/0.70/0.50/0.30) are based on security engineering judgment rather than empirical data correlating posture levels to breach probability.

6. **Cross-layer rule strengths**: The propagation strengths in Table I (0.50–0.80) are assigned based on engineering experience. Bayesian estimation from paired before/after measurements would strengthen these values.

### G. Threats to Validity

**Internal validity**: The ground truth mapping was produced by a single researcher. Severity weights align with industry convention (CVSS mapping) but have not been validated through independent expert panel consensus.

**External validity**: Evaluation targets are an intentionally vulnerable application and a reference architecture. Real production applications with lower vulnerability density and more complex architectures need evaluation.

**Construct validity**: "Posture" as a measurement of architectural security adequacy is a proxy. The relationship between computed posture scores and actual breach probability has not been empirically established. However, the directional claim (lower posture → higher threat) is consistent with established security principles.

---

## VII. Conclusion and Future Work

This paper has presented CausalTM, a Federated Structural Causal Model for automated STRIDE threat modeling. The system introduces five key innovations over existing approaches:

1. **Posture-based causal reasoning** — computing severity-weighted security control state rather than counting vulnerabilities, aligning automated analysis with STRIDE's architectural intent.

2. **Cross-layer dependency rules** — predicting how interventions in one data source (code, runtime, infrastructure) propagate effects to others, enabling multi-layer return-on-investment calculations.

3. **Graph-traversal attack paths** — discovering concrete multi-hop paths through the component graph scored by exploitability factors, producing actionable architectural narratives rather than abstract threat descriptions.

4. **Unified IaC and application analysis** — applying the same posture framework to both application code (CWE-classified) and infrastructure code (keyword-classified Terraform/Kubernetes findings).

5. **Sequenced remediation roadmaps** — computing optimal fix ordering that accounts for cross-layer side effects, answering "what should we fix first?" rather than merely "what is broken?"

Evaluation against OWASP Juice Shop (23 SAST + 10 DAST findings) with comparative analysis of global-posture (v2) and boundary-specific (v3) approaches demonstrates that: (1) boundary-specific posture improves threat localization and remediation efficiency (4 targeted steps vs 8 broad steps), (2) multi-source fusion with uncertainty tracking detects 5 source divergences that single-source approaches miss, (3) hybrid STRIDE classification produces both rule-matched threats (requiring architectural context) and posture-derived fallback threats, and (4) the same threat coverage is achieved with substantially better specificity, traceability, and confidence handling. The improvement is in localization and prioritization quality, not in raw threat detection count.

### Future Work

- **Empirical posture calibration**: Expert panel studies to validate *K* = 3.0 and STRIDE thresholds against incident data.
- **Full repository auto-detection**: Extending architecture extraction to detect components and flows automatically from arbitrary monorepo and microservice structures.
- **Supply chain analysis**: Integrating SCA/OSV vulnerability data as a fourth sub-DAG to model transitive dependency risks.
- **Incremental/differential analysis**: Computing "what changed since last scan" for CI/CD gate decisions (block merge if new Critical threats introduced).
- **Compliance mapping**: Extending STRIDE threats to OWASP Top 10, NIST 800-53, and CIS Benchmark control mappings for GRC reporting.
- **Formal do-calculus**: Replacing current graph-based propagation with formal Pearl *do*-operator interventional queries for stronger causal guarantees.
- **Multi-application evaluation**: Validating against diverse real-world production applications with varying architecture complexity and vulnerability density.

---

## References

[1] A. Shostack, *Threat Modeling: Designing for Security*. Indianapolis, IN, USA: Wiley, 2014.

[2] IBM Security, "Cost of a Data Breach Report 2024," IBM Corporation, Armonk, NY, USA, 2024.

[3] L. Kohnfelder and P. Garg, "The threats to our products," Microsoft Corporation, Redmond, WA, USA, Internal Document, 1999.

[4] K. Tuma, G. Calikli, and R. Scandariato, "Threat analysis of software systems: A systematic literature review," *J. Syst. Softw.*, vol. 144, pp. 275–294, 2018.

[5] R. Scandariato, K. Wuyts, and W. Joosen, "A descriptive study of Microsoft's threat modeling technique," *Requirements Eng.*, vol. 20, no. 2, pp. 163–180, 2015.

[6] J. Jacobs, S. Romanosky, I. Adjerid, and W. Baker, "Improving vulnerability remediation through better exploit prediction," *J. Cybersecurity*, vol. 7, no. 1, pp. 1–14, 2021.

[7] W. Xiong and R. Lagerstrom, "Threat modeling — A systematic literature review," *Comput. Security*, vol. 84, pp. 53–69, 2019.

[8] J. Pearl, *Causality: Models, Reasoning, and Inference*, 2nd ed. Cambridge, U.K.: Cambridge Univ. Press, 2009.

[9] D. Arp, E. Quiring, F. Pendlebury, et al., "Dos and don'ts of machine learning in computer security," in *Proc. 31st USENIX Security Symp.*, Boston, MA, USA: USENIX, 2022, pp. 3971–3988.

[10] OWASP Foundation, "PyTM: Pythonic threat modeling," 2023. [Online]. Available: https://owasp.org/www-project-pytm/

[11] S. Iqbal, P. Missier, and J. Mayfield, "Automated extraction of data flow diagrams from software repositories," in *Proc. IEEE Int. Conf. Softw. Architecture (ICSA)*, 2023, pp. 1–10.

[12] T. Le, T. Chen, and M. A. Babar, "A survey on data-driven software vulnerability assessment and prioritization," *ACM Comput. Surv.*, vol. 54, no. 5, pp. 1–36, 2021.

[13] Y. Fang, Y. Liu, and Z. Gao, "Causal inference for intrusion detection: A survey," *IEEE Access*, vol. 10, pp. 56892–56912, 2022.

[14] G. Husari, X. Niu, B. Chu, and E. Al-Shaer, "Using entropy and mutual information to extract threat actions from cyber threat intelligence," *Int. J. Inf. Security*, vol. 19, pp. 531–550, 2020.

[15] S. Noel and S. Jajodia, "Optimal IDS sensor placement and alert prioritization using attack graphs," *J. Comput. Security*, vol. 16, no. 3, pp. 259–290, 2008.

[16] X. Ou, S. Govindavajhala, and A. W. Appel, "MulVAL: A logic-based network security analyzer," in *Proc. 14th USENIX Security Symp.*, Baltimore, MD, USA: USENIX, 2005, pp. 113–128.

[17] S. Jha, O. Sheyner, and J. Wing, "Two formal analyses of attack graphs," in *Proc. 15th IEEE Comput. Security Foundations Workshop*, 2002, pp. 49–63.

[18] B. Schölkopf, F. Locatello, S. Bauer, et al., "Toward causal representation learning," *Proc. IEEE*, vol. 109, no. 5, pp. 612–634, 2021.

[19] A. Hagberg, D. Schult, and P. Swart, "Exploring network structure, dynamics, and function using NetworkX," in *Proc. 7th Python Sci. Conf. (SciPy)*, 2008, pp. 11–15.

[20] B. Kimminich and OWASP Foundation, "OWASP Juice Shop: Probably the most modern and sophisticated insecure web application," 2024. [Online]. Available: https://owasp.org/www-project-juice-shop/

