# Mathematical Foundations: Current State & Future Plan

## Overview

This document captures the mathematical underpinnings of the CausalTM Federated Structural Causal Model (FSCM). It is organized as:

1. **Current State** — What math is implemented today (heuristic, engineering-grade)
2. **Future Plan** — Formal causal inference math to be implemented (Pearl's framework)
3. **Gap Analysis** — What needs to change and why
4. **Implementation Roadmap** — How to get from current to formal

---

## 1. CURRENT STATE: Heuristic Mathematical Model

### 1.1 Master DAG Risk Computation

**Current formula (weighted linear combination):**

```
overall_risk = base_risk × reduction_factor

Where:
  base_risk = w₁·Exploitability + w₂·Exposure + w₃·Impact_Severity
  
  w₁ = 0.4, w₂ = 0.3, w₃ = 0.3  (hand-tuned weights)
  
  reduction_factor = 1 - (Mitigation_Posture × mitigation_strength)
  mitigation_strength = 0.4  (maximum 40% risk reduction from defenses)
```

**Intermediate variable computation (weighted sum of edge nodes):**

```
Exploitability = Σᵢ (edge_nodeᵢ.value × weightᵢ × edge_nodeᵢ.causal_strength) / Σᵢ (weightᵢ × strengthᵢ)

Where inputs to Exploitability:
  - sast.vulnerability_density  (weight: 0.25)
  - sast.injection_risk         (weight: 0.30)
  - dast.confirmed_exploitable  (weight: 0.35)
  - dast.severity_score         (weight: 0.10)
```

**Properties:**
- Deterministic (same input → same output)
- Bounded [0, 1]
- Monotonic (more vulnerabilities → higher risk)
- No probabilistic semantics
- No formal causal justification for the weights

---

### 1.2 Attack Path Scoring

**Current formula:**

```
path_score = (Σᵢ edge_weightᵢ) / path_length × boundary_bonus × confirmation_bonus

Where:
  edge_weightᵢ = weight on edge between node i and node i+1 (0-1)
  path_length = number of nodes in the path
  boundary_bonus = 1.3 if path crosses trust boundary, else 1.0
  confirmation_bonus = 1.4 if any step is DAST-confirmed, else 1.0
  
Final score = min(1.0, path_score)
```

**Properties:**
- Shorter paths score higher (fewer steps = easier attack)
- Confirmed paths score higher (proven exploitable)
- Boundary crossings increase severity
- No probability distribution — single point estimate

---

### 1.3 Counterfactual Analysis

**Current formula (graph surgery):**

```
effectiveness(intervention) = (paths_before - paths_after) / paths_before

Where:
  paths_before = count of attack paths from any vulnerability to any impact
  paths_after = same count after removing the intervention node from the graph
```

**For tactical counterfactuals (within sub-graph):**

```
tactical_effectiveness = Σᵢ |edge_node_beforeᵢ - edge_node_afterᵢ| / N

Where N = number of edge nodes in the sub-graph
```

**For multi-level counterfactuals (tactical → strategic propagation):**

```
risk_reduction = risk_before - risk_after
risk_reduction_pct = (risk_before - risk_after) / risk_before × 100

Where:
  risk_before = master_dag.overall_risk (with original edge node values)
  risk_after = master_dag.recalculate(new_edge_node_values_after_intervention)
```

**Properties:**
- Approximates the do-operator via graph surgery
- No probabilistic uncertainty
- No formal abduction step (doesn't infer hidden variables)

---

### 1.4 Confounder Handling

**Current approach (detection + confidence reduction):**

```
If confounder C detected for relationship A → B:
  threat.confidence = max(0.1, threat.confidence - 0.2)
  
Detection rule:
  C is a confounder if:
    C → A exists in graph  AND
    C → B exists in graph  AND
    A → B exists in graph  AND
    C is NOT on the direct path A → B
```

**Properties:**
- Correctly identifies confounder structure (fork: C → A, C → B)
- But adjustment is arbitrary (subtract 0.2) — not mathematically justified
- Does not compute the actual confounded vs. deconfounded effect

---

### 1.5 Edge Node Computation (Sub-Graph Level)

**SAST vulnerability density:**

```
vulnerability_density = (critical × 1.0 + high × 0.7 + medium × 0.4) / max(total_findings, 1)
Bounded to [0, 1]
```

**DAST confirmed exploitable ratio:**

```
confirmed_ratio = confirmed_count / max(total_findings, 1)
Causal strength = 0.95 (very high — runtime confirmation is strong evidence)
```

**Repo public exposure:**

```
exposure = public_facing_components / total_components
```

**Defense-in-depth score:**

```
defense = mean(auth_coverage, encrypted_cross_flows_ratio, boundary_count/3, indirect_access_score)
```

---

## 2. FUTURE PLAN: Formal Causal Inference Mathematics

### 2.1 Structural Causal Model (SCM) Formalization

**Definition:** An SCM M = (U, V, F, P(U)) consists of:

- **U** = {U_exploit, U_exposure, U_impact, ...} — Exogenous (unobserved) variables
- **V** = {Exploitability, Exposure, Impact, Mitigation, Risk} — Endogenous (observed) variables
- **F** = {f₁, f₂, f₃, f₄, f₅} — Structural equations (one per endogenous variable)
- **P(U)** = Prior distribution over exogenous variables

**Structural Equations (to replace weighted sums):**

```
f₁: Exploitability := σ(β₁·SAST_density + β₂·DAST_confirmed + β₃·Injection_risk + U_exploit)

f₂: Exposure := σ(β₄·Public_facing + β₅·Boundary_crossings + β₆·Attack_surface + U_exposure)

f₃: Impact_Severity := σ(β₇·Data_sensitivity + β₈·Blast_radius + β₉·SPOF_risk + U_impact)

f₄: Mitigation_Posture := σ(β₁₀·Defense_depth + β₁₁·Auth_coverage + β₁₂·TLS_posture + U_mitigation)

f₅: Risk := σ(γ₁·Exploitability + γ₂·Exposure + γ₃·Impact_Severity - γ₄·Mitigation_Posture + U_risk)

Where:
  σ(x) = 1 / (1 + e^(-x))  — Sigmoid function (bounds output to [0,1])
  βᵢ, γᵢ = Structural parameters (learnable from data or expert-specified)
  Uᵢ ~ Distribution (captures unmodeled factors)
```

**Why sigmoid?** Security risk is bounded [0,1], relationships are non-linear (diminishing returns on mitigation), and it enables probabilistic interpretation.

**Alternative: Noisy-OR model (common in security):**

```
P(Risk = High) = 1 - Π(1 - P(Risk | parentᵢ = active))

Example:
P(Breach) = 1 - (1 - P(Breach|SQLi)) × (1 - P(Breach|NoAuth)) × (1 - P(Breach|Exposed))
           = 1 - (1 - 0.6) × (1 - 0.4) × (1 - 0.3)
           = 1 - 0.4 × 0.6 × 0.7
           = 1 - 0.168
           = 0.832
```

Noisy-OR is particularly suitable because multiple vulnerabilities independently increase risk.

---

### 2.2 The do-Operator (Interventional Queries)

**Pearl's Truncated Factorization:**

For a causal model with variables V = {V₁, V₂, ..., Vₙ} and DAG G:

```
P(v₁, v₂, ..., vₙ | do(Vᵢ = x)) = Π_{j≠i} P(vⱼ | pa(Vⱼ))  if vᵢ = x
                                    = 0                          if vᵢ ≠ x

Where pa(Vⱼ) = parents of Vⱼ in the causal DAG
```

**In our system, this means:**

```
P(Risk > 0.7 | do(Mitigation = "add_gateway"))

= Evaluate structural equation f₅ with Mitigation FORCED to the value 
  that "add_gateway" produces, regardless of what would naturally occur.

Concretely:
  1. Set Mitigation_Posture = 0.9 (gateway adds strong defense)
  2. Do NOT change Exploitability or Exposure (they're independent of Mitigation in the causal graph)
  3. Compute: Risk = σ(γ₁·E + γ₂·X + γ₃·I - γ₄·0.9 + U_risk)
  4. Compare to: Risk = σ(γ₁·E + γ₂·X + γ₃·I - γ₄·M_current + U_risk)
  5. Difference = Causal Effect of adding gateway
```

**Average Causal Effect (ACE):**

```
ACE(Mitigation → Risk) = E[Risk | do(M = applied)] - E[Risk | do(M = not_applied)]

If ACE = -0.35, it means: "Applying this mitigation CAUSES a 0.35 reduction in expected risk"
```

---

### 2.3 Backdoor Criterion and Adjustment Formula

**When to use:** When estimating causal effects from OBSERVATIONAL DATA (historical scans + breach outcomes).

**Backdoor Criterion:**

A set Z satisfies the backdoor criterion relative to (X, Y) in DAG G if:
1. No node in Z is a descendant of X
2. Z blocks every path between X and Y that contains an arrow INTO X

**Backdoor Adjustment Formula:**

```
P(Y = y | do(X = x)) = Σ_z P(Y = y | X = x, Z = z) × P(Z = z)
```

**Application in CausalTM:**

```
Scenario: Estimating causal effect of "vulnerability count" (X) on "breach probability" (Y)
Confounder: "Internet exposure" (Z) — causes both more detection AND more breaches

Without adjustment (biased):
  P(Breach | High_Vulns) = 0.7  (seems like vulns strongly cause breaches)

With backdoor adjustment through Z = {Internet_Exposure}:
  P(Breach | do(High_Vulns)) = Σ_z P(Breach | High_Vulns, Exposure=z) × P(Exposure=z)
                              = P(Breach | High_Vulns, Exposed) × P(Exposed)
                              + P(Breach | High_Vulns, Not_Exposed) × P(Not_Exposed)
                              = 0.8 × 0.3 + 0.3 × 0.7
                              = 0.24 + 0.21
                              = 0.45  (TRUE causal effect is lower — exposure was inflating it)
```

**Implementation plan:**

```python
def backdoor_adjustment(self, treatment: str, outcome: str, adjustment_set: list[str]) -> float:
    """
    Compute P(outcome | do(treatment)) using backdoor adjustment.
    
    Requires historical data with observed values for all variables.
    """
    # P(Y|do(X)) = Σ_z P(Y|X,Z) × P(Z)
    total = 0.0
    for z_values in self._enumerate_adjustment_set(adjustment_set):
        p_y_given_x_z = self._conditional_probability(outcome, treatment, z_values)
        p_z = self._marginal_probability(z_values)
        total += p_y_given_x_z * p_z
    return total
```

---

### 2.4 Frontdoor Criterion and Adjustment Formula

**When to use:** When you CANNOT block the backdoor path (unobserved confounders), but you have a mediator.

**Frontdoor Criterion:**

A set M satisfies the frontdoor criterion relative to (X, Y) if:
1. X blocks all directed paths from X to M
2. There is no unblocked backdoor path from X to M
3. All backdoor paths from M to Y are blocked by X

**Frontdoor Adjustment Formula:**

```
P(Y = y | do(X = x)) = Σ_m P(M = m | X = x) × Σ_x' P(Y = y | M = m, X = x') × P(X = x')
```

**Application in CausalTM:**

```
Scenario: Effect of "coding practice" (X) on "breach" (Y)
Problem: Unobserved confounder U (e.g., team skill level) affects both X and Y
Mediator: "vulnerability count" (M) — coding practice → vulnerabilities → breach

P(Breach | do(Good_Practice)) = Σ_m P(Vulns=m | Good_Practice) × Σ_x' P(Breach | Vulns=m, Practice=x') × P(Practice=x')
```

**When this applies in our system:**
- When organizational factors (unmeasured) confound both security practices and outcomes
- When we can observe the MEDIATOR (vulnerability count) but not the confounder (team capability)

---

### 2.5 Counterfactual Queries (Level 3 — Formal)

**Three-Step Procedure (Abduction-Action-Prediction):**

```
Question: "Given that we observed Risk=0.8 with current configuration,
           what WOULD the risk have been if we had added a gateway?"

Step 1: ABDUCTION — Infer exogenous variables given evidence
  P(U | Risk=0.8, current_observations) 
  → Solve for U values that are consistent with what we observed

Step 2: ACTION — Modify the SCM (apply intervention)
  Set Mitigation = "gateway_added" (force the variable)
  Remove all incoming edges to Mitigation (it's now externally set)

Step 3: PREDICTION — Compute outcome under modified model with inferred U
  Risk_counterfactual = f₅(Exploitability, Exposure, Impact, Mitigation="gateway", U_inferred)
```

**Formal notation:**

```
P(Risk_{do(M=gateway)} = r | Risk = 0.8, Observed_State = current)

= Σ_u P(Risk = r | do(M = gateway), U = u) × P(U = u | Risk = 0.8, Observed_State)
```

**Implementation plan:**

```python
def counterfactual_query(self, intervention: dict, evidence: dict) -> float:
    """
    Full counterfactual: "Given evidence, what would Y be under intervention?"
    
    Uses the 3-step abduction-action-prediction procedure.
    """
    # Step 1: Abduction — infer U given evidence
    u_posterior = self._abduction(evidence)
    
    # Step 2: Action — modify SCM
    modified_scm = self._apply_intervention(intervention)
    
    # Step 3: Prediction — compute outcome
    counterfactual_outcome = modified_scm.predict(u_posterior)
    
    return counterfactual_outcome
```

---

### 2.6 Natural Direct and Indirect Effects (Mediation Analysis)

**Purpose:** Decompose the total effect of X on Y into:
- Direct effect (X → Y, not through mediator)
- Indirect effect (X → M → Y, through mediator)

**Formulas:**

```
Total Effect (TE):
  TE = E[Y | do(X=1)] - E[Y | do(X=0)]

Natural Direct Effect (NDE):
  NDE = E[Y_{X=1, M=M₀}] - E[Y_{X=0, M=M₀}]
  (Effect of X on Y if M were held at its natural value under X=0)

Natural Indirect Effect (NIE):
  NIE = E[Y_{X=0, M=M₁}] - E[Y_{X=0, M=M₀}]  
  (Effect of X on Y through M only)

Decomposition:
  TE = NDE + NIE (on additive scale)
  TE = NDE × NIE (on multiplicative scale)
```

**Application in CausalTM:**

```
Total Effect of "adding authentication" on "breach risk":
  TE = P(Breach | do(Auth=present)) - P(Breach | do(Auth=absent)) = -0.45

Natural Direct Effect (auth directly prevents unauthorized access):
  NDE = -0.30

Natural Indirect Effect (auth reduces vulnerability exploitability which reduces breach):
  NIE = -0.15

Interpretation: 67% of auth's protective effect is DIRECT (blocks access),
               33% is INDIRECT (through reducing exploitability of other vulns)
               
Decision: Auth is valuable even if it doesn't fix underlying code vulns.
```

---

### 2.7 Probability of Necessity and Sufficiency

**Purpose:** Answer "Was X necessary/sufficient for Y?" — critical for root cause analysis.

**Probability of Necessity (PN):**

```
PN = P(Y₀ = 0 | X = 1, Y = 1)

"Given that the breach happened (Y=1) with SQLi present (X=1),
 what's the probability that the breach would NOT have happened 
 if SQLi was absent?"
```

**Probability of Sufficiency (PS):**

```
PS = P(Y₁ = 1 | X = 0, Y = 0)

"Given no breach (Y=0) with SQLi absent (X=0),
 what's the probability that a breach WOULD have occurred
 if SQLi was present?"
```

**Application:** Prioritizing remediation. High PN = fixing this would likely have prevented the breach. High PS = this vulnerability alone is sufficient to cause a breach.

---

## 3. GAP ANALYSIS: Current vs. Formal

| Component | Current Math | Formal Math Needed | Difficulty |
|---|---|---|---|
| Risk computation | Weighted sum | Structural equations (sigmoid/noisy-OR) | Medium |
| Counterfactuals | Graph surgery (remove node, count paths) | Abduction-Action-Prediction (3-step) | High |
| Confounder handling | Detect fork structure, subtract confidence | Backdoor adjustment formula | Medium |
| Mediator analysis | Betweenness centrality (frequency) | Natural Direct/Indirect Effects | High |
| Edge weights | Hand-assigned (0.3, 0.5, 0.8) | Conditional probability tables or learned parameters | Medium |
| Uncertainty | Point estimates (single number) | Probability distributions P(Y\|do(X)) | High |
| Historical learning | Not implemented | Parameter estimation from past scan data | High |
| Causal discovery | Not applicable (structure is given) | Optional: learn structure from data (PC algorithm) | Future |

---

## 4. IMPLEMENTATION ROADMAP

### Phase 1: Parametric SCM (Immediate — Current Sprint)
- Replace weighted sums with sigmoid structural equations
- Define explicit conditional probability tables for known relationships
- Implement noisy-OR for multi-parent risk nodes
- Keep DAG structure as-is (expert-defined)
- **Outcome:** Math is formalized and defensible for the DBA/paper

### Phase 2: Proper do-Calculus (Next — After Prototype Works)
- Implement truncated factorization for interventional queries
- Replace "remove node and count" with proper do-operator computation
- Add Average Causal Effect (ACE) computation
- **Outcome:** Counterfactuals have proper probabilistic semantics

### Phase 3: Backdoor/Frontdoor Adjustment (When Historical Data Available)
- Collect historical scan results (runs across multiple projects over time)
- Implement backdoor adjustment for confounded relationships
- Implement frontdoor adjustment for unobserved confounders
- Learn edge weights from data (maximum likelihood or Bayesian estimation)
- **Outcome:** System improves with data; confounder handling is formally correct

### Phase 4: Full Counterfactual Reasoning (Advanced)
- Implement abduction-action-prediction 3-step procedure
- Add Probability of Necessity/Sufficiency for root cause analysis
- Implement Natural Direct/Indirect Effects for mediation analysis
- Add uncertainty quantification (credible intervals on risk scores)
- **Outcome:** Full Pearl Level 3 reasoning; publishable as novel contribution

### Phase 5: Causal Discovery (Research Extension)
- When sufficient historical data accumulated (100+ scans)
- Apply PC/GES/NOTEARS algorithms to learn/validate DAG structure
- Compare learned structure against expert-defined structure
- Identify previously unknown causal relationships
- **Outcome:** System discovers new security insights from data

---

## 5. THEORETICAL POSITIONING (For DBA/Book)

### 5.1 Pearl's Causal Hierarchy (Ladder of Causation)

```
Level 3: COUNTERFACTUAL (Imagining)
  "Would the breach have occurred if we had added authentication?"
  P(Y_x | X', Y')
  → Our Phase 4 target
  
Level 2: INTERVENTIONAL (Doing)  
  "What happens to risk if we add a gateway?"
  P(Y | do(X))
  → Our Phase 2 target (currently approximated by graph surgery)
  
Level 1: ASSOCIATIONAL (Seeing)
  "How often do systems with SQLi get breached?"
  P(Y | X)
  → What correlation-based AI does (insufficient for decision-making)
```

**Our contribution:** Moving threat modeling from Level 1 (where most tools operate) to Level 2-3 (where security decisions actually live).

### 5.2 How This Relates to the Federated Architecture

```
Level 1 (Association): Each sub-graph computes edge nodes (observations)
Level 2 (Intervention): Master DAG performs do-calculus across layers
Level 3 (Counterfactual): Multi-level what-if reasoning (tactical + strategic)

The FEDERATED STRUCTURE enables:
- Level 2 at the MASTER level (strategic interventions)
- Level 2 at the SUB-GRAPH level (tactical interventions)
- Level 3 through PROPAGATION (intervene locally, observe globally)
```

### 5.3 Key Theorems to Reference

| Theorem | Author | Relevance |
|---|---|---|
| Truncated Factorization | Pearl (2000) | Justifies our do-operator implementation |
| Backdoor Criterion | Pearl (1993) | Justifies our confounder adjustment |
| Frontdoor Criterion | Pearl (1995) | Justifies mediation-based estimation |
| Causal Effect Identifiability | Tian & Pearl (2002) | Proves when our queries are answerable |
| Mediation Formula | Pearl (2001), VanderWeele (2015) | Justifies direct/indirect effect decomposition |
| Modularity/Autonomy | Halpern & Pearl (2005) | Justifies our federated sub-graph independence |

### 5.4 Key References for the Dissertation

1. Pearl, J. (2009). *Causality: Models, Reasoning, and Inference*. Cambridge University Press. — THE foundational text
2. Pearl, J., Glymour, M., & Jewell, N.P. (2016). *Causal Inference in Statistics: A Primer*. Wiley. — Accessible introduction
3. Peters, J., Janzing, D., & Scholkopf, B. (2017). *Elements of Causal Inference*. MIT Press. — Machine learning perspective
4. Spirtes, P., Glymour, C., & Scheines, R. (2000). *Causation, Prediction, and Search*. MIT Press. — Causal discovery algorithms
5. Hernan, M.A. & Robins, J.M. (2020). *Causal Inference: What If*. Chapman & Hall. — Applied perspective
6. Scholkopf, B. et al. (2021). "Toward Causal Representation Learning." Proceedings of the IEEE. — Modular causal models (related to our federation concept)

---

## 6. NOTATION SUMMARY

| Symbol | Meaning |
|---|---|
| X, Y, Z | Variables (treatments, outcomes, confounders) |
| do(X = x) | Intervention operator (force X to value x) |
| P(Y \| do(X)) | Interventional distribution (causal effect) |
| P(Y_x \| X', Y') | Counterfactual probability |
| pa(V) | Parents of V in the causal DAG |
| U | Exogenous (unobserved) variables |
| V | Endogenous (observed) variables |
| F = {fᵢ} | Set of structural equations |
| σ(x) | Sigmoid function: 1/(1+e^(-x)) |
| ACE | Average Causal Effect |
| PN | Probability of Necessity |
| PS | Probability of Sufficiency |
| NDE | Natural Direct Effect |
| NIE | Natural Indirect Effect |
| TE | Total Effect (NDE + NIE) |

---

## 7. SUMMARY TABLE: WHAT CHANGES AT EACH PHASE

| Phase | Current Formula | Replaces With | Library/Tool |
|---|---|---|---|
| Phase 1 | `risk = w₁E + w₂X + w₃I` | `risk = σ(β₁E + β₂X + β₃I - β₄M)` | NumPy/SciPy |
| Phase 2 | Remove node, count paths | Truncated factorization P(Y\|do(X)) | DoWhy / custom |
| Phase 3 | Subtract 0.2 from confidence | Backdoor: `Σ_z P(Y\|X,Z)P(Z)` | DoWhy / pgmpy |
| Phase 4 | N/A | Abduction-Action-Prediction | Custom / Pyro |
| Phase 5 | Expert-defined DAG | PC/GES learned DAG | causal-learn / NOTEARS |
