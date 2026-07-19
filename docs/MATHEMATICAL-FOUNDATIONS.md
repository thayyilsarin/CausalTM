# Mathematical Foundations: Current State & Future Plan

*Updated to reflect CausalTM v2 — vulnerabilities as base variables, posture as effect*

## Overview

This document captures the mathematical underpinnings of the CausalTM Federated Structural Causal Model. The fundamental causal claim is:

> **Individual vulnerabilities (base variables) CAUSE architectural security posture (edge nodes/effects), which DETERMINES STRIDE threat existence (final assessment).**

This three-level causal chain is what makes CausalTM a true causal model — not just an aggregation engine.

```
CAUSAL DIRECTION:

  [Vuln₁: CWE-89, Critical] ──┐
  [Vuln₂: CWE-79, High]    ──┼──CAUSES──▶ [Validation Posture = 0.23] ──DETERMINES──▶ [Tampering THREAT]
  [Vuln₃: CWE-22, High]    ──┘                    (effect)                             (STRIDE assessment)
       (base variables / causes)
```

---

## 1. CURRENT STATE: Implemented Mathematical Model (v2)

### 1.1 The Causal Structure

**Base Variables (Causes):** Individual SAST/DAST findings or architectural facts.
Each has properties: CWE, severity, posture_type, file/URL.

**Edge Nodes (Effects):** Severity-weighted posture scores representing the STATE of security controls.
These are CAUSED by the base variables — they are not arbitrary summaries.

**STRIDE Threats (Assessment):** Determined by posture thresholds applied to edge node values.

```
Layer 3 (Sub-DAGs):    Base Variables ──cause──▶ Edge Nodes (Effects)
Layer 4 (Master DAG):  Edge Nodes ──determine──▶ STRIDE Posture Nodes ──determine──▶ Overall Risk
Layer 5 (STRIDE):      Posture < Threshold ──implies──▶ Architectural Threat Exists
```

### 1.2 Posture Computation (Sub-DAG Level)

**The core formula — severity-weighted deficit:**

```
severity_weights = {Critical: 1.0, High: 0.7, Medium: 0.4, Low: 0.2}
max_deficit = 3.0  (calibration constant)

For a given posture type (e.g., "auth"):
  Let G = set of base variables classified as "auth" posture gaps
  weighted_deficit = Σᵢ∈G severity_weight(findingᵢ)
  posture = max(0.0, 1.0 - (weighted_deficit / max_deficit))
```

**Why this formula is causal (not just aggregation):**

The causal claim is: "Each vulnerability in category C CAUSES a reduction in posture P_C proportional to its severity." This is a structural equation:

```
P_C := max(0, 1 - (1/K) · Σᵢ∈G_C w(sᵢ))

Where:
  P_C = posture for category C (auth, crypto, validation, logging)
  G_C = set of findings classified into category C (base variables)
  w(sᵢ) = severity weight of finding i
  K = 3.0 (calibration: 3 Critical findings bring posture to zero)
```

**Calibration justification:**
- K = 3.0 means three Critical findings (total weight 3.0) brings posture to 0%
- One Critical finding reduces posture by 33% (significant — represents complete control failure at one boundary)
- Three Medium findings (total weight 1.2) reduce posture by 40% — less than one Critical
- This reflects security reality: one critical auth bypass is worse than three medium info leaks

**Properties:**
- Monotonically decreasing (more/worse findings → lower posture)
- Bounded [0, 1]
- Severity-sensitive (Critical matters more than Low)
- Interpretable: "posture = 0.37 means 63% of the calibrated maximum deficit is present"

### 1.3 Classification (CWE to Posture Type)

When CWE identifiers are available:

```
CWE_TO_POSTURE: CWE-ID → {auth, crypto, validation, logging}

Examples:
  CWE-89 (SQLi) → validation
  CWE-287 (Missing Auth) → auth
  CWE-311 (Missing Encryption) → crypto
  CWE-778 (Insufficient Logging) → logging
```

When CWE is unavailable (keyword fallback):

```
CLASSIFY_BY_KEYWORDS(finding.title + finding.rule_id):
  Contains {auth, login, password, session, jwt, csrf} → auth
  Contains {encrypt, crypto, tls, ssl, hash, secret} → crypto
  Contains {inject, xss, input, sanitiz, traversal, eval} → validation
  Contains {log, audit, trace, monitor} → logging
  Otherwise → validation (default, most common gap type)
```

### 1.4 Cross-Layer Propagation (Master DAG Level)

**Forward propagation (What-If):**

```
Given: Intervention do(edge_nodeₐ = v_new) where v_new ≠ v_current

For each cross-layer rule R where R.trigger = edge_nodeₐ:
  Δ = v_new - v_current  (change magnitude)
  
  If R.trigger_direction matches sign(Δ):
    affected_current = edge_nodes[R.affected].value
    effect_magnitude = |Δ| × R.strength
    
    If R.effect_direction = "increase":
      affected_new = min(1.0, affected_current + effect_magnitude)
    Else:
      affected_new = max(0.0, affected_current - effect_magnitude)
    
    edge_nodes[R.affected].value = affected_new
```

**STRIDE posture computation (from edge nodes):**

```
For each STRIDE category C:
  Let E_C = set of edge nodes with C in their stride_relevance
  
  stride_posture(C) = (1/|E_C|) × Σₑ∈E_C adjusted(e)
  
  Where adjusted(e) = 
    (1 - e.value) × e.causal_strength  if e is an exposure/leakage metric (lower = better)
    e.value × e.causal_strength          otherwise (higher = better)
```

**Overall risk:**

```
overall_risk = 1 - mean(stride_posture(C) for all C in STRIDE categories)
```

### 1.5 STRIDE Threat Generation

```
For each STRIDE category C:
  If stride_posture(C) < THRESHOLD_LOW (0.85):
    Generate threat with severity = posture_to_severity(stride_posture(C))
    
  posture_to_severity(p):
    p < 0.3 → Critical
    p < 0.5 → High
    p < 0.7 → Medium
    p < 0.85 → Low
```

### 1.6 Roadmap Algorithm

```
fixed_nodes = ∅
current_state = {edge_node_id: edge_node.value for all edge nodes}

REPEAT:
  best_fix = None
  best_impact = 0
  
  FOR each edge_node e NOT IN fixed_nodes:
    target = 1.0 (for posture metrics) or 0.1 (for exposure metrics)
    IF current_state[e] already at target: SKIP
    
    // Temporarily update state to current for accurate what-if
    result = what_if(e.layer, e.id, target)
    
    impact = Σ(stride_after - stride_before for all categories) + cross_layer_bonus
    
    IF impact > best_impact:
      best_fix = e
      best_impact = impact
  
  IF best_fix is None OR best_impact ≤ 0.01: BREAK
  
  // Apply fix
  current_state[best_fix.id] = target
  fixed_nodes.add(best_fix.id)
  Apply cross-layer effects to current_state
  
  roadmap.append(step)

UNTIL risk ≈ 0 OR no more improvements
```

### 1.7 Backward Propagation (Target → What to Fix)

```
Given: Target posture value T for edge node E (e.g., auth_posture = 1.0)
Current: E.value = V (e.g., 0.37)
Deficit to close: D = T - V (e.g., 0.63)

The edge node's base variables are known: E.base_variables = [v₁, v₂, v₃, ...]
Each base variable vᵢ contributes: contribution(vᵢ) = severity_weight(vᵢ) / max_deficit

To achieve target T:
  Must remove base variables until: Σ remaining_weights / max_deficit ≤ (1 - T)
  
  Recommendation: Fix base variables in SEVERITY ORDER (Critical first)
  Because: One Critical fix (weight 1.0/3.0 = 0.33 improvement) achieves more per fix
           than three Low fixes (weight 0.6/3.0 = 0.20 improvement)
```

---

## 2. WHY THIS IS CAUSAL (Not Just Aggregation)

### 2.1 The Causal Claim

The model makes an explicit causal claim:

> "The presence of CWE-89 (SQL Injection) in the codebase CAUSES the input validation posture to be degraded. This degraded posture CAUSES the architecture to be vulnerable to Tampering threats."

This is different from correlation:
- Correlation: "Systems with CWE-89 tend to have breaches" (association)
- Our model: "CWE-89 CAUSES posture degradation BECAUSE it represents absent input validation at a specific boundary" (mechanism)

### 2.2 The Causal Direction

```
Base Variable (Cause) → Edge Node (Effect) → STRIDE (Assessment)

NOT:
  STRIDE (Assessment) → Edge Node → Base Variable (this would be diagnostic, not causal)
  
NOT:
  Edge Node = average(Base Variables) (this would be aggregation, not causation)
```

The direction is justified because:
- Removing a base variable (fixing a vuln) CHANGES the edge node value (posture improves)
- This is interventional: do(remove_vuln) → observe(posture_change)
- The reverse is not true: arbitrarily setting posture to 1.0 doesn't make vulnerabilities disappear

### 2.3 Cross-Layer as Causal Prediction

The cross-layer rules make a causal prediction:

> "Improving code validation posture (SAST layer) WILL CAUSE the runtime attack surface (DAST layer) to decrease."

This prediction is testable: fix the code, re-run DAST, observe whether attack surface actually decreased. The rule encodes a known causal mechanism (validated code → fewer exploitable endpoints).

### 2.4 Why Bidirectional Propagation Is Causal

**Forward (causal effect):** "If I fix this vuln, what happens to posture and risk?"
→ This is the do-operator: do(remove_base_var) → observe(edge_node_change) → observe(risk_change)

**Backward (causal attribution):** "What base variables CAUSE this posture deficit?"
→ This is causal attribution: given the effect (low posture), identify the causes (which vulns)

Both directions are legitimate causal queries on the same DAG structure.

---

## 3. FUTURE PLAN: Formal Pearl Framework

### 3.1 Replace Weighted Sum with Structural Equations

**Current:** `posture = max(0, 1 - deficit/K)` (linear)

**Future:** `posture = σ(-β₀ - Σᵢ βᵢ · xᵢ + U)` where xᵢ = severity-weighted indicator of finding i

This gives:
- Probabilistic interpretation (posture as probability of control adequacy)
- Non-linear relationships (diminishing returns, threshold effects)
- Exogenous variables U (unmeasured factors affecting posture)

### 3.2 Formal do-Operator for What-If

**Current:** Set edge node value directly, recompute downstream.

**Future:** Truncated factorization:
```
P(risk | do(auth_posture = 0.9)) = Σ_z P(risk | auth_posture=0.9, Z=z) × P(Z=z)

Where Z = all other edge nodes (unchanged by this intervention because
      they're independent in the causal graph — unless cross-layer rule applies)
```

### 3.3 Backdoor Adjustment for Confounders

**When historical data available:**
```
P(STRIDE_threat | do(validation_posture = x)) = 
  Σ_z P(STRIDE_threat | validation_posture=x, exposure=z) × P(exposure=z)

This deconfounds the effect of validation on STRIDE threats
by controlling for the confounder "exposure" (which affects both
how many validation issues are FOUND and how dangerous they ARE).
```

### 3.4 Counterfactual with Abduction (Level 3)

**Current:** Remove base variable, recompute posture (graph surgery).

**Future (3-step procedure):**
```
1. ABDUCTION: Given observed posture=0.37, infer U (exogenous factors)
   "What unobserved factors explain why posture is 0.37 given these findings?"
   
2. ACTION: Remove base variable (do(vuln_fixed = True))
   
3. PREDICTION: Recompute posture with inferred U but without the removed variable
   "Given the same unobserved factors, what would posture be without this vuln?"
```

This gives a more accurate counterfactual because it accounts for factors beyond the measured findings.

### 3.5 Noisy-OR for STRIDE Threat Probability

**Future:**
```
P(Spoofing_threat) = 1 - Π_e∈E_spoofing (1 - P(threat | e.value))

Where:
  E_spoofing = edge nodes relevant to Spoofing
  P(threat | e.value) = probability that edge node e alone would cause Spoofing threat

This models multiple independent paths to the same threat:
  Auth gap alone could cause Spoofing
  Boundary gap alone could cause Spoofing
  Both together increase probability (noisy-OR combination)
```

---

## 4. GAP ANALYSIS: Current vs. Formal

| Component | Current (v2) | Formal (Future) | Gap Severity |
|---|---|---|---|
| Posture computation | Severity-weighted linear deficit | Sigmoid structural equation with U | Medium |
| Counterfactual | Graph surgery (set value, recompute) | Abduction-Action-Prediction (3-step) | Medium |
| Cross-layer rules | Fixed strength multipliers | Learnable parameters from historical data | Medium |
| STRIDE evaluation | Threshold-based (posture < 0.85) | Noisy-OR probability model | Low |
| Uncertainty | Point estimates (single number) | Probability distributions with credible intervals | High |
| Confounder handling | Not yet in v2 (cross-layer rules approximate it) | Formal backdoor adjustment | Medium |
| Edge weight calibration | Expert-specified (K=3.0) | Empirically estimated from validation data | Medium |

---

## 5. IMPLEMENTATION ROADMAP

### Phase 1: Current (Implemented — v2)
- Severity-weighted posture (linear deficit model) ✓
- Cross-layer propagation (fixed strength rules) ✓
- Bidirectional: forward (what-if) + backward (what to fix) ✓
- Roadmap to zero (iterative greedy with dedup) ✓
- CWE tracing from base variables to STRIDE threats ✓

### Phase 2: Sigmoid Structural Equations
- Replace linear posture formula with sigmoid: P_C = σ(-β₀ - Σ βᵢxᵢ)
- Add exogenous variables U (unmodeled factors)
- Enable probabilistic interpretation of posture scores
- Effort: 2-3 weeks

### Phase 3: Formal do-Calculus
- Implement truncated factorization for interventional queries
- Add Average Causal Effect (ACE) computation for each fix
- Enable formal comparison: "Fix A has ACE=-0.35, Fix B has ACE=-0.22 → Fix A is 60% more effective"
- Effort: 3-4 weeks

### Phase 4: Backdoor Adjustment + Learning
- When historical scan data available: learn cross-layer strengths from observations
- Apply backdoor adjustment when exposure confounds posture → threat relationship
- Validate expert-specified calibration against empirical data
- Effort: 4-6 weeks

### Phase 5: Full Level 3 (Counterfactual)
- Abduction-Action-Prediction for precise counterfactuals
- Probability of Necessity: "Was this vuln NECESSARY for the threat to exist?"
- Probability of Sufficiency: "Is this vuln SUFFICIENT to cause the threat alone?"
- Effort: 4-6 weeks

---

## 6. NOTATION SUMMARY

| Symbol | Meaning |
|---|---|
| G_C | Set of base variables (findings) in posture category C |
| w(sᵢ) | Severity weight of finding i (Critical=1.0, High=0.7, Medium=0.4, Low=0.2) |
| K | Calibration constant (3.0 — three Critical findings = zero posture) |
| P_C | Posture score for category C (0=no control, 1=fully controlled) |
| E_S | Set of edge nodes relevant to STRIDE category S |
| do(X=x) | Intervention operator (force variable X to value x) |
| σ(x) | Sigmoid function: 1/(1+e^(-x)) |
| U | Exogenous (unobserved) variables in structural equations |
| ACE | Average Causal Effect |
| PN | Probability of Necessity |
| PS | Probability of Sufficiency |

---

## 7. KEY THEORETICAL REFERENCES

1. Pearl, J. (2009). *Causality: Models, Reasoning, and Inference*. Cambridge University Press.
2. Pearl, J., Glymour, M., & Jewell, N.P. (2016). *Causal Inference in Statistics: A Primer*. Wiley.
3. Schölkopf, B. et al. (2021). "Toward Causal Representation Learning." Proceedings of the IEEE.
4. Peters, J., Janzing, D., & Schölkopf, B. (2017). *Elements of Causal Inference*. MIT Press.
5. Hernán, M.A. & Robins, J.M. (2020). *Causal Inference: What If*. Chapman & Hall.
