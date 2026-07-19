# Federated Causal AI vs. Traditional Correlation-Based AI

*Updated to reflect CausalTM v2 architecture (posture-based, STRIDE cream layer)*

## The Three Questions

1. **Is this approach better than traditional correlation-based AI models?**
2. **Does this avoid data dependency and drift problems?**
3. **Is it more reusable compared to traditional approaches?**

---

## Question 1: Is Federated Causal AI Better Than Correlation-Based AI?

### What is "Traditional Correlation-Based AI" in This Context?

A correlation-based AI model for security would typically be:
- A machine learning classifier (Random Forest, XGBoost, Neural Network)
- Trained on historical data (past vulnerabilities, past incidents)
- Learns statistical patterns: "when X appears, Y usually also appears"
- Outputs: probability scores, risk classifications, ranked vulnerability lists

Examples: EPSS (Exploit Prediction Scoring System), ML-based SAST prioritisation, anomaly detection for intrusion, automated severity classification.

### The Fundamental Difference

| Aspect | Correlation-Based AI | CausalTM v2 (Ours) |
|--------|---------------------|---------------------------|
| **Core question** | "Which vulnerabilities are likely to be exploited?" | "What architectural controls are missing and what STRIDE threats exist by design?" |
| **Logic** | Pattern matching from historical data | Posture assessment from current state + causal mechanism reasoning |
| **Input** | Features extracted from vulnerability metadata | Security posture extracted from SAST/DAST/Repo as architectural state |
| **Output** | Ranked vulnerability list with probability scores | STRIDE threat model + sequenced remediation roadmap to zero risk |
| **Reasoning level** | Associational (Level 1 of Pearl's hierarchy) | Interventional + Counterfactual (Levels 2-3) |
| **Direction** | Cannot distinguish cause from effect | Explicit causal direction through DAG edges |
| **Counterfactual** | Cannot answer "what if we fix X?" | Core capability with cross-layer effect prediction |
| **Architecture awareness** | None — treats vulns as independent items | Central — evaluates the DESIGN, not individual bugs |

### Why Posture-Based Causal Is Better FOR STRIDE Threat Modeling

#### 1. STRIDE Is About Architecture, Not Vulnerability Statistics

STRIDE asks: "Can identity be spoofed at this trust boundary?" — regardless of whether any specific spoofing vulnerability has been found. A correlation model trained on past vulnerabilities cannot answer this. Our system computes authentication posture from available evidence (SAST: auth patterns in code + DAST: auth enforcement at runtime + Repo: auth requirements at boundaries) and determines whether the architecture is vulnerable to spoofing by design.

```
Correlation AI:  "You have 5 auth-related CVEs → probability of auth breach = 0.73"
CausalTM v2:    "Auth posture = 37% (3 Critical gaps found) → Spoofing THREAT exists
                  because the architecture lacks authentication at 2 of 3 trust boundaries.
                  Fix: Add auth to Frontend→Backend boundary (cross-layer: also fixes
                  DAST runtime_auth from 60% to ~85%)"
```

#### 2. Severity-Weighted Posture vs. Flat Counting

Correlation models typically use vulnerability counts as features. Our system uses severity-weighted posture:

```
Correlation approach: 10 Medium + 1 Critical = 11 features (equally weighted in training)
Our approach:         10 Medium (weight 4.0) + 1 Critical (weight 1.0) = deficit 5.0
                      Critical matters MORE because it represents complete control failure
                      
Result: Our system correctly identifies that one Critical auth bypass is worse
        than ten Medium informational findings — without needing training data to learn this.
```

#### 3. Cross-Layer Effect Prediction (Impossible with Correlation)

A correlation model processes each finding independently. It cannot predict:

> "Fixing input validation in code (SAST layer) will also reduce the attack surface at runtime (DAST layer) by strength 0.5"

Our cross-layer dependency rules make this prediction explicit:

| Trigger (fixed) | Cross-layer Effect | Strength |
|---|---|---|
| Code auth posture improves | Runtime auth enforcement improves | 0.7 |
| Code validation improves | Runtime attack surface decreases | 0.5 |
| Architecture adds defense layers | Runtime attack surface decreases | 0.6 |

This means a single code fix can be correctly valued for its TOTAL impact across layers — something no correlation model can compute.

#### 4. Sequenced Roadmap (vs. Flat Priority List)

| Correlation AI Output | CausalTM v2 Output |
|---|---|
| "Fix these 23 vulnerabilities in this order: #1, #2, #3..." | "Step 1: Reduce topology exposure (Repo fix) — this also reduces DAST attack surface via cross-layer rule. Step 2: Add input validation (SAST fix) — this further reduces attack surface. Step 3: Add defense-in-depth..." |
| Each fix evaluated in isolation | Each fix evaluated in context of what's already been fixed |
| No awareness that fix #5 becomes unnecessary if fix #2 is done | Explicitly tracks: "Step 2's cross-layer effect eliminates the need for Step 5" |

#### 5. Graceful Handling of Missing Data

| Situation | Correlation AI | CausalTM v2 |
|---|---|---|
| No DAST scan available | Model expects all features → degrades or fails | DAST edge nodes exist with value=0, strength=0 (not observed). System works with SAST + Repo only. Can still answer: "What WOULD risk be if DAST found issues?" |
| New project, no history | Cannot predict (cold start) | Computes posture from current scan immediately |
| One layer has no findings | Feature columns are zero → model confused | That layer's posture = 1.0 (no gaps found = secure posture). Other layers still contribute. |

### Summary: When Is Each Better?

| Scenario | Correlation AI Wins | CausalTM v2 Wins |
|----------|--------------------|--------------------|
| Large historical dataset, need statistical patterns | ✓ | |
| Novel application, no history | | ✓ |
| Need to explain WHY a threat exists | | ✓ |
| Need sequenced remediation with cross-layer awareness | | ✓ |
| Anomaly detection (unusual runtime behaviour) | ✓ | |
| Architecture-level STRIDE threat identification | | ✓ |
| Real-time streaming data classification | ✓ | |
| Strategic planning ("where should we invest?") | | ✓ |
| Compliance (need deterministic, auditable reasoning) | | ✓ |

---

## Question 2: Does This Avoid Data Dependency and Drift Problems?

### Data Dependency: ELIMINATED for Core Reasoning

| Problem | Correlation AI | CausalTM v2 |
|---------|---------------|---------------------|
| "Never seen CWE-1234 before" | Can't classify → unknown risk | Classified by keyword if CWE unknown; maps to posture type (auth/crypto/validation/logging) |
| "No breach history for this app" | No labels → can't train → can't predict | Doesn't need history: posture computed from current scan immediately |
| "Only 1 finding of this type" | Statistically insignificant → ignored | 1 Critical finding brings posture down by 33% (severity-weighted — one finding CAN matter) |
| "New technology stack" | Retrain on new features | Detectors find manifests → same posture calculation applies |
| "No DAST scan performed" | Missing features → model breaks | DAST edge nodes marked "not observed" → other layers still work → counterfactual "what if DAST found X?" still answerable |

**Why?** Because our system computes POSTURE from whatever evidence is available. Posture is:
- **Presence-based:** "Do auth controls exist here? Yes/No → posture score"
- **Severity-weighted:** "How bad are the gaps that DO exist?"
- **Not count-dependent:** One Critical gap matters more than ten Low gaps

A correlation model needs VOLUME of data to find patterns. We need CURRENT STATE to assess posture.

### Data Drift: SIGNIFICANTLY REDUCED

| Drift Type | Correlation AI Impact | CausalTM v2 Impact |
|-----------|----------------------|---------------------------|
| **New attack techniques** | Model misses them until retrained | If the attack exploits an auth gap → auth posture already reflects the architectural weakness, regardless of whether this specific technique existed when rules were written |
| **New SAST tool version** | Features change → retrain | Only SAST sub-DAG ingests new format. Edge nodes (posture scores) stay the same interface. Master DAG unaffected. |
| **New technology stack** | Retrain entirely | Add new architecture detector → Repo sub-DAG produces same 4 edge nodes. Everything else works. |
| **Changing severity standards** | Model learned old standards | Update severity_weights dict: `{Critical: 1.0, High: 0.7, Medium: 0.4, Low: 0.2}`. One line change, no retraining. |
| **Organisation changes** | Model trained on old org | Repo sub-DAG rebuilds from current infrastructure files automatically. |

**What DOES drift in our system (honest):**
- Severity weight calibration (`max_deficit = 3.0`) — may need tuning if typical finding distributions change
- Keyword classification list — new rule naming patterns may not match existing keywords
- Cross-layer rule strengths — the 0.7 strength for "code auth → runtime auth" is expert-specified

But these are **transparent, human-readable parameters** in Python/YAML — not opaque model weights requiring GPU retraining.

### The Federated Architecture Adds Drift Resilience

```
Correlation AI when drift occurs:
  ENTIRE model is suspect → retrain everything → weeks of GPU time + data collection

CausalTM v2 when drift occurs:
  Only the AFFECTED sub-DAG needs adjustment:
  - New SAST tool? → Only sast_subdag.py classification logic updates
  - New architecture pattern? → Only repo_subdag.py detection logic updates
  - New STRIDE threshold? → One number in stride_layer.py
  
  Master DAG structure: UNCHANGED (cross-layer rules are architectural truths)
  Other sub-DAGs: UNCHANGED (independent by design)
  STRIDE evaluation: UNCHANGED (architectural threats don't shift with tooling)
```

---

## Question 3: Is It More Reusable Than Traditional Approaches?

### Reusability at Three Levels

#### Level 1: Across Organisations (Zero Adaptation)

| Scenario | Correlation AI | CausalTM v2 |
|---|---|---|
| Deploy at Company A | Retrain on their vulnerability history (3-6 months) | Run immediately: ingest their SARIF + ZAP XML + repo. Same posture calculation. Same STRIDE evaluation. |
| Deploy at Company B (different industry) | Retrain again (different patterns) | Same engine. Different findings → different posture scores → different STRIDE threats. No adaptation needed. |
| Different security maturity | Model tuned to one maturity level | Lower maturity = more gaps = lower posture = more STRIDE threats. Automatic. |

#### Level 2: Across Technology Stacks (Same Engine)

CausalTM v2 is technology-agnostic at the posture level:

```
Java app with Spring Security:
  SAST finds CWE-89 (injection) → posture_type = "validation" → validation_posture affected
  
Node.js app with Express:
  SAST finds CWE-89 (injection) → posture_type = "validation" → validation_posture affected
  
Same posture calculation. Same STRIDE evaluation. Same roadmap logic.
The TECHNOLOGY doesn't matter — the POSTURE does.
```

#### Level 3: Adding New Data Sources (Modular Extension)

```
SCENARIO: Add Terraform/Cloud IaC analysis

Correlation AI:
  1. Define new features from .tf files
  2. Collect thousands of labeled examples (Terraform configs + breach outcomes)
  3. Retrain entire model with new feature columns
  4. Validate on holdout set
  5. Deploy new model version
  Effort: 3-6 months

CausalTM v2:
  1. Create new sub-DAG: terraform_subdag.py
  2. Define edge nodes: iam_posture, network_isolation_posture, encryption_at_rest_posture
  3. Define cross-layer rules: "iam_posture improves → auth posture improves"
  4. Plug into Master DAG (edge node interface is standard)
  Effort: 1-2 weeks. No retraining. No historical data needed.
```

### The Posture-Based Edge Node Interface Enables Reusability

The key to reusability is the **edge node contract**:

```python
class ArchitecturalEdgeNode:
    id: str           # Standard naming: "layer.posture_name"
    value: float      # Always 0.0 to 1.0 (normalised posture)
    causal_strength: float  # How strongly this influences STRIDE
    stride_relevance: list[str]  # Which STRIDE categories this affects
    observed: bool    # Whether this layer actually ran
```

ANY sub-DAG that produces conformant edge nodes can participate. The Master DAG and STRIDE layer don't care HOW the posture was computed — only that it's normalised and carries STRIDE relevance metadata. This is analogous to API contracts in microservices: stable interface, independent implementation.

### Partial Data Tolerance

```
All three inputs available:
  SAST (4 edge nodes) + DAST (4 edge nodes) + Repo (4 edge nodes) = full picture

Only SAST + Repo (no DAST):
  SAST (4 edge nodes) + DAST (4 edge nodes, all zero, not observed) + Repo (4 edge nodes)
  = Partial picture, but STRIDE still evaluates from available posture
  = Result is CONSERVATIVE (less confident) but still VALID

Only Repo (no scans at all):
  SAST (not observed) + DAST (not observed) + Repo (4 edge nodes from architecture)
  = ARCHITECTURE-ONLY threat model — still identifies design-level STRIDE threats
  = This is exactly what manual STRIDE does (no scans needed, just architecture review)
```

---

## Summary: Three Questions Answered

### 1. Is Federated Causal AI better than correlation-based AI?

**Yes, for architectural threat modeling.** Correlation models count and rank vulnerabilities. CausalTM v2 assesses architectural security posture and identifies STRIDE threats from design gaps. The key differentiators:
- Posture-based (not count-based) — aligns with what STRIDE actually evaluates
- Cross-layer prediction — one fix's impact across all layers, predicted before applying
- Sequenced roadmap — optimal fix order with cumulative effect tracking
- Counterfactual reasoning — "what if?" questions answerable without historical data

### 2. Does it avoid data dependency and drift?

**Largely yes.**
- **Data dependency eliminated:** Posture computed from current scan state, not learned from history
- **Drift localised:** Only affected sub-DAG needs adjustment; master structure is stable
- **Parameters are transparent:** Severity weights, thresholds, and cross-layer strengths are human-readable numbers, not opaque model weights
- **Honest caveat:** Calibration values (max_deficit, STRIDE thresholds) are expert-specified and may need empirical validation

### 3. Is it more reusable?

**Significantly yes.**
- Cross-organisation: works immediately without adaptation (posture calculation is universal)
- Cross-technology: same engine regardless of language or framework (posture is tech-agnostic)
- Composable: new data sources added via new sub-DAGs with standard edge node interface
- Gracefully degrades: missing layers don't break the system, just reduce confidence
- Architecture-only mode: produces valid STRIDE threats even without SAST/DAST (same as manual TM)

---

## For the DBA Dissertation / Book

This comparison positions the contribution clearly:

> "We do not claim that causal AI replaces machine learning universally. Rather, we demonstrate that for the specific problem of STRIDE-based architectural threat modeling — where the question is 'what can go wrong with this design?' rather than 'which vulnerabilities will be exploited?' — a posture-based Federated Structural Causal Model provides capabilities that correlation-based approaches structurally cannot: cross-layer effect prediction, sequenced remediation planning, and design-level threat identification independent of specific vulnerability existence."

This is a defensible, nuanced claim that acknowledges ML's strengths in other domains while demonstrating clear superiority for THIS specific problem.
