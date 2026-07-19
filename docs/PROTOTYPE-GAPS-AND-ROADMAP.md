# Prototype Gaps and Fix Roadmap

*Updated July 2026 — reflects CausalTM v2 architecture (federated causal model with base variables → effect edge nodes → STRIDE cream layer)*

This document captures known limitations and the prioritised plan to address them.

---

## 1. Posture Calibration and Validation (NEW — Critical for Credibility)

### Current State
The system computes "security posture" (0-1 score per control type) from a STATIC RULE BOOK hardcoded in Python. The calibration has NO empirical validation.

### What Exists (Static Rule Book)

| Component | Implementation | Source | Defensible? |
|---|---|---|---|
| CWE → Posture Type mapping | Python dict: ~20 CWEs mapped to 4 categories (auth, crypto, validation, logging) | Written manually from MITRE CWE descriptions | Partially — aligns with CWE consequences but only 20 of 900+ mapped |
| Keyword classification fallback | Python lists: ["auth", "login", "password"...] → auth type | Written manually | Weak — arbitrary keyword selection |
| Severity weights | `{Critical: 1.0, High: 0.7, Medium: 0.4, Low: 0.2}` | Chosen to align with CVSS ordinal ranking | Partially — ratio is reasonable but exact numbers unvalidated |
| max_deficit calibration | `3.0` (three Critical findings = zero posture) | Chosen to "seem reasonable" | Weak — no empirical basis |
| STRIDE thresholds | `{critical: 0.3, high: 0.5, medium: 0.7, low: 0.85}` | Chosen manually | Weak — no standard says "below 85% = Low threat" |
| Cross-layer rule strengths | `0.5 - 0.8` range | Educated guess | Weak — not empirically validated |

### Impact
- Posture percentages (e.g., "auth posture = 37%") have no validated meaning
- Thresholds for STRIDE threat generation are arbitrary
- Cross-layer predictions may over/under-estimate effects
- PAPER RISK: reviewers may challenge calibration validity

### Fix Plan

| Fix | Approach | Effort | Priority |
|---|---|---|---|
| Auto-generate CWE mapping from MITRE XML | Parse CWE `Common_Consequences` → map `Scope` to posture type automatically | 2 weeks | P1 |
| Expert panel for severity weights | Survey 10-15 security professionals: "3 Critical auth gaps = what posture %?" | 4-6 weeks | P2 (DBA evaluation) |
| Empirical threshold validation | Compare tool's STRIDE threats vs expert-produced threat models → calibrate thresholds | 4-6 weeks | P2 (DBA evaluation) |
| Cross-layer strength estimation | Before/after data: fix code auth → measure if runtime auth improved → estimate strength | Long-term | P3 |
| Industry standard alignment | Map posture calculation to NIST CSF / ISO 27001 control coverage metrics | 2 weeks | P2 |

### Mitigation for Paper
- Do NOT highlight "posture" as a headline/title concept
- Present posture as an implementation mechanism (methodology section), not as the contribution
- Acknowledge calibration as a limitation in the Discussion section
- Note that the RELATIVE ordering is correct (more severe findings → lower posture) even if absolute percentages are unvalidated

---

## 2. CWE Coverage (20 of 900+ Mapped)

### Current State (v2)
- CWE → Posture Type mapping covers ~20 CWEs explicitly
- Keyword fallback classifies findings without CWE IDs
- Unclassified findings default to "validation" type

### Gaps
| Gap | Impact | Severity |
|---|---|---|
| Only 20 CWEs mapped of 900+ | Many SAST findings cannot be classified into correct posture category | High |
| Keyword fallback is imprecise | May classify auth issues as validation (wrong STRIDE category) | Medium |
| Default to "validation" inflates validation gap count | Validation posture appears artificially low | Medium |

### Fix Plan
| Fix | Effort | Priority |
|---|---|---|
| Auto-sync from MITRE CWE XML (parse Consequences → posture type) | 2 weeks | P1 |
| Expand manual mapping to 50+ most common CWEs | 1 week | P1 |
| Improve keyword lists based on Semgrep rule naming conventions | 2 days | P1 |
| Add "unknown" posture type instead of defaulting to validation | 1 day | P1 |

---

## 3. Pearl's Causal Inference Formalism

### Current State (v2)
- Vulnerabilities as BASE VARIABLES causing posture EFFECTS (correct causal direction) ✓
- Severity-weighted deficit formula (linear, not probabilistic)
- Cross-layer propagation via fixed-strength rules ✓
- Bidirectional: forward (what-if) + backward (what to fix) ✓
- Roadmap to zero with deduplication ✓
- NO formal do-calculus, NO probabilistic inference, NO backdoor adjustment

### Gaps
| Gap | Impact | Severity |
|---|---|---|
| Linear deficit formula (not sigmoid structural equations) | Cannot claim formal SCM compliance | Medium |
| Fixed cross-layer strengths (not learned) | Predictions may be inaccurate | Medium |
| No probability distributions | Cannot express uncertainty | Medium |
| No backdoor adjustment for confounders | Posture may be inflated/deflated by unmodeled factors | Low (future) |

### Fix Plan
| Fix | Effort | Priority |
|---|---|---|
| Replace linear deficit with sigmoid: `posture = σ(-β₀ - Σ βᵢxᵢ)` | 2 weeks | P2 |
| Add confidence intervals to posture scores | 1 week | P2 |
| Implement truncated factorization for formal do-operator | 3 weeks | P3 |
| Backdoor adjustment when historical data available | 3 weeks | P3 |

---

## 4. DAST Integration

### Current State (v2)
- DAST sub-DAG implemented and tested with real ZAP data ✓
- ZAP scan runs in CI against live Juice Shop ✓
- 10 DAST findings correctly classified into runtime posture ✓
- Cross-layer effects from DAST observed ✓

### Remaining Gaps
| Gap | Impact | Severity |
|---|---|---|
| ZAP baseline only finds header/config issues (not injection/auth bypass) | DAST posture may look better than reality | Medium |
| Need authenticated ZAP scan for deeper coverage | Many Juice Shop challenges are behind login | Medium |
| DAST only optional — triggered when URL provided | Projects without running instances get no DAST posture | Design choice |

### Fix Plan
| Fix | Effort | Priority |
|---|---|---|
| Add ZAP full scan (not just baseline) with authentication | 2 days | P2 |
| Add ZAP AJAX Spider for SPA crawling (Juice Shop is Angular) | 1 day | P2 |
| Document that DAST-absent projects get "not observed" (not "secure") | Done ✓ | — |

---

## 5. Architecture Auto-Detection

### Current State
- Docker/Compose detector works
- Kubernetes detector works
- OpenAPI detector works
- Config detector (.env, appsettings) works
- Dependency detector works
- Code pattern detector works (keyword-based)
- NO Terraform/CloudFormation/Serverless detection

### Gaps (same as before)
- No cloud IaC (Terraform, CloudFormation)
- No serverless (Lambda, Functions)
- No service mesh (Istio, Linkerd)
- Monolith apps produce minimal/empty architecture

### Fix Plan
| Fix | Effort | Priority |
|---|---|---|
| Terraform detector | 2 weeks | P1 |
| Serverless Framework detector | 1 week | P1 |
| AWS SAM detector | 1 week | P2 |
| Generic auto-detection wired into v2 engine (no per-project scripts) | 1 week | P1 |

---

## 6. Report Quality

### Current State (v2)
- HTML report with: DFD, STRIDE threats (table), attack paths, Master DAG, counterfactual recommendations ✓
- Sub-graph SVGs generated (SAST, DAST, Repo) ✓
- Attack graph showing architectural topology ✓

### Remaining Gaps
| Gap | Impact | Severity |
|---|---|---|
| No roadmap-to-zero section in report (only in console + JSON) | Key output not visible to stakeholders | Medium |
| No PDF export | Some stakeholders need PDF | Low |
| No methodology explanation in report | Readers don't understand what posture means | Medium |
| Posture percentages shown without context ("37%" means what?) | Confusing to non-technical audience | Medium |

### Fix Plan
| Fix | Effort | Priority |
|---|---|---|
| Add roadmap section to HTML report | 1 day | P2 |
| Add methodology explanation ("how to read this report") | 2 hours | P2 |
| Add posture interpretation guide ("0-30% = Critical gap, 30-50% = High gap...") | 1 hour | P2 |
| PDF export via WeasyPrint | 1 day | P3 |

---

## 7. Generic Execution (No Per-Project Scripts)

### Current State
- `eval_juice_shop.py` has hardcoded Juice Shop architecture
- Each new project would need a custom eval script
- v2 engine IS generic — but the eval script wrapping it is project-specific

### Gap
The v2 engine accepts `(component_graph, sast_findings, dast_findings)` generically. But:
- `component_graph` currently comes from hardcoded Python dict (for Juice Shop)
- Should come from the auto-detection analyzer

### Fix Plan
| Fix | Effort | Priority |
|---|---|---|
| Wire analyzer engine output into v2 engine (component_graph auto-generated from repo) | 1 week | P1 |
| Create generic CLI: `causaltm scan --repo URL --sast file.sarif --dast file.xml` | 1 week | P1 |
| Remove all per-project eval scripts (replace with single generic pipeline) | 2 days | P1 |

---

## Phased Delivery Plan (Updated for v2)

### Phase 0: Paper-Ready (CURRENT — mostly complete)

| Task | Status |
|------|--------|
| v2 Federated engine (base vars → posture → STRIDE) | ✅ Done |
| SAST sub-DAG with severity-weighted posture | ✅ Done |
| DAST sub-DAG with runtime posture | ✅ Done |
| Repo sub-DAG with structural posture | ✅ Done |
| Master DAG with cross-layer rules + roadmap | ✅ Done |
| STRIDE cream layer with 6-category evaluation | ✅ Done |
| Bidirectional propagation (forward + backward) | ✅ Done |
| CWE tracing from base variables to STRIDE threats | ✅ Done |
| Juice Shop evaluation with real SAST + DAST | ✅ Done |
| DFD + sub-graph + master DAG rendering | ✅ Done |
| HTML report with all sections | ✅ Done |
| Ground truth comparison (15 challenges) | ✅ Done (53% match) |
| Generic auto-detection (no hardcoded architecture) | ❌ Not done |

### Phase 1: Solid Foundation (Weeks 1-4)

| Task | Effort |
|------|--------|
| Wire auto-detection into v2 (generic execution) | 1 week |
| Expand CWE mapping to 50+ (from MITRE CWE XML) | 1 week |
| Terraform detector | 2 weeks |
| NIST/ISO alignment documentation for posture | 1 week |

### Phase 2: DBA Evaluation (Weeks 5-12)

| Task | Effort |
|------|--------|
| Expert panel for posture calibration | 4-6 weeks |
| Evaluate on 10+ diverse projects | 4 weeks |
| Sigmoid structural equations | 2 weeks |
| Formal do-calculus approximation | 3 weeks |

### Phase 3: Production (Weeks 13-24)

| Task | Effort |
|------|--------|
| Full Pearl Level 3 counterfactuals | 4 weeks |
| Cross-layer strength learning from data | 4 weeks |
| Web UI for interactive what-if | 6 weeks |
| PDF reports + executive summary | 2 weeks |

---

## Summary: What IS Solid vs What IS NOT

| Solid (Can Claim in Paper) | Not Solid (Don't Highlight) |
|---|---|
| Federated architecture (3 sub-DAGs + master + STRIDE cream) | Specific posture percentages ("37% auth posture") |
| Vulnerabilities as base variables causing effects (causal direction) | Calibration constants (max_deficit=3.0, threshold=0.85) |
| Cross-layer dependency rules (fixing one layer affects another) | Cross-layer strength numbers (0.5-0.8) |
| Bidirectional propagation (forward + backward) | "Posture" as a validated metric |
| STRIDE evaluation from architectural posture gaps | Exact severity weight ratios |
| Sequenced roadmap (no duplicates, cross-layer aware) | Ground truth match percentage (53% — needs improvement) |
| No training data required | CWE coverage completeness |
| Works on any project with SARIF + ZAP XML + repo | Auto-detection accuracy (untested for most app types) |
