# CausalTM v2 vs v3 Evaluation — OWASP Juice Shop (Full)

**Last updated:** July 2026 (reflects full 23+10 evaluation with Repo sub-DAG)

## Inputs (Same for Both Engines)
- SAST findings: 23 (Semgrep p/javascript + p/nodejs)
- DAST findings: 10 (OWASP ZAP baseline scan)
- Components: 6
- Data flows: 5
- Trust boundaries: 3

## Comparison Table

| Metric | v2 (Global) | v3 (Boundary-Specific) | Improvement |
|---|---|---|---|
| Overall Risk | 0.431 (Medium) | 0.404 (Medium) | Less over-generalization |
| Total Threats | 6 | 6 | Same coverage |
| Roadmap Steps | 8 | 4 | 50% more efficient (boundary-targeted) |
| Boundary Specificity | Global | Per-boundary (4 assessed) | Localization |
| Sources Used | SAST + DAST | SAST + DAST + Repo | +structural assessment |
| Traceability Depth | 2 layers | 4 layers | +2 abstraction layers |
| Confidence Tracking | None | Yes (avg 68%) | Uncertainty awareness |
| Uncertain Divergences | N/A | 5 flagged | Multi-source conflict detection |
| Fusion Layer | None | Yes (worst-case adjusted, alpha=0.6) | Prevents dilution |
| Classification Method | Threshold only | Hybrid (5 rule-matched + 1 posture-derived) | Contextual + fallback |

## STRIDE Posture Comparison

| Category | v2 | v3 | Delta | Interpretation |
|---|---|---|---|---|
| Denial of Service | 0.353 | 0.541 | +0.188 | v3 avoids global crash from localized findings |
| Tampering | 0.563 | 0.571 | +0.008 | Similar |
| Spoofing | 0.571 | 0.613 | +0.042 | Repo adds positive structural signal |
| Information Disclosure | 0.592 | 0.590 | −0.002 | Nearly identical |
| Elevation of Privilege | 0.602 | 0.555 | −0.047 | Repo found unauthenticated exposure |
| Repudiation | 0.733 | 0.705 | −0.028 | Repo detected logging gap |

## v3 Fused Architectural Postures (with Boundary Detail)

| Control Category | Posture | Confidence | Worst Critical Boundary | Boundary ID |
|---|---|---|---|---|
| Validation | 52.1% | 59% | 37.6% | tb-internal |
| Auth | 59.0% | 59% | 53.3% | tb-internet |
| Crypto | 64.7% | 72% | 53.8% | tb-internal |
| Logging | 75.4% | 80% | 72.0% | tb-internal |

## v3 Threats (with Boundary Localization)

| Category | Severity | Method | Boundaries | Confidence |
|---|---|---|---|---|
| Spoofing | Medium | rule_matched | tb-internet, tb-dmz | 68% |
| Tampering | Medium | rule_matched | tb-internet, tb-dmz, tb-internal | 68% |
| Information Disclosure | Medium | rule_matched | tb-internet, tb-dmz, tb-internal | 83% |
| Denial of Service | Medium | rule_matched | tb-internet, tb-dmz | 68% |
| Elevation of Privilege | Medium | rule_matched | tb-internet, tb-dmz, tb-internal | 68% |
| Repudiation | Low | posture_derived | tb-dmz, tb-internal, tb-internet | 80% |

## v3 Remediation Roadmap (4 Steps to Zero Risk)

| Step | Fix | Boundary | Current → Target | Risk Reduction |
|---|---|---|---|---|
| 1 | Fix input validation | tb-internal | 52% → 100% | −0.180 |
| 2 | Fix authentication | tb-internet | 59% → 100% | −0.116 |
| 3 | Fix encryption | tb-internal | 65% → 100% | −0.080 |
| 4 | Fix audit logging | tb-internal | 75% → 100% | −0.029 |

## v3 What-If Analysis

| Intervention | Risk Before | Risk After | Reduction |
|---|---|---|---|
| Fix all validation issues | 0.404 | 0.224 | −0.180 (45%) |
| Fix all authentication issues | 0.404 | 0.288 | −0.116 (29%) |

## v3 Attack Paths

| Score | Path | Hops |
|---|---|---|
| 0.750 | Angular Frontend → REST API Backend | 1 |
| 0.750 | Internet User → Angular Frontend | 1 |
| 0.530 | Internet User → Angular Frontend → REST API Backend | 2 |
| 0.513 | Angular Frontend → REST API Backend → SQLite Database | 2 |
| 0.500 | Administrator → REST API Backend | 1 |

## RQ1 Evidence: Key Improvements

### 1. Over-generalization Avoidance (DoS Case)
- **v2:** DoS posture = 0.353 (Critical) — all validation findings globally reduce posture
- **v3:** DoS posture = 0.541 (Medium) — findings localized to tb-internal, other boundaries retain posture
- **Evidence:** Same findings, but v3's boundary-specific aggregation avoids catastrophic global assessment

### 2. Roadmap Efficiency
- **v2:** 8 steps (broad system-wide recommendations)
- **v3:** 4 steps (targeted: "fix validation AT tb-internal", "fix auth AT tb-internet")
- **Evidence:** Boundary localization enables 50% more efficient remediation sequencing

### 3. Hybrid STRIDE Classification
- **v2:** All 6 threats are threshold-only (posture < threshold → threat)
- **v3:** 5 rule-matched (posture + architectural context required) + 1 posture-derived (Repudiation)
- **Evidence:** Both modes operate in practice; Repudiation demonstrates fallback mechanism

### 4. Multi-Source Enrichment (Repo Sub-DAG)
- **v2:** Only SAST + DAST signals
- **v3:** SAST + DAST + Repo structural assessment (3 sources)
- **Evidence:** Repo detected unencrypted internal flows (crypto 0.87→0.65), unauthenticated public components (auth 0.77→0.59), logging gaps (newly visible)

### 5. Uncertainty Tracking
- **v2:** No divergence detection; all assessments equally certain
- **v3:** 5 uncertain divergences flagged where SAST/DAST/Repo disagree
- **Evidence:** Epistemic uncertainty is communicated, not hidden

## Methodology Notes

- **Traceability depth:** Design-based measure. v2: finding→posture→STRIDE (2). v3: finding→boundary_posture→fused_posture→STRIDE (4).
- **Classification modes:** Repudiation is posture-derived because no rule pattern requires public-facing logging exposure. All other categories satisfied rule conditions (posture weakness + architectural context).
- **Threat count parity:** Equal count (6 each) is expected — same weaknesses trigger both engines. Improvement is in localization, efficiency, and confidence, not raw detection.
- **Repo sub-DAG:** Derives posture from component graph structure alone (no external findings needed). Assesses auth on public components, flow encryption, defense depth, logging presence.
- **Worst-case aggregation:** alpha=0.6 weighted average + 0.4 worst-critical-boundary. Ensures severe local risk at external boundaries is not diluted.

## Limitations

- Single evaluation target (Juice Shop). Enterprise generalizability needs validation.
- Repo sub-DAG uses heuristic structural assessment (not formal verification).
- v3 primarily triggers rule-matched threats when architectural context is rich. Systems with less clear architecture would show more posture-derived threats.
- Traceability depth is a design-based measure, not a runtime metric.
- Severity differences reflect aggregation approach differences, not detection quality differences.
- 23+10 findings are production-representative but not from a live CI scan in this evaluation.

## RQ1 Supported Claim

> **Boundary-specific posture improves threat LOCALIZATION and REMEDIATION PRIORITIZATION over global posture.**

This evaluation demonstrates:
- Improved localization (WHERE, not just WHAT)
- Improved efficiency (4 vs 8 roadmap steps)
- Hybrid classification (both modes demonstrated)
- Multi-source enrichment (3 sources vs 2)
- Explicit uncertainty tracking (5 divergences flagged)
- Same threat coverage (no detection loss)
