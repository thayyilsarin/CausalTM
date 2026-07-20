# CausalTM v2 vs v3 Evaluation — OWASP Juice Shop

## Inputs
- SAST findings: 7
- DAST findings: 3
- Components: 5
- Data flows: 4
- Trust boundaries: 3

## Comparison Table

| Metric | v2 | v3 | Improvement |
|---|---|---|---|
| Overall Risk | 0.364 | 0.265 | — |
| Total Threats | 5 | 5 | — |
| Boundary Specificity | Global | Per-boundary | Localization |
| Traceability Depth | 2 layers | 4 layers | +2 layers |
| Confidence Tracking | No | Yes | Uncertainty awareness |
| Fusion Layer | No | Yes | Multi-source reconciliation |
| Classification Method | Threshold only | Hybrid (rules + posture) | Contextual grounding |
| Worst-Case Aggregation | No | Yes (alpha=0.6) | Prevents dilution |

## STRIDE Posture Comparison

| Category | v2 | v3 |
|---|---|---|
| Denial of Service | 0.336 | 0.596 |
| Elevation of Privilege | 0.667 | 0.655 |
| Information Disclosure | 0.615 | 0.718 |
| Repudiation | 1.000 | 0.941 |
| Spoofing | 0.629 | 0.837 |
| Tampering | 0.572 | 0.661 |

## v3 Threats (with boundary localization)

| Category | Severity | Method | Boundaries | Confidence |
|---|---|---|---|---|
| Spoofing | Low | rule_matched | tb-external, tb-dmz | 0.72 |
| Tampering | Medium | rule_matched | tb-external, tb-dmz, tb-internal | 0.79 |
| Information Disclosure | Low | rule_matched | tb-external, tb-dmz, tb-internal | 0.72 |
| Denial of Service | Medium | rule_matched | tb-external, tb-dmz | 0.79 |
| Elevation of Privilege | Medium | rule_matched | tb-external, tb-dmz, tb-internal | 0.76 |

## RQ1 Evidence: Key Improvements

### Boundary localization
- **v2:** All threats attributed to 'Architecture' (global)
- **v3:** Threats localized to specific boundaries: ['tb-dmz', 'tb-external', 'tb-internal']
- **Improvement:** v3 tells you WHERE to fix, not just WHAT to fix

### Over-generalization avoidance
- **v2:** 1 SQLi finding reduces validation posture for entire system by 23%
- **v3:** 1 SQLi finding reduces validation posture ONLY at tb-internal by 23%. Other boundaries unaffected.
- **Improvement:** v3 avoids 'whole system is weak' false generalization

### Confidence and uncertainty
- **v2:** No confidence tracking. All assessments presented as equally certain.
- **v3:** Confidence tracked per layer. Single-source penalty applied. 0 divergences flagged.
- **Improvement:** v3 communicates uncertainty, enabling better decision-making

### Threat classification approach
- **v2:** Pure threshold on global posture
- **v3:** Hybrid: ['rule_matched']. Rules check architectural context (public-facing, trust crossing, sensitive data).
- **Improvement:** v3 threats are contextually grounded, not just threshold-derived

### Worst-case boundary awareness
- **v2:** Simple average across all findings
- **v3:** α=0.6 weighted avg + (1-α) worst-critical. Validation worst=0.3 at tb-internal
- **Improvement:** v3 prevents dilution of severe local risk by safe internal boundaries
