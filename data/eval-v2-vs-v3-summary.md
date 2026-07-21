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
- **v2:** All threats attributed to global 'Architecture' (no boundary distinction)
- **v3:** Threats localized to specific boundaries: ['tb-dmz', 'tb-external', 'tb-internal']
- **Improvement:** v3 identifies WHERE the weakness exists, enabling targeted remediation

### Over-generalization avoidance
- **v2:** Global aggregation can overgeneralize: a single finding affects system-wide posture
- **v3:** Boundary-specific posture: findings affect only the boundary where they were observed. Other boundaries retain full posture.
- **Improvement:** v3 avoids false generalization of localized weaknesses to the entire system

### Confidence and uncertainty
- **v2:** No confidence tracking. All assessments presented with equal certainty.
- **v3:** Confidence tracked per layer. Single-source penalty (x0.7) applied. 0 source divergences flagged.
- **Improvement:** v3 communicates epistemic uncertainty, supporting risk-informed decisions

### Threat classification approach
- **v2:** Pure threshold on global posture (no architectural context considered)
- **v3:** Hybrid: ['rule_matched']. Rules combine posture weakness with architectural context (public-facing components, trust boundary crossings, sensitive data flows).
- **Improvement:** v3 threats are contextually grounded — posture weakness alone is insufficient; architectural exposure must also exist

### Worst-case boundary awareness
- **v2:** Simple severity-weighted average across all findings
- **v3:** Risk-averse aggregation: alpha=0.6 weighted avg + (1-alpha) worst-critical boundary. Validation worst=0.3 at tb-internal
- **Improvement:** v3 prevents dilution of severe local risk by safe internal boundaries

## Methodology Notes

- **traceability_depth:** Design-based measure (not runtime-computed). v2: finding→posture→STRIDE (2 abstractions). v3: finding→boundary_posture→fused_posture→STRIDE (4 abstractions).
- **classification_modes:** In this Juice Shop run, all v3 threats are rule_matched because architectural context (public-facing components, trust crossings, sensitive data) was strong enough to satisfy rule conditions for all triggered categories. Posture-derived mode would fire for categories where rules do not match (e.g., if no public-facing components existed for DoS, threshold-only assessment would apply).
- **threat_count_parity:** Equal threat count (5 v2, 5 v3) is expected because the same posture weaknesses trigger both engines. The improvement is in localization and confidence, not raw detection count.
- **rq1_claim:** Boundary-specific posture improves threat LOCALIZATION and REMEDIATION PRIORITIZATION over global posture. This evaluation does not claim improved raw detection recall.

## Limitations

- Single evaluation target (Juice Shop). Generalizability to enterprise applications needs validation.
- v3 primarily triggered rule-matched threats because architectural context was strong enough for all categories. A system without public-facing components would demonstrate posture-derived fallback.
- Traceability depth is a design-based measure, not a runtime-computed metric.
- Threat severity differences between v2 and v3 reflect different posture aggregation approaches rather than inherently better/worse detection.
- The evaluation uses the same fixture findings (7 SAST + 3 DAST). Real-world Semgrep/ZAP scans would produce more findings and potentially different boundary distributions.

## RQ1 Supported Claim

> Boundary-specific posture improves threat LOCALIZATION and REMEDIATION PRIORITIZATION over global posture.
> This evaluation demonstrates improved specificity, traceability, and uncertainty handling — not improved raw detection count.
