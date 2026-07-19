# A Federated Structural Causal Model for Automated STRIDE Threat Modeling from Multi-Source Security Intelligence

**[Author Name]**
Rushford Business School

---

## Abstract

Threat modeling remains largely manual despite the availability of rich automated security data. This paper introduces CausalTM, a framework that automates STRIDE-based architectural threat modeling through a five-layer Federated Structural Causal Model. Three domain-specific causal sub-graphs extract security posture from static analysis reports, dynamic analysis findings, and repository architecture respectively. Each sub-graph computes severity-weighted posture scores representing the state of security controls rather than counting vulnerabilities. These posture scores feed a master directed acyclic graph that applies cross-layer dependency rules and supports bidirectional propagation — predicting both the impact of a fix and what must be fixed to achieve a target posture. A STRIDE evaluation layer sits above the master DAG, identifying architectural threats from posture gaps without requiring any specific vulnerability to exist. We evaluate the prototype against OWASP Juice Shop using real Semgrep static analysis (23 findings) and real OWASP ZAP dynamic analysis (10 findings). The system identifies threats across all six STRIDE categories, computes a severity-weighted overall risk of 0.462, and generates a sequenced remediation roadmap of 11 steps toward zero risk — each step accounting for cross-layer side effects. These results demonstrate that posture-based causal reasoning produces actionable architectural threat intelligence that vulnerability-centric tools and correlation-based machine learning cannot provide.

**Keywords:** causal inference, STRIDE, federated structural causal model, threat modeling, cybersecurity, architectural security posture, counterfactual analysis, OWASP Juice Shop

---

## I. Introduction

Software teams that deploy changes several times a day cannot wait weeks for a threat model. The economics are prohibitive: industry estimates place the cost of a single manual threat modeling exercise between fifteen and fifty thousand US dollars, requiring specialised expertise that most organisations lack in sufficient quantity [1]. Meanwhile, the consequences of forgoing the practice are well documented — the average data breach now costs USD 4.88 million and takes 277 days to identify and contain [2].

The STRIDE framework, developed at Microsoft in 1999, remains the prevailing method for classifying application-level threats [3]. Its strength lies in its focus on architectural design: by examining system topology, data flows, and trust boundaries against six threat categories — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege — an analyst identifies threats that exist by design, regardless of whether any specific vulnerability has been discovered yet [4]. The weakness is that both the diagram construction and the threat analysis remain human-driven activities [5].

Modern development pipelines produce considerable security intelligence automatically. Static analysis tools report code-level weaknesses. Dynamic analysis tools confirm exploitability against running applications. Container manifests, API specifications, and environment configurations document system architecture in machine-readable form. The gap is not in data availability but in the absence of a reasoning layer that can synthesise these sources into an architectural understanding suitable for STRIDE analysis.

Machine learning has been proposed for vulnerability prioritisation [6], but these approaches count and rank vulnerabilities rather than reasoning about architecture. They cannot answer the question a STRIDE analysis actually asks: "Given this design, what can go wrong?" — a question about structure, not about individual bugs. They also require historical data [7], cannot answer interventional questions [8], and degrade as patterns shift [9].

This paper proposes a fundamentally different approach. Rather than counting vulnerabilities, we extract architectural security posture from each data source. Rather than applying rules to individual components, we evaluate the complete architecture against STRIDE as a holistic assessment. Rather than producing a flat threat list, we generate a sequenced remediation roadmap that accounts for cross-layer side effects. The framework, termed CausalTM, employs a five-layer Federated Structural Causal Model:

1. Input sources (SAST reports, DAST reports, source repository) are consumed by ingestors.
2. Three domain-specific sub-DAGs extract security posture (not vulnerability counts) as severity-weighted scores.
3. A master DAG combines posture scores with cross-layer dependency rules and supports bidirectional propagation.
4. A STRIDE evaluation layer identifies architectural threats from posture gaps across all six categories.
5. A remediation roadmap sequences fixes for maximum cross-layer impact toward zero risk.

The contributions of this work are fourfold:

1. A posture-based causal architecture where sub-graphs compute severity-weighted security posture (authentication, encryption, validation, logging) rather than counting vulnerabilities — making threat identification independent of specific findings.
2. Cross-layer dependency rules that predict how fixing an issue in one layer (code, runtime, architecture) affects posture in other layers.
3. A STRIDE evaluation layer that sits above the causal model and identifies architectural threats from posture gaps with multi-layer evidence and automated CWE tracing.
4. A prototype evaluation against OWASP Juice Shop with real SAST and DAST data demonstrating posture-based threat identification and sequenced remediation planning.

---

## II. Related Work

### A. Automated Threat Modeling

Tools such as Microsoft's Threat Modeling Tool, OWASP Threat Dragon, and PyTM [10] reduce the mechanical burden of threat enumeration once a system model exists. However, every tool in this category requires a human analyst to construct the model manually. No existing tool extracts architecture directly from source code repositories or deployment configurations [5]. Tuma et al. [4] confirm in their systematic literature review that this architecture extraction step remains the principal unsolved bottleneck.

### B. Vulnerability Prioritisation via Machine Learning

The Exploit Prediction Scoring System (EPSS) applies logistic regression to historical exploitation data [6]. Other researchers have employed random forests and deep learning for severity prediction [11]. These systems rank vulnerabilities by exploitation likelihood, but they operate at the associational level. They cannot perform the architectural reasoning that STRIDE requires — asking whether a design permits spoofing, regardless of whether any spoofing vulnerability has been found yet.

### C. Causal Inference in Cybersecurity

Pearl's framework [8] distinguishes three levels of inference: associational, interventional, and counterfactual. Recent work applies causal methods to intrusion detection [12] and incident root cause analysis [13], but no published research applies causal inference to application-level threat modeling. The present work fills this gap by using causal sub-graphs to represent architectural posture and a master DAG for cross-layer interventional reasoning.

### D. Modular and Composable Causal Models

Scholkopf et al. [14] argue that independent causal mechanisms can be combined without mutual interference. This theoretical result supports our federated architecture. However, we extend beyond full independence by introducing cross-layer dependency rules — acknowledging that in security, fixing code may affect what is observable at runtime, violating strict mechanism independence in a predictable, modelable way.

---

## III. Proposed Architecture

### A. Design Philosophy: Posture, Not Vulnerability Counts

Traditional security tools count vulnerabilities: "you have 23 findings." CausalTM instead asks: "what is the state of your security controls?" A system with 23 low-severity findings in well-defended areas may be safer than one with 3 critical findings at unprotected trust boundaries. By computing posture — the degree to which security controls are implemented and effective — we align the analysis with what STRIDE actually evaluates: architectural adequacy.

### B. Sub-DAGs: Extracting Posture from Each Source

Each sub-DAG produces four severity-weighted posture scores (edge nodes) representing the effect of base variables (individual findings) on architectural security state.

**SAST Sub-DAG** answers: "What security controls exist in the code?"

Findings are classified by CWE into four posture categories (authentication, cryptography, input validation, audit logging). When CWE identifiers are unavailable — common with pattern-based tools like Semgrep — the system classifies findings by keyword analysis of rule titles. Posture is computed using severity-weighted deficit:

*posture = max(0, 1.0 - (Σ severity_weight_i / calibration))*

where severity weights are Critical=1.0, High=0.7, Medium=0.4, Low=0.2, and calibration is set to 3.0 (three Critical findings bring posture to zero). This makes the calculation defensible: a single Critical authentication bypass reduces posture more than three Medium informational findings combined.

**DAST Sub-DAG** answers: "Are controls actually enforced at runtime?"

DAST findings carry higher causal strength (0.85-0.9) than SAST because they represent proven runtime behaviour. When DAST has not been performed, edge nodes exist with zero values and zero causal strength — preserving the graph structure for counterfactual queries while contributing nothing to current risk.

**Repo Sub-DAG** answers: "What is the structural design?"

Architecture is extracted from Docker manifests, Kubernetes configurations, API specifications, and environment files. Posture scores capture topology exposure, data sensitivity, trust boundary integrity, and defense-in-depth — properties that exist independent of any vulnerability.

### C. Master DAG: Cross-Layer Reasoning

The master DAG receives 12 edge nodes (4 per sub-DAG), adds 6 STRIDE posture intermediate nodes and 1 overall risk node, and connects them via cross-layer dependency rules.

Six dependency rules capture how interventions in one layer predict effects in others:

| Trigger | Effect | Strength |
|---------|--------|----------|
| Code auth improves | Runtime auth improves | 0.7 |
| Code crypto improves | Runtime encryption improves | 0.6 |
| Code validation improves | Attack surface decreases | 0.5 |
| Architecture adds defense | Attack surface decreases | 0.6 |
| Topology exposure decreases | Attack surface decreases | 0.8 |
| Boundary integrity improves | Information leakage decreases | 0.5 |

These rules enable the system to predict: "If you fix input validation in code (SAST layer), the attack surface at runtime (DAST layer) will also decrease — you get two improvements from one fix."

### D. STRIDE Layer: The Cream

STRIDE sits above the master DAG and evaluates posture scores against threshold criteria for each category. A threat is generated when posture falls below the threshold (0.85 for Low severity, 0.7 for Medium, 0.5 for High, 0.3 for Critical). Each threat carries:

- Multi-layer evidence (what SAST, DAST, and Repo each contribute)
- Corroboration count (how many layers agree the threat exists)
- Traced CWE identifiers (automatically mapped from base variables)
- Three-level remediation (architecture fix, code fix, runtime verification)

### E. Remediation Roadmap

The system iteratively identifies the single fix with the highest cross-layer impact, applies it (including propagated effects), marks it as done, and repeats until no further meaningful improvement is achievable. This produces a sequenced roadmap where each step builds on the previous — accounting for the reality that fixing one thing changes the landscape for everything else.

---

## IV. Implementation

The prototype is implemented in Python 3.11 using NetworkX for graph operations, Pydantic v2 for data schemas, and Graphviz for diagram rendering. SAST findings are ingested via a SARIF v2.1.0 parser compatible with Semgrep, CodeQL, Coverity, and Bandit. DAST findings are ingested via parsers for OWASP ZAP XML and Netsparker XML. Architecture is detected from Docker Compose files, Kubernetes manifests, OpenAPI specifications, environment files, dependency manifests, and code patterns.

The system is deployed via GitHub Actions. The evaluation pipeline starts a live Juice Shop Docker container, runs Semgrep for SAST, runs OWASP ZAP for DAST, and feeds all three inputs into the CausalTM v2 engine. Reports and diagrams are published as downloadable artifacts.

---

## V. Evaluation

### A. Evaluation Target

We evaluate against OWASP Juice Shop [9], a deliberately vulnerable web application with over one hundred documented security challenges. Its challenges are mapped to vulnerability types, providing ground truth for comparison.

### B. Methodology

The evaluation uses three real input sources:
1. **Architecture:** Modeled from Juice Shop's actual structure (6 components, 5 data flows, 2 trust boundaries)
2. **SAST:** Semgrep scan producing 23 real findings (7 High, 16 Medium) across 7 unique CWE types
3. **DAST:** OWASP ZAP baseline scan against a running Juice Shop instance producing 10 findings (2 Medium, 5 Low, 3 Informational)

We compare the system's output against 15 known Juice Shop challenges manually mapped to STRIDE categories.

### C. Results

The CausalTM v2 engine completed analysis in under two seconds:

| Metric | Result |
|--------|--------|
| Overall risk score | 0.462 (Medium) |
| STRIDE threats identified | 6 (one per category) |
| SAST base variables | 23 (classified into 4 posture types) |
| DAST base variables | 10 (runtime-confirmed) |
| Repo base variables | 11 (structural facts) |
| Remediation roadmap steps | 11 (to near-zero risk) |
| Cross-layer effects triggered | 3 (in roadmap steps) |

STRIDE posture per category:

| Category | Posture | Status |
|----------|---------|--------|
| Denial of Service | 26% | Critical threat |
| Information Disclosure | 43% | High threat |
| Tampering | 56% | High threat |
| Spoofing | 62% | Medium threat |
| Repudiation | 67% | Medium threat |
| Elevation of Privilege | 69% | Medium threat |

The roadmap's first three steps: (1) Reduce topology exposure — architecture fix with cross-layer effect on attack surface; (2) Improve input validation — code fix with cross-layer effect on attack surface; (3) Add defense-in-depth — architecture fix with cross-layer effect on attack surface.

### D. Ground Truth Comparison

Of 15 known Juice Shop challenges, the system matched 8 (53%) through STRIDE category alignment and CWE tracing. All six STRIDE categories were represented. The system correctly identified threats corresponding to SQL injection, path traversal, directory listing, rate limiting bypass, and IDOR challenges.

Challenges missed were primarily those requiring semantic understanding of business logic (JWT forgery, CSRF, specific credential attacks) — confirming that posture-based analysis excels at structural/architectural threats but requires extension for application-specific logic threats.

---

## VI. Discussion

### A. Posture vs. Vulnerability Counting

The shift from counting vulnerabilities to computing posture aligns CausalTM with what STRIDE actually evaluates. A STRIDE analyst does not count bugs — they assess whether the architecture provides adequate controls. Our severity-weighted posture calculation formalises this assessment: Critical findings damage posture more than Low ones, and three Critical findings in authentication bring auth posture to zero (total architectural failure for that control).

### B. Cross-Layer Value

The cross-layer dependency rules produced three triggered effects in the Juice Shop evaluation. This demonstrates the core value proposition: a single code fix (improving validation) simultaneously improves the runtime attack surface — the system predicts this before the fix is applied, enabling informed investment decisions.

### C. Limitations

The posture calibration (max_deficit = 3.0) is expert-specified rather than empirically derived. The evaluation uses a single deliberately-vulnerable application; real-world applications with lower vulnerability density need validation. The architecture was modeled rather than fully auto-detected. Per-flow STRIDE evaluation (rather than per-category) would increase granularity.

### D. Threats to Validity

The ground truth mapping was produced by a single researcher. The severity weights align with industry convention but have not been validated through expert panel consensus. The system has not been compared head-to-head against commercial threat modeling tools.

---

## VII. Conclusion

This paper has presented a posture-based Federated Structural Causal Model for automated STRIDE threat modeling. By computing severity-weighted security posture rather than counting vulnerabilities, the system aligns with STRIDE's architectural focus. By introducing cross-layer dependency rules, it predicts side effects of fixes across data sources. By placing STRIDE as a cream layer above the causal model, it identifies threats from design gaps rather than from individual findings.

Evaluation against OWASP Juice Shop with real SAST and DAST data demonstrates that the approach identifies threats across all six STRIDE categories, produces a sequenced remediation roadmap with cross-layer awareness, and traces architectural threats back to specific CWE types for validation. Future work will formalise posture calibration through expert panel studies, expand evaluation to diverse real-world applications, and implement formal Pearl do-calculus for the interventional queries currently approximated through graph operations.

---

## References

[1] A. Shostack, *Threat Modeling: Designing for Security*. Indianapolis: Wiley, 2014.

[2] IBM Security, "Cost of a Data Breach Report 2024," IBM Corporation, Armonk, NY, 2024.

[3] L. Kohnfelder and P. Garg, "The threats to our products," Microsoft Corporation, Redmond, WA, Internal Document, 1999.

[4] K. Tuma, G. Calikli, and R. Scandariato, "Threat analysis of software systems: A systematic literature review," *J. Systems and Software*, vol. 144, pp. 275-294, 2018.

[5] R. Scandariato, K. Wuyts, and W. Joosen, "A descriptive study of Microsoft's threat modeling technique," *Requirements Engineering*, vol. 20, no. 2, pp. 163-180, 2015.

[6] J. Jacobs, S. Romanosky, I. Adjerid, and W. Baker, "Improving vulnerability remediation through better exploit prediction," *J. Cybersecurity*, vol. 7, no. 1, pp. 1-14, 2021.

[7] W. Xiong and R. Lagerstrom, "Threat modeling — A systematic literature review," *Computers and Security*, vol. 84, pp. 53-69, 2019.

[8] J. Pearl, *Causality: Models, Reasoning, and Inference*, 2nd ed. Cambridge: Cambridge University Press, 2009.

[9] D. Arp, E. Quiring, F. Pendlebury, et al., "Dos and don'ts of machine learning in computer security," in *Proc. 31st USENIX Security Symp.*, Boston: USENIX, 2022, pp. 3971-3988.

[10] B. Kimminich and OWASP Foundation, "OWASP Juice Shop: Probably the most modern and sophisticated insecure web application," 2024. [Online]. Available: https://owasp.org/www-project-juice-shop/

[11] OWASP, "PyTM: Pythonic threat modeling," OWASP Foundation, 2023. [Online]. Available: https://owasp.org/www-project-pytm/

[12] T. Le, T. Chen, and M. A. Babar, "A survey on data-driven software vulnerability assessment and prioritization," *ACM Computing Surveys*, vol. 54, no. 5, pp. 1-36, 2021.

[13] Y. Fang, Y. Liu, and Z. Gao, "Causal inference for intrusion detection: A survey," *IEEE Access*, vol. 10, pp. 56892-56912, 2022.

[14] G. Husari, X. Niu, B. Chu, and E. Al-Shaer, "Using entropy and mutual information to extract threat actions from cyber threat intelligence," *Int. J. Information Security*, vol. 19, pp. 531-550, 2020.

[15] B. Scholkopf, F. Locatello, S. Bauer, et al., "Toward causal representation learning," *Proc. IEEE*, vol. 109, no. 5, pp. 612-634, 2021.

[16] J. Pearl, M. Glymour, and N. P. Jewell, *Causal Inference in Statistics: A Primer*. Chichester: Wiley, 2016.

[17] X. Ou, S. Govindavajhala, and A. W. Appel, "MulVAL: A logic-based network security analyzer," in *Proc. 14th USENIX Security Symp.*, Baltimore: USENIX, 2005, pp. 113-128.

[18] G. Dhillon, R. Syed, and F. de Sa-Soares, "Information security management in the new world," *European J. Information Systems*, vol. 30, no. 3, pp. 233-244, 2021.

[19] I. Pashchenko, M. Vuagnoux, and M. Bezzi, "Vulnerable open source dependencies: Counting those that matter," in *Proc. ESEC/FSE*, New York: ACM, 2020, pp. 1456-1466.

[20] J. Ruohonen, T. Laukka, and S. Hyrynsalmi, "A systematic review of machine learning approaches for software vulnerability prediction," in *Proc. ICSSP*, New York: ACM, 2018, pp. 135-144.
