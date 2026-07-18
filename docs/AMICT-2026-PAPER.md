# A Federated Structural Causal Model for Automated STRIDE Threat Modeling from Multi-Source Security Intelligence

## Authors
[Author Name], Rushford Business School

---

## Abstract

Manual threat modeling using frameworks such as STRIDE remains costly, time-intensive, and inconsistent across practitioners. Existing automation tools require human-defined system models and cannot reason causally about the relationship between vulnerabilities, architecture, and business impact. This paper presents CausalTM, a novel framework that employs a Federated Structural Causal Model (FSCM) to automate STRIDE-based threat modeling by composing domain-specific causal sub-graphs — covering static analysis findings, dynamic analysis confirmations, and repository architecture — into a master directed acyclic graph capable of cross-layer causal reasoning. Unlike correlation-based machine learning approaches, the framework operates without historical training data, provides quantified counterfactual mitigation recommendations, identifies cross-layer confounders that inflate perceived risk, and resists concept drift. A prototype implementation demonstrates the approach on a benchmark application, producing automated Data Flow Diagrams, concrete causal attack paths, and evidence-based prioritisation guidance within seconds rather than weeks. Preliminary results indicate that the federated causal architecture correctly identifies known vulnerability chains and produces actionable intervention recommendations that traditional tools cannot generate.

**Keywords:** Causal inference, STRIDE, threat modeling, federated structural causal model, cybersecurity, counterfactual analysis, software security automation

---

## I. Introduction

The velocity of modern software delivery has outpaced the capacity of security teams to assess risk. Organisations deploying code multiple times daily cannot afford threat modeling exercises that consume weeks of specialist time and budgets exceeding USD 15,000 per engagement [1]. Yet threat modeling remains the primary mechanism for identifying architectural security weaknesses before they manifest as breaches — breaches that cost an average of USD 4.88 million to contain [2].

Microsoft's STRIDE framework [3], the dominant approach to application-level threat classification, systematically evaluates system components against six threat categories: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege. The method requires constructing a Data Flow Diagram (DFD) and applying threat rules to each element. Both steps remain predominantly manual, creating a scalability bottleneck that renders the practice impractical in continuous delivery environments [4].

Meanwhile, organisations accumulate rich security intelligence from automated scanning tools. Static Application Security Testing (SAST) products identify code-level weaknesses with file and line precision. Dynamic Application Security Testing (DAST) products confirm exploitability against running applications. Infrastructure-as-code files, container manifests, and API specifications document the system architecture explicitly. None of these sources, individually or collectively, are synthesised into a coherent threat model today [5].

Machine learning approaches have been proposed for vulnerability prioritisation [6], but these operate at the associational level of reasoning — identifying patterns without establishing causation. They cannot answer the interventional questions that security managers need: "If we implement this control, by how much does our risk actually decrease?" Such questions require causal reasoning [7].

This paper addresses these gaps by proposing a Federated Structural Causal Model (FSCM) architecture for automated threat modeling. The key contributions are:

1. A federated causal architecture where independent domain-specific sub-graphs (SAST, DAST, architecture) reason within their layer and compose into a master DAG for cross-layer reasoning.
2. Multi-level counterfactual analysis enabling both tactical (within-layer) and strategic (cross-layer) what-if queries with quantified risk reduction.
3. A concrete causal attack graph that traces attacker movement through actual system components, enriched by evidence from multiple scanning sources.
4. A prototype implementation demonstrating feasibility on a benchmark application.

The remainder of this paper is organised as follows. Section II reviews related work. Section III presents the proposed architecture. Section IV describes the implementation. Section V demonstrates preliminary results. Section VI discusses implications and limitations. Section VII concludes.

---

## II. Related Work

### A. Automated Threat Modeling

Several tools attempt to reduce threat modeling effort. Microsoft's Threat Modeling Tool, OWASP Threat Dragon, and PyTM [8] automate threat enumeration once a system model is provided. However, all require manual model construction — no tool automatically extracts architecture from source repositories [9]. Tuma et al. [4] confirm in their systematic review that architecture extraction remains the primary unsolved bottleneck.

### B. SAST/DAST Integration

Static and dynamic analysis tools are standard in development pipelines, producing findings in standardised formats (SARIF for SAST, XML for DAST). DefectDojo [10] aggregates findings from multiple tools but performs no causal reasoning about how findings relate to each other or to the system architecture. Pashchenko et al. [5] demonstrate that without architectural context, vulnerability lists overwhelm teams without enabling prioritisation.

### C. Machine Learning for Security Prioritisation

The Exploit Prediction Scoring System (EPSS) [6] uses logistic regression on historical exploitation data to estimate exploit probability. Other approaches apply random forests and neural networks to severity prediction [11]. These models learn statistical associations but cannot distinguish causation from correlation, cannot perform interventional reasoning, and suffer from data dependency and concept drift [12]. Pearl [7] proves formally that observational data alone cannot answer interventional queries without causal structural assumptions.

### D. Causal Inference in Cybersecurity

Causal methods have been applied to intrusion detection [13] and root cause analysis [14], but no published work applies causal inference to application-level STRIDE threat modeling. Scholkopf et al. [15] provide theoretical grounding for modular causal models — independent causal mechanisms that compose without interference — directly supporting our federated architecture. The application of Pearl's do-calculus [7] to security decision-making represents an unexplored opportunity.

### E. Attack Graphs

Network-level attack graphs (MulVAL [16], NetSPA) are well-studied but focus on infrastructure topology rather than application architecture. Our work brings attack graph reasoning to the application level, enriched with SAST/DAST evidence and causal semantics.

---

## III. Proposed Architecture

### A. Overview

The Federated Structural Causal Model (FSCM) consists of three domain-specific causal sub-graphs, a master DAG, and a causal attack graph (Fig. 1). Each sub-graph reasons independently about its domain and produces aggregated causal variables called *edge nodes* that are promoted to the master DAG for cross-layer reasoning.

```
[SAST Sub-Graph] ──edge nodes──┐
[DAST Sub-Graph] ──edge nodes──┼──▶ [Master DAG] ──▶ Risk Score
[Repo Sub-Graph] ──edge nodes──┘         │
                                         ▼
                              [Causal Attack Graph]
                              (concrete component paths)
```

*Fig. 1. Federated Structural Causal Model architecture*

### B. Domain-Specific Sub-Graphs

Each sub-graph is a directed acyclic graph operating within a single security intelligence domain:

**SAST Sub-Graph** reasons about code-level vulnerabilities. Nodes represent findings (classified by CWE), components, and root cause patterns. Internal causal relationships link shared root causes to multiple findings. The sub-graph produces six edge nodes: vulnerability density, injection risk, authentication coverage, cryptographic implementation quality, affected component ratio, and root cause concentration.

**DAST Sub-Graph** reasons about runtime-confirmed vulnerabilities. All DAST findings carry higher causal strength (0.95) than SAST findings because they represent proven exploitability rather than theoretical weakness. Edge nodes include: confirmed exploitable ratio, attack surface size, authentication bypass evidence, TLS posture, information leakage level, and severity distribution score.

**Repo Sub-Graph** reasons about architectural structure. Nodes represent services, databases, external entities, data flows, and trust boundaries detected from Docker manifests, Kubernetes configurations, API specifications, and environment files. Edge nodes include: public exposure ratio, trust boundary crossing density, data sensitivity level, dependency depth, defense-in-depth score, single-point-of-failure risk, and network segmentation quality.

### C. Edge Node Interface

The edge node is the contract between sub-graphs and the master DAG:

```
EdgeNode {
  id: string          // e.g., "sast.vulnerability_density"
  value: float [0,1]  // normalised score
  causal_strength: float [0,1]  // how strongly it influences downstream
  layer: string       // which sub-graph produced it
  evidence: string[]  // supporting justification
}
```

This interface ensures modularity: any sub-graph producing conformant edge nodes can participate in the master DAG without modification to other components.

### D. Master DAG

The master DAG receives 19 edge nodes from the three sub-graphs and computes five intermediate causal variables through weighted structural equations:

- **Exploitability** = f(SAST.vulnerability_density, SAST.injection_risk, DAST.confirmed_exploitable, DAST.severity_score)
- **Exposure** = f(Repo.public_exposure, Repo.trust_boundary_crossings, DAST.attack_surface)
- **Impact Severity** = f(Repo.data_sensitivity, SAST.affected_components, Repo.single_point_of_failure)
- **Blast Radius** = f(Repo.dependency_depth, Repo.single_point_of_failure, SAST.affected_components)
- **Mitigation Posture** = f(Repo.defense_depth, SAST.auth_coverage, SAST.crypto_usage, DAST.tls_posture, Repo.segmentation)

Overall risk is computed as:

```
Risk = (w₁·Exploitability + w₂·Exposure + w₃·Impact) × (1 - Mitigation × α)
```

where w₁=0.4, w₂=0.3, w₃=0.3, and α=0.4 represents maximum mitigation reduction.

### E. Multi-Level Counterfactual Analysis

The federated architecture enables counterfactuals at two granularities:

**Strategic counterfactuals** (master level): "What if all critical SAST findings are fixed?" — directly sets edge node values to zero and recomputes risk.

**Tactical counterfactuals** (sub-graph level): "What if we add input validation to the web service?" — the SAST sub-graph recomputes its internal state, produces new edge node values, which propagate to the master DAG for global risk recalculation.

This two-level design answers both executive questions ("where should we invest?") and engineering questions ("what specific fix has the highest ROI?").

### F. Causal Attack Graph

Unlike the master DAG (which reasons abstractly about risk factors), the Causal Attack Graph produces concrete attacker-movement paths by composing all three sub-graphs:

- Repo sub-graph provides structural topology (who connects to whom)
- SAST sub-graph identifies exploitable components (where vulnerabilities exist)
- DAST sub-graph confirms reachable entry points (what is proven accessible)

Paths are enumerated from an "attacker" entry node through components and vulnerabilities to impact nodes, scored by edge weights, path length, boundary crossings, and DAST confirmation status. Critical choke points (components appearing on the most paths) are identified as priority intervention targets.

### G. Cross-Layer Confounder Detection

The master DAG identifies cross-layer confounders — variables that inflate the perceived relationship between a cause and an effect. For example, internet exposure (Repo layer) confounds the relationship between SAST vulnerability count and actual exploitability: exposed systems get scanned more thoroughly (more findings detected) AND are more likely to be breached (more actual risk). Without adjustment, this leads to overestimating the causal effect of fixing vulnerabilities in non-exposed systems.

---

## IV. Implementation

CausalTM is implemented in Python 3.11 using the following stack:

| Component | Technology |
|-----------|-----------|
| Causal graphs | NetworkX (directed graph operations) |
| Data models | Pydantic (type-safe schemas) |
| API layer | FastAPI (async REST endpoints) |
| Architecture detection | Custom detectors for Docker, Kubernetes, OpenAPI, environment files |
| SAST ingestion | SARIF v2.1.0 parser (compatible with Coverity, Semgrep, CodeQL) |
| DAST ingestion | ZAP XML and Netsparker XML parser |
| DFD rendering | Graphviz (SVG/PNG output) |
| Report generation | Jinja2 templates (HTML/Markdown) |
| Git operations | GitPython (repository cloning) |

The architecture detection layer employs six detectors operating on repository files: Docker/Compose detector (services, databases, ports, dependencies), Kubernetes detector (deployments, services, ingress, namespaces), API specification detector (OpenAPI/Swagger endpoints, authentication schemes), configuration detector (database URLs, external services, message brokers), dependency detector (package manifests for technology stack identification), and code pattern detector (regex-based detection of HTTP clients, database queries, authentication patterns, and cryptographic operations).

The system accepts three inputs: a Git repository URL, an optional SAST report (SARIF format), and an optional DAST report (ZAP/Netsparker XML). It produces four outputs: a Data Flow Diagram (SVG), a STRIDE threat report (HTML), a causal attack graph (JSON), and counterfactual mitigation recommendations.

---

## V. Preliminary Demonstration

### A. Setup

The prototype was evaluated against a simulated three-component application consisting of a public-facing web service (Node.js), a PostgreSQL database storing user credentials, and an external user entity. Two SAST findings (CWE-89 SQL Injection, Critical; CWE-287 Missing Authentication, High) and two DAST findings (confirmed SQL injection at /api/users; missing security headers) were provided as input.

### B. Results

The federated engine produced the following analysis in under one second:

| Metric | Value |
|--------|-------|
| Overall Risk Score | 0.459 (Medium) |
| Attack Paths Identified | 22 |
| Confirmed Attack Paths (DAST-verified) | 22 |
| Top Attack Path Score | 0.953 |
| Strategic Counterfactual Scenarios | 5 |
| Critical Choke Points | 2 (Web Service, Database) |

**Layer contributions:** SAST drove 41.9% of the risk signal, repository architecture 34.6%, and DAST confirmations 23.6%.

**Top attack path:** Attacker → Web Service → exploits CWE-89 → Privilege Escalation (score: 0.953, confirmed by DAST).

**Top counterfactual recommendation:** "Fix all critical SAST findings" would reduce overall risk by 29.8%. "Harden architecture (API gateway + segmentation)" would reduce risk by 15.4%.

**Cross-layer insight:** The engine identified that internet exposure confounds the SAST-to-breach relationship — the SQL injection's severity is elevated because the web service is publicly accessible (confirmed by both Repo and DAST layers independently).

### C. Comparison with Flat Approaches

A non-federated approach (single monolithic graph) would produce:
- A single risk score without layer attribution
- No distinction between tactical and strategic interventions
- No isolation of drift (changing one input reconstructs the entire model)
- Counterfactuals that remove individual low-level nodes (negligible effect in a 100+ node graph)

The federated architecture produces layered, interpretable, and actionable output because edge nodes abstract sub-graph complexity while preserving causal semantics.

---

## VI. Discussion

### A. Advantages Over Correlation-Based AI

The FSCM approach provides three capabilities structurally unavailable to correlation-based models:

1. **Counterfactual reasoning:** The framework answers "what if?" questions directly, enabling quantified investment guidance rather than opaque risk scores.
2. **Zero data dependency:** The system operates from its first scan without requiring historical breach data for training.
3. **Drift resistance:** Causal mechanisms (e.g., "SQL injection enables unauthorised data access") remain stable over time; only edge weights may require periodic calibration.

### B. Limitations

The current implementation uses heuristic weighted sums rather than formal probabilistic structural equations. Edge weights are expert-specified rather than learned from data. The evaluation is preliminary (single simulated application). These limitations define the immediate research roadmap: formalising the mathematics using Pearl's do-calculus, validating against 15-20 real-world projects with known CVE histories, and conducting expert panel evaluation.

### C. Generalisability

The federated architecture is language-agnostic (architecture detection operates on manifests, not source language) and tool-agnostic (any SARIF-producing SAST tool or XML-producing DAST tool is compatible). New data sources can be integrated by adding sub-graphs without modifying existing components — a direct consequence of the edge node interface contract.

---

## VII. Conclusion

This paper presented a Federated Structural Causal Model for automated STRIDE threat modeling that composes domain-specific causal sub-graphs into a unified reasoning system. The architecture enables multi-level counterfactual analysis, cross-layer confounder detection, and concrete attack path identification — capabilities absent from both traditional threat modeling tools and correlation-based machine learning approaches. Preliminary results demonstrate that the framework produces actionable, evidence-based threat assessments within seconds, identifies the highest-impact intervention points, and quantifies the expected risk reduction from specific mitigations. Future work will formalise the mathematical foundations using Pearl's interventional calculus, evaluate against diverse real-world projects, and assess organisational decision-making impact through expert panel studies.

---

## References

[1] A. Shostack, *Threat Modeling: Designing for Security*. Indianapolis: Wiley, 2014.

[2] IBM Security, "Cost of a Data Breach Report 2024," IBM Corporation, Armonk, NY, 2024.

[3] L. Kohnfelder and P. Garg, "The threats to our products," Microsoft Corporation, Redmond, WA, Internal Document, 1999.

[4] K. Tuma, G. Calikli, and R. Scandariato, "Threat analysis of software systems: A systematic literature review," *J. Systems and Software*, vol. 144, pp. 275-294, 2018.

[5] I. Pashchenko, M. Vuagnoux, and M. Bezzi, "Vulnerable open source dependencies: Counting those that matter," in *Proc. ESEC/FSE*, New York: ACM, 2020, pp. 1456-1466.

[6] J. Jacobs, S. Romanosky, I. Adjerid, and W. Baker, "Improving vulnerability remediation through better exploit prediction," *J. Cybersecurity*, vol. 7, no. 1, pp. 1-14, 2021.

[7] J. Pearl, *Causality: Models, Reasoning, and Inference*, 2nd ed. Cambridge: Cambridge University Press, 2009.

[8] OWASP, "PyTM: Pythonic threat modeling," OWASP Foundation, 2023. [Online]. Available: https://owasp.org/www-project-pytm/

[9] R. Scandariato, K. Wuyts, and W. Joosen, "A descriptive study of Microsoft's threat modeling technique," *Requirements Engineering*, vol. 20, no. 2, pp. 163-180, 2015.

[10] OWASP, "DefectDojo," OWASP Foundation, 2024. [Online]. Available: https://www.defectdojo.org/

[11] T. Le, T. Chen, and M. A. Babar, "A survey on data-driven software vulnerability assessment and prioritization," *ACM Computing Surveys*, vol. 54, no. 5, pp. 1-36, 2021.

[12] D. Arp, E. Quiring, F. Pendlebury, et al., "Dos and don'ts of machine learning in computer security," in *Proc. 31st USENIX Security Symp.*, Boston: USENIX, 2022, pp. 3971-3988.

[13] Y. Fang, Y. Liu, and Z. Gao, "Causal inference for intrusion detection: A survey," *IEEE Access*, vol. 10, pp. 56892-56912, 2022.

[14] G. Husari, X. Niu, B. Chu, and E. Al-Shaer, "Using entropy and mutual information to extract threat actions from cyber threat intelligence," *Int. J. Information Security*, vol. 19, pp. 531-550, 2020.

[15] B. Scholkopf, F. Locatello, S. Bauer, et al., "Toward causal representation learning," *Proc. IEEE*, vol. 109, no. 5, pp. 612-634, 2021.

[16] X. Ou, S. Govindavajhala, and A. W. Appel, "MulVAL: A logic-based network security analyzer," in *Proc. 14th USENIX Security Symp.*, Baltimore: USENIX, 2005, pp. 113-128.

[17] W. Xiong and R. Lagerstrom, "Threat modeling — A systematic literature review," *Computers and Security*, vol. 84, pp. 53-69, 2019.

[18] J. Pearl, M. Glymour, and N. P. Jewell, *Causal Inference in Statistics: A Primer*. Chichester: Wiley, 2016.

[19] G. Dhillon, R. Syed, and F. de Sa-Soares, "Information security management in the new world," *European J. Information Systems*, vol. 30, no. 3, pp. 233-244, 2021.

[20] J. Ruohonen, T. Laukka, and S. Hyrynsalmi, "A systematic review of machine learning approaches for software vulnerability prediction," in *Proc. ICSSP*, New York: ACM, 2018, pp. 135-144.
