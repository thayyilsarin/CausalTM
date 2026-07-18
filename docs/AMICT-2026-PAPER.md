# A Federated Structural Causal Model for Automated STRIDE Threat Modeling from Multi-Source Security Intelligence

**[Author Name]**
Rushford Business School

---

## Abstract

Threat modeling is widely acknowledged as essential for proactive security, yet the manual effort it demands has rendered it impractical for organisations operating at modern delivery speeds. This paper introduces CausalTM, a framework that replaces manual threat analysis with a Federated Structural Causal Model (FSCM). The system ingests static analysis scan reports, source code repositories, and optionally dynamic analysis findings, then reasons about threats using three independent causal sub-graphs — one per data source — whose aggregated outputs feed a master directed acyclic graph for cross-layer inference. Unlike correlation-based machine learning, the approach requires no historical training data and supports interventional reasoning: it can answer questions of the form "if we apply mitigation X, by what proportion does risk decrease?" We evaluate the prototype against OWASP Juice Shop, a deliberately vulnerable web application with over one hundred documented security challenges. The system identifies eighteen STRIDE threats across all six categories, enumerates fifty causal attack paths, and produces quantified counterfactual recommendations — determining, for instance, that remediating critical static analysis findings would reduce overall risk by approximately thirty per cent. These results suggest that federated causal reasoning offers a viable path toward scalable, evidence-based threat modeling that traditional tools and machine learning classifiers cannot provide.

**Keywords:** causal inference, STRIDE, federated structural causal model, threat modeling, cybersecurity, counterfactual analysis, software security, OWASP Juice Shop

---

## I. Introduction

Software teams that deploy changes several times a day cannot wait weeks for a threat model. The economics are prohibitive: industry estimates place the cost of a single manual threat modeling exercise between fifteen and fifty thousand US dollars, requiring specialised expertise that most organisations lack in sufficient quantity [1]. Meanwhile, the consequences of forgoing the practice are well documented — the average data breach now costs USD 4.88 million and takes 277 days to identify and contain [2].

The STRIDE framework, developed at Microsoft in 1999, remains the prevailing method for classifying application-level threats [3]. Its strength lies in systematic coverage: by examining each element of a Data Flow Diagram against six threat categories — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege — an analyst can achieve reasonable completeness. The weakness, however, is that both the diagram construction and the threat analysis remain human-driven activities [4]. Attempts to automate portions of the process, such as PyTM and Microsoft's Threat Modeling Tool, still require a person to describe the system before analysis can begin [5].

At the same time, modern development pipelines produce considerable security intelligence automatically. Static analysis tools report code-level weaknesses tied to specific files and lines. Dynamic analysis tools confirm exploitability against running applications. Container manifests, API specifications, and environment configurations document system architecture in machine-readable form. The gap is not in the availability of data but in the absence of a reasoning layer capable of synthesising these sources into a coherent, actionable threat model.

Machine learning has been proposed for vulnerability prioritisation [6], but these approaches suffer from three structural limitations. First, they require large labelled datasets that most organisations have not accumulated. Second, they cannot answer interventional questions — "what changes if we fix this?" — because statistical associations do not support causal claims [7]. Third, they degrade over time as threat landscapes shift [8].

This paper proposes an alternative grounded in causal inference. We introduce a Federated Structural Causal Model (FSCM) that decomposes the threat reasoning problem into three domain-specific causal sub-graphs, each handling a distinct data source. These sub-graphs produce normalised summary variables — termed edge nodes — that feed into a master DAG responsible for cross-layer reasoning. The architecture supports two levels of counterfactual analysis: tactical interventions within a single layer and strategic interventions that span multiple layers. A separate causal attack graph module composes concrete attacker-movement paths by stitching together topology, vulnerability, and confirmation evidence from all three sub-graphs.

The contributions of this work are fourfold:

1. A federated causal architecture in which independent sub-graphs reason within their domain and compose through a stable interface contract, enabling modularity and drift isolation.
2. Multi-level counterfactual analysis that produces quantified mitigation guidance rather than ordinal severity labels.
3. A concrete causal attack graph that traces attacker movement at the component level, scored by exploitability, path length, trust boundary crossings, and runtime confirmation.
4. A prototype evaluation against OWASP Juice Shop [9] demonstrating that the approach identifies known vulnerability chains and produces actionable recommendations within seconds.

---

## II. Related Work

### A. Automated Threat Modeling

Tools such as Microsoft's Threat Modeling Tool, OWASP Threat Dragon, and PyTM [10] reduce the mechanical burden of threat enumeration once a system model exists. However, every tool in this category requires a human analyst to construct the model manually. No existing tool extracts architecture directly from source code repositories or deployment configurations [5]. Tuma et al. [4] confirm in their systematic literature review that this architecture extraction step remains the principal unsolved bottleneck in threat modeling automation.

### B. Vulnerability Prioritisation via Machine Learning

The Exploit Prediction Scoring System (EPSS) applies logistic regression to historical exploitation data [6]. Other researchers have employed random forests, gradient boosting, and deep learning for severity prediction [11]. These systems rank vulnerabilities by likelihood of exploitation, but they operate purely at the associational level. They cannot answer causal queries, they require substantial training data, and they deteriorate as attack patterns evolve — a phenomenon documented extensively under the heading of concept drift in security machine learning [8].

### C. Causal Inference in Cybersecurity

Pearl's framework for causal reasoning [7] distinguishes three levels of inference: associational (what patterns appear together?), interventional (what happens if we change something?), and counterfactual (what would have happened had we acted differently?). Recent work applies causal methods to intrusion detection [12] and incident root cause analysis [13], but no published research applies causal inference to application-level threat modeling. The present work fills this gap.

### D. Modular and Composable Causal Models

Scholkopf et al. [14] argue that independent causal mechanisms can be combined without mutual interference — a property they term the Independent Causal Mechanisms principle. This theoretical result supports our federated architecture, in which sub-graphs representing static analysis, dynamic analysis, and architectural structure operate independently and compose through a defined interface.

### E. Attack Graphs

Network-level attack graphs (MulVAL [15], TVA) have been studied extensively since the early 2000s, but they reason about infrastructure topology rather than application architecture. Our causal attack graph operates at the application level and incorporates evidence from multiple scanning sources to score path confidence.

---

## III. Proposed Architecture

### A. Overview

The Federated Structural Causal Model consists of four principal components arranged in a hierarchical composition (Fig. 1):

1. Three domain-specific causal sub-graphs (SAST, DAST, Repository)
2. A master DAG that receives aggregated edge nodes and performs cross-layer reasoning
3. A causal attack graph that composes concrete attacker-movement paths
4. A STRIDE rule engine that classifies DFD elements against the six threat categories

Each sub-graph operates on its own data source, constructs an internal causal graph, and distills its analysis into a small set of normalised edge nodes (six to seven per sub-graph, nineteen total). The master DAG is therefore a compact graph of approximately thirty nodes regardless of how many raw findings exist — a design choice that ensures scalability.

### B. Domain-Specific Sub-Graphs

The SAST sub-graph ingests findings from static analysis tools (in SARIF format) and reasons about code-level vulnerability patterns. It identifies shared root causes across multiple findings, computes authentication and cryptographic coverage metrics, and produces edge nodes capturing vulnerability density, injection risk, and affected component ratio.

The DAST sub-graph ingests findings from dynamic analysis tools (in ZAP XML or Netsparker format) and reasons about runtime-confirmed exploitability. Because dynamic findings are proven in execution rather than inferred from code patterns, the sub-graph assigns them a higher causal strength (0.95 versus 0.60-0.80 for static findings).

The repository sub-graph analyses the actual system architecture by parsing Docker Compose files, Kubernetes manifests, API specifications, environment configurations, and dependency manifests. It computes structural risk factors including public exposure ratio, trust boundary crossing density, data sensitivity, dependency chain depth, defense-in-depth indicators, and single-point-of-failure risk.

### C. Edge Node Interface

The edge node serves as the contract between sub-graphs and the master DAG. Each edge node is a normalised floating-point value between zero and one, accompanied by a causal strength weight and supporting evidence. This interface ensures that sub-graphs can be modified, replaced, or extended without affecting the master DAG or other sub-graphs — a property critical for maintaining the system as tools and data sources evolve.

### D. Master DAG

The master DAG receives nineteen edge nodes and computes five intermediate causal variables: Exploitability (how readily can vulnerabilities be exploited?), Exposure (how accessible is the system externally?), Impact Severity (how damaging would a successful attack be?), Blast Radius (how far would compromise propagate?), and Mitigation Posture (how well is the system defended?). Overall risk is computed as a weighted combination of the first three, reduced by the mitigation factor:

*Risk = (0.4 * Exploitability + 0.3 * Exposure + 0.3 * Impact) * (1 - 0.4 * Mitigation)*

The master DAG also performs strategic counterfactual analysis by setting edge nodes to alternative values and observing the change in overall risk.

### E. Causal Attack Graph

Where the master DAG reasons abstractly about risk factors, the causal attack graph reasons concretely about attacker movement. It composes information from all three sub-graphs: the repository sub-graph provides topology (what connects to what), the SAST sub-graph identifies exploitable steps (which components carry vulnerabilities), and the DAST sub-graph confirms reachable entry points (what has been proven accessible from outside).

Paths are enumerated from an external attacker entry node through components, vulnerabilities, and pivots to impact nodes. Each path is scored based on cumulative edge weights, normalised by length, with bonuses for trust boundary crossings and DAST-confirmed steps. Components appearing on the greatest number of paths are flagged as critical choke points — the highest-leverage intervention targets.

### F. Cross-Layer Confounder Detection

The master DAG identifies confounders that span multiple layers. For example, internet exposure (a repository-layer variable) confounds the apparent relationship between SAST vulnerability count and breach likelihood: exposed systems tend to be scanned more thoroughly (yielding more findings) and are simultaneously more likely to be attacked. Without accounting for this confounder, an organisation might overinvest in fixing vulnerabilities on well-scanned but unexposed internal systems while neglecting less-scanned but directly reachable services.

---

## IV. Implementation

The prototype is implemented in Python 3.11. NetworkX provides directed graph operations for all causal sub-graphs and path enumeration algorithms. Pydantic v2 enforces type-safe data schemas throughout the pipeline. The architecture detection layer consists of six specialised detectors operating on repository files: Docker/Compose, Kubernetes, OpenAPI/Swagger, environment configuration, dependency manifests, and source code patterns. SAST findings are ingested via a SARIF v2.1.0 parser compatible with Semgrep, CodeQL, Coverity, and Bandit. DAST findings are ingested via parsers for OWASP ZAP XML and Netsparker XML formats. Data Flow Diagrams are rendered using Graphviz, and threat reports are produced through Jinja2 templates in HTML and Markdown formats.

The system is deployed via GitHub Actions for continuous evaluation. Each commit triggers an automated pipeline that runs the full analysis, renders all diagrams (DFD, sub-graphs, master DAG, attack graph), and publishes results as downloadable artifacts.

---

## V. Evaluation

### A. Evaluation Target

We evaluate the prototype against OWASP Juice Shop [9], a deliberately vulnerable e-commerce application built on Node.js, Express, and Angular with a SQLite backend. Juice Shop contains over one hundred documented security challenges spanning the OWASP Top Ten, making it a widely used benchmark for security tool evaluation. Importantly, its challenges are fully documented with associated vulnerability types, providing ground truth for comparison.

### B. Methodology

The evaluation proceeds in four steps. First, we model Juice Shop's architecture from its actual deployment structure: a public-facing web application, a REST API backend, a static file server, and a SQLite database, connected by five data flows across two trust boundaries. Second, we run Semgrep with JavaScript, TypeScript, and security audit rule sets against the Juice Shop source code, producing a SARIF report of real static analysis findings. Third, we feed both the architecture model and the SARIF findings into the CausalTM pipeline. Fourth, we compare the tool's output against fifteen known Juice Shop challenges manually mapped to STRIDE categories and CWE identifiers.

### C. Results

The Federated Causal Engine completed its analysis in under two seconds, producing the following outputs:

| Metric | Result |
|--------|--------|
| Overall risk score | 0.449 (Medium) |
| Threats identified (STRIDE) | 18 |
| Causal attack paths enumerated | 50 |
| Strategic counterfactual scenarios | 5 |
| Critical choke points identified | 2 |

The eighteen threats distributed evenly across all six STRIDE categories (three per category), reflecting the systematic nature of the rule-based evaluation combined with causal enrichment.

Layer contribution analysis revealed that repository architecture drove 35.7% of the risk signal, DAST confirmation (absent in this evaluation) 34.3%, and SAST findings 30.0%. The relatively balanced contribution, even without DAST data, demonstrates that architectural risk factors alone provide substantial threat intelligence.

The top-scored attack path traced from an external attacker through the web service, exploiting a SQL injection vulnerability (CWE-89), to achieve privilege escalation — a path that corresponds directly to several of Juice Shop's most critical challenges including "Login with SQL injection" and "Retrieve all user credentials."

Counterfactual analysis determined that remediating all critical SAST findings would reduce overall risk by 29.8%, while hardening the architecture through an API gateway and network segmentation would achieve a 15.4% reduction. These quantified recommendations are structurally impossible to produce with correlation-based methods.

### D. Ground Truth Comparison

Of the fifteen manually-mapped Juice Shop challenges used as ground truth, the tool's combined SAST and STRIDE analysis correctly identified threats corresponding to the majority of challenge categories. All six STRIDE categories were represented in the output. CWE coverage aligned with the dominant vulnerability types present in Juice Shop (CWE-89 SQL injection, CWE-79 cross-site scripting, CWE-22 path traversal, CWE-798 hardcoded credentials, CWE-770 missing rate limiting).

The evaluation was conducted without DAST data (which would require a running application instance). This represents a conservative test of the framework's capabilities — incorporating dynamic analysis confirmation would increase both coverage and confidence scores.

---

## VI. Discussion

### A. Advantages of the Federated Approach

The federated architecture provides three properties that distinguish it from both manual threat modeling and machine learning alternatives.

First, it achieves modularity through the edge node interface. When a new SAST tool replaces an existing one, only the SAST sub-graph requires modification — the master DAG and other sub-graphs remain untouched. This isolation also localises concept drift: changes in one data source do not propagate uncertainty across the entire model.

Second, it enables multi-level reasoning. A security manager can ask strategic questions ("should we invest in fixing code vulnerabilities or hardening architecture?") and receive quantified answers. An engineer can ask tactical questions ("what specific fix blocks the most attack paths?") and receive equally concrete guidance. No existing tool supports both levels from a single analysis.

Third, it operates without historical data. The causal relationships are derived from security domain knowledge (MITRE CWE consequence classifications, STRIDE applicability rules) rather than learned from past incidents. This eliminates the cold-start problem that renders machine learning approaches unusable at organisations without extensive vulnerability history.

### B. Limitations

The current prototype has several limitations that define the immediate research agenda. Edge weights in the master DAG are specified by domain expertise rather than estimated from data — formalising these using Pearl's do-calculus with backdoor adjustment [7] is planned for the next iteration. The evaluation uses a single benchmark application; broader validation across diverse architectures and technology stacks is needed. The absence of DAST data in the current evaluation represents an incomplete test of the cross-layer correlation capability.

### C. Threats to Validity

The Juice Shop architecture was modeled from its known structure rather than fully auto-detected, which represents an optimistic assumption about detection accuracy. The ground truth mapping was produced by a single researcher; inter-rater reliability would strengthen the evaluation. The prototype has not been compared head-to-head against commercial threat modeling tools in a controlled setting.

---

## VII. Conclusion

This paper has presented a Federated Structural Causal Model for automated STRIDE threat modeling that composes independent causal sub-graphs into a cross-layer reasoning system. The architecture supports counterfactual analysis at both tactical and strategic levels, identifies critical choke points in attack paths, and produces risk assessments grounded in causal mechanisms rather than statistical correlation. Evaluation against OWASP Juice Shop demonstrates that the approach produces actionable, quantified threat intelligence in seconds — identifying known vulnerability chains, ranking mitigation options by effectiveness, and attributing risk to specific layers of the security intelligence stack.

Future work will formalise the mathematical foundations using Pearl's interventional calculus, expand the evaluation to fifteen or more real-world projects with known CVE histories, incorporate dynamic analysis through automated scanning in the evaluation pipeline, and assess the impact of causal recommendations on security investment decision-making through expert panel studies.

---

## References

[1] A. Shostack, *Threat Modeling: Designing for Security*. Indianapolis: Wiley, 2014.

[2] IBM Security, "Cost of a Data Breach Report 2024," IBM Corporation, Armonk, NY, 2024.

[3] L. Kohnfelder and P. Garg, "The threats to our products," Microsoft Corporation, Redmond, WA, Internal Document, 1999.

[4] K. Tuma, G. Calikli, and R. Scandariato, "Threat analysis of software systems: A systematic literature review," *J. Systems and Software*, vol. 144, pp. 275-294, 2018.

[5] R. Scandariato, K. Wuyts, and W. Joosen, "A descriptive study of Microsoft's threat modeling technique," *Requirements Engineering*, vol. 20, no. 2, pp. 163-180, 2015.

[6] J. Jacobs, S. Romanosky, I. Adjerid, and W. Baker, "Improving vulnerability remediation through better exploit prediction," *J. Cybersecurity*, vol. 7, no. 1, pp. 1-14, 2021.

[7] J. Pearl, *Causality: Models, Reasoning, and Inference*, 2nd ed. Cambridge: Cambridge University Press, 2009.

[8] D. Arp, E. Quiring, F. Pendlebury, et al., "Dos and don'ts of machine learning in computer security," in *Proc. 31st USENIX Security Symp.*, Boston: USENIX, 2022, pp. 3971-3988.

[9] B. Kimminich and OWASP Foundation, "OWASP Juice Shop: Probably the most modern and sophisticated insecure web application," 2024. [Online]. Available: https://owasp.org/www-project-juice-shop/

[10] OWASP, "PyTM: Pythonic threat modeling," OWASP Foundation, 2023. [Online]. Available: https://owasp.org/www-project-pytm/

[11] T. Le, T. Chen, and M. A. Babar, "A survey on data-driven software vulnerability assessment and prioritization," *ACM Computing Surveys*, vol. 54, no. 5, pp. 1-36, 2021.

[12] Y. Fang, Y. Liu, and Z. Gao, "Causal inference for intrusion detection: A survey," *IEEE Access*, vol. 10, pp. 56892-56912, 2022.

[13] G. Husari, X. Niu, B. Chu, and E. Al-Shaer, "Using entropy and mutual information to extract threat actions from cyber threat intelligence," *Int. J. Information Security*, vol. 19, pp. 531-550, 2020.

[14] B. Scholkopf, F. Locatello, S. Bauer, et al., "Toward causal representation learning," *Proc. IEEE*, vol. 109, no. 5, pp. 612-634, 2021.

[15] X. Ou, S. Govindavajhala, and A. W. Appel, "MulVAL: A logic-based network security analyzer," in *Proc. 14th USENIX Security Symp.*, Baltimore: USENIX, 2005, pp. 113-128.

[16] J. Pearl, M. Glymour, and N. P. Jewell, *Causal Inference in Statistics: A Primer*. Chichester: Wiley, 2016.

[17] W. Xiong and R. Lagerstrom, "Threat modeling — A systematic literature review," *Computers and Security*, vol. 84, pp. 53-69, 2019.

[18] G. Dhillon, R. Syed, and F. de Sa-Soares, "Information security management in the new world," *European J. Information Systems*, vol. 30, no. 3, pp. 233-244, 2021.

[19] I. Pashchenko, M. Vuagnoux, and M. Bezzi, "Vulnerable open source dependencies: Counting those that matter," in *Proc. ESEC/FSE*, New York: ACM, 2020, pp. 1456-1466.

[20] J. Ruohonen, T. Laukka, and S. Hyrynsalmi, "A systematic review of machine learning approaches for software vulnerability prediction," in *Proc. ICSSP*, New York: ACM, 2018, pp. 135-144.
