# Prototype Gaps and Fix Roadmap

This document captures the known limitations of the CausalTM prototype as of July 2026, and provides a prioritised plan to address each gap. It serves as the development roadmap for evolving the prototype into a production-capable tool.

---

## 1. Vulnerability Detection Coverage

### Current State
- CausalTM does NOT scan code itself — it consumes findings from external SAST/DAST tools
- Only 8 CWEs are mapped to STRIDE impacts (CWE-89, 79, 287, 311, 319, 269, 400, 770)
- Only 16 STRIDE rules exist in `rules/default.yaml`
- Business logic flaws, race conditions, and serialization issues are not detectable

### Gaps
| Gap | Impact | Severity |
|-----|--------|----------|
| 8 CWE mappings out of 900+ | Most SAST findings cannot be mapped to STRIDE impacts via domain knowledge | High |
| 16 STRIDE rules only | Misses many valid threat patterns (e.g., insecure deserialization, SSRF, XXE) | High |
| No business logic detection | Cannot identify domain-specific threats | Medium |
| Relies entirely on external tool quality | If Semgrep misses a vuln, CausalTM is blind to it | Inherent design choice |

### Fix Plan
| Fix | Effort | Priority | Phase |
|-----|--------|----------|-------|
| Expand CWE → STRIDE mapping to 50+ CWEs using MITRE CWE consequence data | 1 week | P1 | Immediate |
| Add 25+ additional STRIDE rules covering OWASP Top 10 fully | 1 week | P1 | Immediate |
| Build automated CWE sync from MITRE XML feed (auto-generate mappings) | 2 weeks | P2 | Short-term |
| Support multiple SAST tool combination (Semgrep + CodeQL + Bandit together) | 1 week | P3 | Medium-term |

---

## 2. Pearl's Causal Inference Formalism

### Current State
- Uses causal DAG structure with causal SEMANTICS (edges mean causes/enables/influences)
- Risk computation is a heuristic weighted sum, not structural equations
- Counterfactuals use "set-to-zero-and-recompute" not formal abduction-action-prediction
- No probabilistic inference, no uncertainty quantification
- No backdoor/frontdoor adjustment implemented

### Gaps
| Gap | Impact | Severity |
|-----|--------|----------|
| Weighted sums instead of structural equations | Cannot claim formal causal inference compliance | High (for paper) |
| No do-calculus implementation | Interventional queries are approximated, not formally computed | High (for paper) |
| No backdoor adjustment | Confounder handling is heuristic (subtract 0.2) not statistical | Medium |
| No probability distributions | Cannot express uncertainty in risk scores | Medium |
| No abduction step in counterfactuals | Cannot answer "given breach happened, what would have prevented it?" | Low (future) |

### Fix Plan
| Fix | Effort | Priority | Phase |
|-----|--------|----------|-------|
| Replace weighted sums with sigmoid structural equations in Master DAG | 2 weeks | P1 | Short-term |
| Implement noisy-OR model for multi-parent risk nodes | 1 week | P1 | Short-term |
| Add confidence intervals to risk scores (basic uncertainty) | 1 week | P2 | Short-term |
| Implement proper do-operator via truncated factorization | 3 weeks | P2 | Medium-term |
| Add backdoor adjustment when historical data is available | 3 weeks | P3 | Medium-term |
| Implement abduction-action-prediction (full Level 3 counterfactuals) | 4 weeks | P3 | Long-term |
| Integrate DoWhy/pgmpy for formal causal inference operations | 2 weeks | P3 | Long-term |

---

## 3. DFD Accuracy and Completeness

### Current State
- DFD is generated from infrastructure files (Docker, K8s, OpenAPI, env configs)
- Works well for containerised applications with explicit manifests
- Poor or no coverage for monoliths, serverless, or apps without IaC
- Cannot detect internal service boundaries within code (function-level)
- Does not infer data types flowing between services (only from API specs)

### Gaps
| Gap | Impact | Severity |
|-----|--------|----------|
| Monolith apps produce empty/minimal DFDs | Tool is unusable for non-containerised apps | High |
| No serverless detection (Lambda, Functions) | Misses entire cloud-native application category | High |
| No database schema awareness | Cannot determine what data (PII, financial) is in which store | Medium |
| No runtime service discovery (Consul, Eureka) | Misses dynamic topology | Low |
| Data flow labels are generic ("data", "api_requests") | DFD lacks precision on what data moves where | Medium |

### Fix Plan
| Fix | Effort | Priority | Phase |
|-----|--------|----------|-------|
| Improve code pattern detector to infer service boundaries from HTTP route handlers | 2 weeks | P2 | Short-term |
| Parse database migration files (schema.sql, Sequelize models) for data classification | 2 weeks | P2 | Short-term |
| Add serverless detector (`serverless.yml`, AWS SAM `template.yaml`) | 1 week | P2 | Short-term |
| Infer data types from API request/response schemas in OpenAPI specs | 1 week | P2 | Short-term |
| Add Terraform detector for cloud architecture | 2 weeks | P1 | Short-term |
| Add CloudFormation/Bicep/Pulumi detector | 2 weeks | P3 | Medium-term |

---

## 4. Application Type Support

### Current State
- Supported: Docker/Compose, Kubernetes, OpenAPI/Swagger, GraphQL
- Partially supported: Any repo with config files (.env, appsettings.json)
- Not supported: Serverless, cloud-native IaC, mobile, IoT, mainframe

### Gaps
| Application Type | Status | Priority to Fix |
|------------------|--------|-----------------|
| Containerised (Docker/K8s) | Supported | — |
| API-first (OpenAPI/Swagger) | Supported | — |
| Traditional monolith (WAR, DLL) | Barely | P3 |
| Serverless (Lambda, Azure Functions, Cloud Functions) | Not supported | P1 |
| Cloud IaC (Terraform, CloudFormation) | Not supported | P1 |
| Service mesh (Istio, Linkerd) | Not supported | P3 |
| Mobile (iOS/Android backend) | Not supported | P4 |
| IoT/Embedded | Not supported | Out of scope |
| Legacy (COBOL/mainframe) | Not supported | Out of scope |

### Fix Plan
| Fix | Effort | Priority | Phase |
|-----|--------|----------|-------|
| Terraform detector (`.tf` files → AWS/Azure/GCP resources, VPCs, security groups) | 2 weeks | P1 | Short-term |
| Serverless Framework detector (`serverless.yml` → functions, events, resources) | 1 week | P1 | Short-term |
| AWS SAM detector (`template.yaml` → Lambda, API Gateway, DynamoDB) | 1 week | P2 | Short-term |
| CloudFormation detector (JSON/YAML → full AWS architecture) | 2 weeks | P2 | Medium-term |
| Azure Bicep/ARM detector | 2 weeks | P3 | Medium-term |
| Istio/Linkerd service mesh detector (network policies, mTLS config) | 1 week | P3 | Medium-term |

---

## 5. Cloud and Infrastructure Components

### Current State
- No cloud service detection whatsoever
- Cannot identify: managed databases (RDS, Cloud SQL), object storage (S3), message queues (SQS), CDNs (CloudFront), WAFs, API Gateways, identity providers (Cognito, Auth0)
- Trust boundaries limited to Docker networks and K8s namespaces

### Gaps
| Cloud Component | Supported? | Why It Matters for Threat Modeling |
|-----------------|------------|-----------------------------------|
| AWS EC2/ECS/EKS | No | Compute layer — trust boundaries, network exposure |
| AWS S3 / Azure Blob / GCS | No | Data store — sensitivity, public access misconfig |
| AWS RDS / Cloud SQL | No | Data store — encryption at rest, network isolation |
| AWS Lambda / Azure Functions | No | Compute — IAM roles, timeout abuse, injection |
| AWS SQS / SNS / EventBridge | No | Data flow — message tampering, replay attacks |
| AWS API Gateway / Azure APIM | No | Entry point — auth, rate limiting, WAF |
| CDN (CloudFront, Akamai) | No | Edge — cache poisoning, TLS config |
| WAF (AWS WAF, Azure FrontDoor) | No | Mitigation layer — defense-in-depth scoring |
| Identity (Cognito, Auth0, Okta) | No | Auth provider — spoofing threat reduction |
| Secrets Manager (Vault, AWS SM) | No | Credential management — hardcoded secret detection |

### Fix Plan
| Fix | Effort | Priority | Phase |
|-----|--------|----------|-------|
| Terraform detector covers all above implicitly (parse any `.tf` resource) | 2 weeks | P1 | Short-term |
| Map Terraform resource types to DFD element types (aws_instance → process, aws_s3_bucket → data_store, aws_lb → external_entity) | 1 week | P1 | Short-term |
| Extract security configurations from Terraform (security groups, IAM policies, encryption settings) | 2 weeks | P2 | Short-term |
| Map cloud security configs to STRIDE properties (has_encryption, has_authentication, is_public_facing) | 1 week | P2 | Short-term |
| Add cloud-specific STRIDE rules (S3 public access → Info Disclosure, Lambda without auth → Spoofing) | 1 week | P2 | Medium-term |

---

## 6. DAST Integration

### Current State
- DAST parser code exists (ZAP XML + Netsparker XML)
- DAST sub-graph logic is implemented
- DAST has NEVER actually been run in the evaluation pipeline
- Requires a live running application instance to scan against

### Gaps
| Gap | Impact | Severity |
|-----|--------|----------|
| No DAST scan in CI pipeline | Cross-layer correlation (SAST + DAST) is untested with real data | High |
| Requires Docker-in-Docker for CI | Complex CI setup needed | Medium |
| DAST sub-graph shows "not observed" in all evaluations so far | Half the federated model is dormant | High |

### Fix Plan
| Fix | Effort | Priority | Phase |
|-----|--------|----------|-------|
| Add Docker service container for Juice Shop in GitHub Actions | 1 day | P1 | Immediate |
| Add OWASP ZAP baseline scan step after app is healthy | 1 day | P1 | Immediate |
| Feed ZAP XML into eval pipeline | 30 min | P1 | Immediate |
| Validate DAST sub-graph produces meaningful edge nodes with real data | 1 day | P1 | Immediate |
| Test cross-layer correlation (SAST finding + DAST confirmation = elevated severity) | 1 day | P1 | Immediate |

---

## 7. Report Quality

### Current State
- HTML report generates with embedded DFD, STRIDE table, attack paths, counterfactuals
- Master DAG and attack graph embedded in report
- Attack path names were showing internal IDs (fixed in latest commit)
- STRIDE categories show enum names in some console outputs

### Gaps
| Gap | Impact | Severity |
|-----|--------|----------|
| No PDF export (only HTML + Markdown) | Some stakeholders expect PDF | Low |
| No executive summary with business language | Report is technical, not board-ready | Medium |
| Attack paths lack detailed narrative per path | Just shows node names, no explanation of each step | Medium |
| No comparison view (before/after mitigation) | Counterfactuals are listed but not visualised | Low |
| Report doesn't explain the methodology to the reader | New users don't understand what they're looking at | Medium |

### Fix Plan
| Fix | Effort | Priority | Phase |
|-----|--------|----------|-------|
| Add methodology explanation section to report template | 2 hours | P2 | Immediate |
| Expand attack path narratives (auto-generated explanation per step) | 1 day | P2 | Short-term |
| Add WeasyPrint PDF export from HTML | 1 day | P3 | Medium-term |
| Add executive summary section with business-language risk description | 1 day | P2 | Short-term |
| Add before/after comparison visualisation for top counterfactual | 2 days | P3 | Medium-term |

---

## Phased Delivery Plan

### Phase 0: Paper-Ready (Current Sprint — Weeks 1-2)

Goal: Produce results good enough for AMICT 2026 paper submission.

| Task | Status |
|------|--------|
| Federated engine running end-to-end | Done |
| Juice Shop evaluation with Semgrep | Done |
| DFD rendering | Done |
| HTML report generation | Done |
| Attack path human-readable names | Done (latest fix) |
| Master DAG showing observed/not-observed | Done (latest fix) |
| Ground truth comparison (15 challenges) | Done |
| DAST actually running (Juice Shop + ZAP) | **NOT DONE — needed for paper** |

### Phase 1: Core Gaps (Weeks 3-6)

Goal: Make the tool credible for the DBA evaluation.

| Task | Effort |
|------|--------|
| Expand CWE → STRIDE mappings to 50+ | 1 week |
| Add 25+ STRIDE rules | 1 week |
| Terraform detector (covers most cloud) | 2 weeks |
| Serverless detector | 1 week |
| DAST integration in CI (Docker + ZAP) | 2 days |
| Sigmoid structural equations in Master DAG | 2 weeks |

### Phase 2: Depth (Weeks 7-12)

Goal: Formal causal inference, broader evaluation.

| Task | Effort |
|------|--------|
| Proper do-operator (truncated factorization) | 3 weeks |
| Backdoor adjustment for confounders | 3 weeks |
| Uncertainty quantification (confidence intervals on risk) | 1 week |
| Evaluate on 10+ diverse projects | 4 weeks |
| Expert panel evaluation (10-15 security professionals) | 4 weeks |
| CloudFormation/Bicep detectors | 2 weeks |

### Phase 3: Production Quality (Weeks 13-24)

Goal: Tool ready for real organisational deployment.

| Task | Effort |
|------|--------|
| Full abduction-action-prediction counterfactuals | 4 weeks |
| DoWhy/pgmpy integration for formal inference | 2 weeks |
| Automated CWE sync from MITRE feed | 2 weeks |
| PDF report generation | 1 week |
| CI/CD webhook integration (GitLab, GitHub, Jenkins) | 2 weeks |
| Multi-repo correlation (organisation-wide view) | 4 weeks |
| Web UI for interactive what-if analysis | 6 weeks |

---

## Summary Table: What Works vs What Doesn't

| Capability | Works Today | Limitation | Fix Priority |
|------------|-------------|------------|-------------|
| Architecture detection (Docker/K8s) | Yes | Only Docker/K8s, not cloud/serverless | P1 |
| SAST ingestion (SARIF) | Yes | Depends on external tool quality | Inherent |
| DAST ingestion (ZAP XML) | Code exists | Never tested with real DAST data | P1 |
| Federated causal engine | Yes | Heuristic math, not formal Pearl | P1 (for paper) |
| STRIDE classification | Yes | Only 16 rules, 8 CWE mappings | P1 |
| DFD generation | Yes | Only for Docker/K8s/OpenAPI repos | P1 |
| Counterfactual analysis | Yes | Approximation, not formal do-calculus | P2 |
| Attack graph | Yes | Name resolution issues (fixing) | P1 |
| HTML report | Yes | Missing exec summary, PDF, methodology | P2 |
| Cloud components | No | No Terraform/CloudFormation detector | P1 |
| Serverless | No | No detector exists | P1 |
| Pearl's do-calculus | No | Only inspired by, not compliant with | P2 |
| Historical learning | No | No data collection mechanism | P3 |

---

## For the AMICT Paper

The paper explicitly states these limitations in Section VI (Discussion) subsection B (Limitations). The contribution is the ARCHITECTURE and CONCEPT, not complete coverage. This is standard and acceptable for a prototype paper at a conference.

## For the DBA Dissertation

The dissertation will address Phase 1 and Phase 2 gaps as part of the research. Phase 3 is identified as "future work" and "contribution to practice." The expert panel evaluation validates whether the current (imperfect) output is still MORE useful than manual approaches — which is the actual research question.
