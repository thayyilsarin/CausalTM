# CausalTM Architecture v2 — Definitive Design

## Core Principle

CausalTM is a **STRIDE-based Threat Modeling** tool. It does NOT fix vulnerabilities — that is the job of SAST and DAST tools. CausalTM consumes their outputs to **understand the application's architecture** and then applies **STRIDE threat analysis** to that architecture using **Federated Causal AI** for reasoning.

---

## The Five-Layer Stack

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 5: STRIDE THREAT MODEL (The Cream Layer)                     │
│  ═══════════════════════════════════════════════                     │
│  What: Identifies DESIGN-LEVEL threats from architecture            │
│  Input: Complete architecture understanding from Layer 4            │
│  Output: Threat Model + Remediation Roadmap to 0% risk             │
│                                                                     │
│  This layer asks: "Given this architecture, what can go wrong       │
│  from a Spoofing, Tampering, Repudiation, Information Disclosure,   │
│  Denial of Service, and Elevation of Privilege perspective?"        │
│                                                                     │
│  It does NOT need any vulnerability to exist. Architecture alone    │
│  is sufficient to identify threats.                                 │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 4: MASTER DAG (Cross-Layer Causal Reasoning)                 │
│  ══════════════════════════════════════════════════                  │
│  What: Combines edge nodes from all sub-DAGs, performs causal       │
│        inference across layers, bidirectional propagation            │
│  Input: Edge nodes (effect variables) from each sub-DAG             │
│  Output: Unified architecture understanding + risk quantification   │
│                                                                     │
│  Capabilities:                                                      │
│    • Counterfactual: "What causes the current risk?"                │
│    • What-If: "If I fix X, what changes across ALL layers?"         │
│    • Bidirectional: Forward (fix → impact) + Backward (target →     │
│      what to fix)                                                   │
│    • Cross-layer side effects: fixing in one layer may             │
│      create/resolve issues in another                               │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 3: SUB-DAGs (Per-Source Architecture Extraction)             │
│  ═════════════════════════════════════════════════════               │
│  What: Each sub-DAG extracts ARCHITECTURE UNDERSTANDING from        │
│        its data source — not vulnerability counts                   │
│                                                                     │
│  SAST Sub-DAG:                                                      │
│    Input: SARIF report                                              │
│    Extracts: What security controls EXIST in code?                  │
│      • Authentication patterns present? Where? Gaps?                │
│      • Encryption/crypto used? Properly? Gaps?                      │
│      • Input validation implemented? Where missing?                 │
│      • Audit logging present?                                       │
│    Edge nodes (effects): auth_posture, crypto_posture,              │
│                          input_validation_posture, logging_posture   │
│                                                                     │
│  DAST Sub-DAG:                                                      │
│    Input: ZAP/Netsparker XML report                                 │
│    Extracts: What does the application LOOK LIKE at runtime?        │
│      • What endpoints are exposed? (attack surface)                 │
│      • Is authentication enforced? (confirmed or bypassable)        │
│      • Is encryption active? (TLS working or broken)                │
│      • What information leaks? (headers, errors, responses)         │
│    Edge nodes (effects): runtime_auth_enforcement,                   │
│                          runtime_encryption_status,                  │
│                          exposed_attack_surface,                     │
│                          information_leakage_level                   │
│                                                                     │
│  Repo Sub-DAG:                                                      │
│    Input: Source code repository                                    │
│    Extracts: What is the STRUCTURAL DESIGN?                         │
│      • Components (services, databases, external entities)          │
│      • Data flows (what connects to what, carrying what data)       │
│      • Trust boundaries (network zones, access levels)              │
│      • Defense layers (WAF, gateway, segmentation)                  │
│    Edge nodes (effects): topology_exposure, data_sensitivity,       │
│                          trust_boundary_integrity,                   │
│                          defense_depth                               │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 2: INGESTORS (Parse & Normalize)                             │
│  ═══════════════════════════════════════                             │
│  What: Parse raw reports into structured data                       │
│  SARIF parser → normalized findings                                 │
│  ZAP XML parser → normalized findings                               │
│  Repo file walker → file list + content                             │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 1: INPUT SOURCES (External — Not Our Job)                    │
│  ═══════════════════════════════════════════════                     │
│  SAST tool (Semgrep/Coverity): Finds & tracks code vulnerabilities  │
│  DAST tool (ZAP/Netsparker): Finds & tracks runtime vulnerabilities │
│  Git repository: Contains source + infrastructure configs           │
│                                                                     │
│  These tools FIX their own findings. We don't duplicate that work.  │
│  We CONSUME their output to understand the application design.      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## How Each Sub-DAG Extracts Architecture (Not Vulnerability Counts)

### SAST Sub-DAG: "What Security Controls Exist in the Code?"

The SAST report is NOT used to count bugs. It's used to answer architectural questions:

```
From SAST findings, we INFER:
─────────────────────────────
CWE-287 (Missing Auth) found     → Architecture has AUTH GAPS
CWE-287 NOT found                → Architecture has AUTH COVERAGE (control exists)

CWE-311 (Missing Encryption)     → Architecture has ENCRYPTION GAPS  
CWE-311 NOT found                → Architecture has ENCRYPTION (control exists)

CWE-89 (SQL Injection)           → Architecture has NO INPUT VALIDATION at this boundary
CWE-89 NOT found                 → Architecture has INPUT VALIDATION (control exists)

CWE-778 (Missing Logging)        → Architecture has NO AUDIT TRAIL
CWE-778 NOT found                → Architecture has AUDIT LOGGING (control exists)
```

**The sub-DAG's internal causal model:**

```
[Individual SAST findings] ──are symptoms of──▶ [Architectural control gaps]
                                                         │
                                                    EFFECT (edge node)
                                                         │
                                                         ▼
                                    "Auth Posture = 0.4" (40% of boundaries have auth)
                                    "Crypto Posture = 0.7" (70% of sensitive flows encrypted)
                                    "Validation Posture = 0.3" (30% of inputs validated)
                                    "Logging Posture = 0.2" (20% of actions logged)
```

**Edge nodes represent ARCHITECTURAL STATE, not vulnerability count.**

### DAST Sub-DAG: "What Does the Application Actually Look Like Running?"

```
From DAST findings, we INFER:
─────────────────────────────
Auth bypass found at /admin      → Architecture's auth IS BYPASSABLE at runtime
CSP header missing               → Architecture LEAKS information in responses
TLS issues found                 → Architecture's encryption IS BROKEN at runtime
Directory listing enabled        → Architecture EXPOSES internal structure
No findings on /api with JWT     → Architecture's auth WORKS on this endpoint
```

**Edge nodes represent RUNTIME ARCHITECTURAL REALITY:**

```
"Runtime Auth Enforcement = 0.6" (60% of endpoints properly enforce auth)
"Runtime Encryption = 0.8" (80% of connections use valid TLS)
"Attack Surface = 0.5" (50% of internal surface is externally reachable)
"Information Leakage = 0.3" (responses leak 30% more info than necessary)
```

### Repo Sub-DAG: "What Is the Structural Design?"

```
From repository, we DETECT:
────────────────────────────
docker-compose.yml        → Services, their connections, exposed ports
Kubernetes manifests      → Trust boundaries (namespaces), ingress exposure  
API specifications        → Data models, endpoint design, auth schemes
Config files              → Database connections, external dependencies
Terraform/CloudFormation  → Cloud resources, network topology, IAM
```

**Edge nodes represent STRUCTURAL DESIGN:**

```
"Topology Exposure = 0.5" (50% of services directly reachable from outside)
"Data Sensitivity = 0.9" (system handles credentials + PII + financial)
"Trust Boundary Integrity = 0.6" (60% of cross-boundary flows have controls)
"Defense Depth = 0.4" (limited layered defenses)
```

---

## The Master DAG: Cross-Layer Architecture Understanding

The Master DAG receives edge nodes from all three sub-DAGs and builds a **unified picture of the architecture's security posture**:

```
FROM SAST:                    FROM DAST:                   FROM REPO:
auth_posture = 0.4            runtime_auth = 0.6           topology_exposure = 0.5
crypto_posture = 0.7          runtime_encryption = 0.8     data_sensitivity = 0.9
validation_posture = 0.3      attack_surface = 0.5         boundary_integrity = 0.6
logging_posture = 0.2         info_leakage = 0.3           defense_depth = 0.4

         │                           │                           │
         └───────────────────────────┼───────────────────────────┘
                                     │
                                     ▼
                         MASTER DAG REASONING:

    "Auth posture in code (0.4) + Auth enforcement at runtime (0.6) + 
     Topology exposure (0.5) = Architecture has PARTIAL AUTH with GAPS"
     
    "Crypto in code (0.7) + Encryption at runtime (0.8) + 
     Boundary integrity (0.6) = Architecture has MOSTLY ENCRYPTED but 
     some cross-boundary flows are UNPROTECTED"
     
    "Low validation (0.3) + Medium attack surface (0.5) + 
     High data sensitivity (0.9) = Architecture is HIGHLY VULNERABLE 
     to data manipulation through unvalidated inputs"
```

### Cross-Layer Dependencies (Bidirectional)

The Master DAG also captures how layers INTERACT:

```
CROSS-LAYER RULES:

"If SAST auth_posture improves → DAST runtime_auth should also improve"
  (fixing auth in code → auth works at runtime)

"If Repo adds API gateway → DAST attack_surface decreases"
  (architectural change → fewer endpoints exposed)

"If SAST removes encryption → DAST runtime_encryption degrades"
  (code change → runtime effect)

"If Repo removes WAF → DAST info_leakage may increase"
  (removing defense → new exposures appear)
```

---

## STRIDE Layer: The Cream (Layer 5)

STRIDE sits ABOVE the Master DAG and evaluates the **complete architecture understanding** against the six threat categories:

```
STRIDE receives from Master DAG:
──────────────────────────────────
  • Complete architecture map (components, flows, boundaries)
  • Security posture per boundary (auth, crypto, validation, logging)
  • Runtime confirmation (what's actually enforced vs. what's designed)
  • Cross-layer consistency (is code aligned with runtime? design aligned with implementation?)

STRIDE asks for EACH data flow / trust boundary crossing:
──────────────────────────────────────────────────────────

  SPOOFING:
    "Can the identity of the sender be verified at this boundary?"
    Input: auth_posture (SAST) + runtime_auth (DAST) + boundary_integrity (Repo)
    If auth_posture < threshold AND runtime_auth < threshold → SPOOFING THREAT

  TAMPERING:
    "Can data be modified in transit across this boundary?"
    Input: crypto_posture (SAST) + runtime_encryption (DAST) + boundary_integrity (Repo)
    If encryption is absent or broken → TAMPERING THREAT

  REPUDIATION:
    "Can actions be denied? Is there an audit trail?"
    Input: logging_posture (SAST) + topology (Repo)
    If logging_posture < threshold → REPUDIATION THREAT

  INFORMATION DISCLOSURE:
    "Can sensitive data be exposed to unauthorized parties?"
    Input: data_sensitivity (Repo) + info_leakage (DAST) + crypto_posture (SAST)
    If high sensitivity data flows without encryption → INFORMATION DISCLOSURE THREAT

  DENIAL OF SERVICE:
    "Can the service be made unavailable?"
    Input: defense_depth (Repo) + attack_surface (DAST) + topology_exposure (Repo)
    If single point of failure AND high exposure → DOS THREAT

  ELEVATION OF PRIVILEGE:
    "Can an attacker gain higher access than intended?"
    Input: auth_posture (SAST) + runtime_auth (DAST) + topology (Repo)
    If direct access from low-trust to high-trust without auth → EOP THREAT
```

---

## Counterfactual & What-If (Bidirectional Propagation)

### Forward: "If I fix X, what happens everywhere?"

```
User asks: "What if I add authentication to the Frontend→Backend flow?"

1. APPLY in Repo sub-DAG:
   → Data flow updated: is_authenticated = true
   → Edge node: boundary_integrity improves (0.6 → 0.8)

2. CROSS-LAYER propagation:
   → SAST: auth_posture should improve (if code implements the auth)
   → DAST: runtime_auth should improve (auth now enforced)

3. MASTER DAG recalculates:
   → Overall auth posture improves
   → Attack surface doesn't change (still exposed, but now protected)

4. STRIDE re-evaluates:
   → Spoofing threat on this flow: MITIGATED
   → Elevation of Privilege via this path: MITIGATED
   → Other threats: unchanged

5. RESULT:
   "Adding auth on Frontend→Backend eliminates 2 STRIDE threats,
    reduces overall risk from 0.72 → 0.55 (24% reduction)"
```

### Backward: "What must I fix to eliminate this STRIDE threat?"

```
User asks: "How do I eliminate the Information Disclosure threat on the DB flow?"

1. STRIDE identifies the threat's CAUSES:
   → Data flow carries PII (data_sensitivity = 0.9)
   → Flow is not encrypted (crypto_posture for this flow = 0)
   → DAST confirms data visible in transit (runtime_encryption = 0 on this flow)

2. BACKWARD propagation asks: "What changes would make this threat disappear?"
   → OPTION A: Encrypt the flow (Repo: add TLS to DB connection)
     → Cross-layer: SAST crypto_posture improves, DAST runtime_encryption improves
     → Net: Threat ELIMINATED
   → OPTION B: Remove sensitive data from this flow (redesign)
     → Cross-layer: data_sensitivity for this flow drops
     → Net: Threat ELIMINATED but requires redesign
   → OPTION C: Add compensating control (network isolation so only backend reaches DB)
     → Cross-layer: topology_exposure drops for DB, defense_depth improves
     → Net: Threat MITIGATED (not eliminated — data still unencrypted but unreachable)

3. RESULT:
   "To eliminate Info Disclosure on DB flow:
    BEST: Add TLS encryption (effort: 2h, eliminates threat fully)
    ALT: Network isolation (effort: 4h, mitigates but doesn't eliminate)
    
    Adding TLS also resolves: SAST CWE-311 finding, DAST TLS warning
    Cross-layer benefit: 2 additional findings auto-resolve"
```

### Sequenced Roadmap: "How do I get to 0%?"

```
STEP 1: What SINGLE fix has the highest cross-layer impact?
  → Answer: "Add API gateway" (resolves 3 STRIDE threats across all layers)

STEP 2: Given Step 1 done, what's next?
  → Answer: "Encrypt DB connection" (resolves 2 remaining Info Disclosure threats)

STEP 3: Given Steps 1+2, what's next?
  → Answer: "Add audit logging" (resolves all Repudiation threats)

... continue until all STRIDE threats = 0
```

---

## Data Flow Diagram (DFD) Role

The DFD is generated from the **Repo sub-DAG's topology understanding** and annotated with **STRIDE findings from Layer 5**:

```
DFD shows:
  • Components (from Repo)
  • Data flows (from Repo, enriched with SAST data types + DAST confirmation)
  • Trust boundaries (from Repo)
  • STRIDE threats PER ELEMENT (from Layer 5)
  • Color coding by threat severity
  • Annotations: "Auth: ✓ (SAST confirms) ✓ (DAST confirms)" or "Auth: ✗ (SAST gap) ✗ (DAST bypass)"
```

---

## Summary: What CausalTM IS and IS NOT

### IS:
- A STRIDE-based threat modeling tool for application ARCHITECTURE
- Consumes SAST/DAST to UNDERSTAND the design (not to fix vulns)
- Uses Federated Causal AI to reason across layers
- Produces a remediation ROADMAP (architecture fixes first)
- Accounts for cross-layer side effects of every fix

### IS NOT:
- A vulnerability scanner (SAST/DAST tools do that)
- A vulnerability manager (those tools track their own fixes)
- A code fixer (developers do that)
- A replacement for SAST/DAST (it consumes them, doesn't replace them)

### The Value Proposition:
> "SAST tells you what's wrong in code. DAST tells you what's wrong at runtime. CausalTM tells you what's wrong with the ARCHITECTURE — and gives you the exact sequence of design changes that eliminates all threats, accounting for the fact that fixing one thing can affect everything else."
