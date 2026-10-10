# Bayora BlindSeal: USP, Technical Investigation, and Decision Record

## 1. Problem Diagnosis & Context

### 1.1 The Actual Problem
In adversarial AI safety testing, three mutually untrusted entities must operate concurrently:
1. **Red Team (Attacker):** Crafts novel adversarial payloads and multi-turn jailbreaks. Payloads are proprietary trade secrets or zero-day exploits that must not leak to defenders before evaluation completes.
2. **Blue Team (Defender):** Develops prompt guards, output filters, classifier weights, and safety policies. Defensive rules and thresholds must not be revealed to the red team to prevent adaptive evasion or overfitting.
3. **Client LLM (Subject under Test):** Executes inference on submitted payloads through defensive guards. It must not retain cross-session state, leak context across tenants, or contaminate subsequent evaluations.

### 1.2 The Conventional Blind Spot
Standard industry approaches assume that running components in separate Docker containers and displaying a pass/fail safety dashboard is sufficient. This assumption is deeply flawed:
- **Evaluation Untrustworthiness:** A test may output "PASS" (no harmful content detected) simply because a stale session corrupted the prompt, a defensive filter timed out silently, the blue team sneaked in an updated rule mid-run, or CPU starvation throttled the safety classifier.
- **Silent State Contamination:** KV caches, residual session contexts, or temporary files on shared mounts leak information between evaluations.
- **Tamperable Audit Records:** Traditional append-only logs can be altered, truncated, or reordered post-run without detection.
- **Premature Disclosure:** Defenders with access to evaluation logs observe live red-team payloads before the test concludes, compromising adversarial test integrity.

**The Core Engineering Question:**
*How can we run adversarial testing, defensive development, and model inference concurrently while maintaining confidentiality, integrity, isolation, reproducibility, and trustworthy evaluation results?*

---

## 2. Structured Investigation of Three Technical Approaches

| Criterion | Approach 1: Hardened Container & Network Isolation | Approach 2: Hardware-Enforced Confidential Computing (TEE) | Approach 3: BlindSeal Validity-Gated Proof-Carrying Evaluation (Selected) |
|---|---|---|---|
| **Underlying Hypothesis** | Namespaces, cgroups, seccomp, and bridge networks are sufficient to isolate tenants. | Hardware enclaves (AMD SEV-SNP / Intel SGX) eliminate host and multi-tenant trust assumptions. | An evaluation outcome is only as trustworthy as the execution environment; results must carry verifiable proof of environmental integrity. |
| **Assumption Challenged** | Challenges the assumption that application-level RBAC is needed by pushing isolation to OS primitives. | Challenges the assumption that the host OS and hypervisor can ever be trusted. | Challenges the foundational assumption that an evaluation result (PASS/FAIL) is meaningful without verifying environmental validity. |
| **Security Weakness Addressed** | Direct process/network snooping between containers. | Malicious host admin, memory scraping, physical/hypervisor interception. | Post-hoc payload swapping, mid-run defense alteration, silent cross-session contamination, log tampering, and false safety conclusions. |
| **Mechanism** | Rootless Docker, dropped capabilities (`CAP_DROP_ALL`), strict seccomp profiles, default-deny network bridge. | Encrypted VM memory, remote hardware attestation, sealed storage keys. | **Seal → Run → Verify → Release** protocol: cryptographic commitment, blinded brokers, canary tripwires, hash-chained ledger, ed25519 digital signature, and a deterministic 4-state validity gate. |
| **Infrastructure Dependencies** | Docker runtime on Linux with cgroups v2 and seccomp. | Specialized cloud VMs (e.g. GCP Confidential VM / Azure DC-series) with TEE support. | Standard Linux/Windows runtime, Python 3.10+, standard cryptography (`hashlib`, `cryptography`), optional container runtime. |
| **Feasibility & Dev Time** | High feasibility (2–3 hours). | Very low feasibility for hackathon (requires specialized cloud hardware, attestation SDKs, complex debugging). | High feasibility (4–6 hours for complete vertical slice). |
| **Likely Failure Modes** | Shared kernel vulnerabilities, timing side-channels, inability to prove that tests were uncorrupted. | Hardware driver mismatches, quota issues, attestation failure during demo, zero local reproducibility. | False invalidations if resource thresholds are set too strictly; orchestrator remains in TCB. |
| **Evaluation Criteria** | Forbidden network probes blocked, container escape prevention. | Remote attestation quote validation, encrypted memory integrity. | Tamper detection rate (100%), canary breach detection (100%), artifact freeze verification (100%), baseline vs invalidation distinction. |
| **Judging Impact** | Moderate/Generic: looks like standard DevSecOps. | High novelty on paper, but high demo risk and unverifiable on local laptop. | **Maximum differentiation**: Directly addresses AI safety evaluation integrity; measurable, interactive, and provably catches corrupted evaluations. |
| **Fallback Plan** | Basic Docker Compose. | Fallback to container isolation. | Tier B: Local process sandbox with tokenized brokers and file isolation if Docker daemon is unavailable. |

### Rationale for Selecting Approach 3 (BlindSeal)
Approach 1 provides necessary baseline hygiene but offers **zero technical novelty**—every containerized system does this. Approach 2 is an impractical research ambition within hackathon constraints that cannot be demonstrated locally without expensive, brittle cloud TEE instances.

Approach 3 combines enforceable baseline controls with a **first-in-class product differentiator**:
1. It solves the actual AI safety evaluation dilemma: **"The model didn't fail. The experiment did."**
2. It introduces a deterministic 4-state gate: `FINDING`, `NO FINDING IN TESTED SCOPE`, `INCONCLUSIVE`, `INVALIDATED`.
3. It implements an independent verifier CLI and signed evidence capsules that any auditor or judge can inspect and verify.
4. It can be implemented, tested, and demonstrated with 100% reproducibility on both cloud Docker environments and local developer runtimes.

---

## 3. Defensible Threat Model & Trust Boundaries

### 3.1 Trust Boundaries & Flow Matrix

```
[Red Tenant Vault]  ---(1. Sealed Suite Commit)---> [Control Plane / Orchestrator] <---(2. Frozen Defense Package)--- [Blue Tenant Vault]
                                                                |
                                                     (Issues Scoped Token)
                                                                v
                                                  [Policy-Enforcing Broker]
                                                   /                     \
                      (3. Sanitized Prompt)       /                       \      (5. Telemetry & Canaries)
                                                 v                         v
                                        [Blue Guard Runtime]      [Observer / Monitor]
                                                 |                         |
                                      (Approved Prompt Only)               |
                                                 v                         v
                                       [Client Model Runtime]     [Hash-Chained Evidence Ledger]
                                                 |                         |
                                                 +---(Model Output)--------+
                                                                           |
                                                                           v
                                                               [Independent Verifier]
                                                                           |
                                                                           v
                                                             [Signed Evidence Capsule]
```

### 3.2 Boundary Enforcement Details

| Boundary | Information Allowed | Forbidden Operations | Enforcement Mechanism | Failure Impact |
|---|---|---|---|---|
| **Red → Broker** | Sealed suite metadata; test prompts under evaluation. | Direct access to blue code, internal guard scores, model weights, or audit signing keys. | Scoped Bearer token, schema validation, isolated network lane. | Broker rejects unauthenticated or out-of-schema requests. |
| **Blue → Broker** | Defense configuration, rule digest, guard decisions (APPROVE / REJECT). | Reading red prompts prior to release; viewing other tenants' sessions. | Scoped Bearer token, isolated storage vault. | Broker rejects direct raw-payload queries. |
| **Broker → Guard** | Current prompt text stripped of metadata. | Access to filesystem outside sandbox; network egress. | Read-only input stream, non-root execution, dropped capabilities. | Guard failure defaults to fail-closed (`INCONCLUSIVE`). |
| **Guard → Model** | Prompts that pass guard policy. | Reusing session history from previous runs; retaining KV cache across tenants. | Fresh session context injection, disabled persistent memory. | Session contamination tripwire triggers `INVALIDATED`. |
| **Observer → Ledger** | Structured event records (hash, timestamp, sequence, event type). | Storing raw prompts, private rule definitions, or secret tokens. | Canonical JSON serializer, SHA-256 chaining, ed25519 signing key. | Verifier detects chain break or signature mismatch. |

### 3.3 Adversary Classes & Scope of Guarantees

1. **Curious Red/Blue Tenant:** Attempting to read rival files, query unauthorized API endpoints, or probe internal telemetry.
   - *Status: PREVENTED & DETECTED.* Enforced by scoped tokens, separated storage vaults, canary tripwires, and broker routing.
2. **Post-Hoc Manipulator:** Attempting to alter test suites, replace defense filters, or edit audit logs after evaluation.
   - *Status: DETECTED & INVALIDATED.* Enforced by pre-run cryptographic commitment (SHA-256 / Merkle root), hash-chained ledger, and asymmetric digital signatures.
3. **Session Contamination / Stale Context:** Attempting to leak previous test data into current evaluations.
   - *Status: DETECTED & INVALIDATED.* Enforced by unique synthetic canary markers and fresh-context enforcement.
4. **Resource Exhaustion Attacker:** An adversarial payload designed to starve CPU/memory and cause denial-of-service or bypass timing guards.
   - *Status: MEASURED & GATED.* Resource quotas and latency thresholds flag runs exceeding tolerance as `INVALIDATED`.
5. **Compromised Host Administrator / Kernel Exploiter:**
   - *Status: OUT OF SCOPE (Explicitly Acknowledged).* Ordinary containers share the host kernel. If the host root user or signing key is compromised, the host can forge events. Production requires external transparency logs (e.g. Sigstore/Rekor) and hardware TEEs.

---

## 4. Key Engineering Decisions

1. **Deterministic 4-State Evaluation Gate:**
   - `FINDING`: Targeted safety violation observed during a structurally valid run.
   - `NO FINDING IN TESTED SCOPE`: No violation observed in tested scope during a valid run.
   - `INCONCLUSIVE`: Execution timed out, ambiguous output, or missing optional signals.
   - `INVALIDATED`: Critical isolation failure, canary breach, artifact mismatch, audit chain break, or resource budget violation.
2. **Cryptographic Primitives:**
   - Hashes: Canonical JSON serialization (`RFC 8785`-inspired sorting and compact formatting) + SHA-256.
   - Signatures: Ed25519 asymmetric cryptography via Python `cryptography` package.
   - Commitments: Pre-run manifest digest linking test suite, defense package, policy version, and sandbox profile.
3. **Dual Execution Runtime Architecture:**
   - **Cloud/Production Configuration:** Docker Compose with non-root UID (10001), read-only root filesystems, dropped capabilities (`ALL`), explicit user-defined networks, and resource limits (`cpus: 1.0`, `mem_limit: 1g`).
   - **Local Developer/Demo Harness:** Process-sandboxed micro-services with port/socket isolation, distinct tenant storage vaults, token-based broker routing, and psutil-based resource tracking, enabling 100% reliable execution on Windows/macOS/Linux without external Docker daemon dependencies.
4. **Interactive Demonstration Sequence:**
   - Scene 1: Normal Verified Run (`NO FINDING IN TESTED SCOPE` / `VALID`).
   - Scene 2: Cross-Tenant Breach Attempt (Canary tripwire tripped -> `INVALIDATED`).
   - Scene 3: Post-Run Audit Tampering (Event modified -> Verifier flags `CHAIN_TAMPERED` -> `INVALIDATED`).
   - Scene 4: Model Session Contamination (Canary marker echoed -> `INVALIDATED`).
   - Scene 5: Resource Starvation / Timing Contention (Latency spike -> Threshold exceeded -> `INVALIDATED`).

---

## 5. Verification & Acceptance Criteria

- **AC-1:** Automated test suite runs with 100% pass rate covering isolation, blindness, audit tampering, session contamination, and resource bounds.
- **AC-2:** Tampering with a single byte in any event log or manifest causes the verifier CLI to reject the run with an exact cryptographic diagnosis.
- **AC-3:** Zero raw payload text or blue private rule secrets appear in general audit logs or public manifests.
- **AC-4:** The operator UI provides a live, clear visualization of the 4-state gate, evidence verification, and honest residual risk scorecard.
