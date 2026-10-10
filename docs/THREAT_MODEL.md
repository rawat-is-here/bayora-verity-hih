# Bayora BlindSeal: Threat Model & Security Control Status

## 1. System Assets

1. **Red Team Payloads:** Zero-day prompt injection sequences, jailbreak templates, and multi-turn attack strategies.
2. **Blue Team Defense Code:** Safety filter heuristics, classifier weights, threshold configurations, and rule dictionaries.
3. **Client LLM State:** Model parameters, conversational context, inference KV-cache, and generated output streams.
4. **Audit Evidence:** Pre-run sealed manifests, hash-chained audit event records, terminal checkpoints, and evaluator signing keys.
5. **System Availability & Timing:** Compute budget, memory limits, and inference execution latency.

---

## 2. Adversary Classes & Capabilities

| Adversary Profile | Assumed Capabilities | Intended Attack |
|---|---|---|
| **Curious Defender (Blue)** | Legitimate access to Blue workspace; access to evaluation results. | Tries to read Red attack payloads prior to release; attempts path traversal to inspect rival vault. |
| **Curious Attacker (Red)** | Legitimate access to Red workspace; submits test suites. | Probes Blue defense logic, inspects internal classifier scores or thresholds to craft evasion attacks. |
| **Tampering Adversary** | Can intercept or modify post-run files on disk if unprotected. | Alters event records, changes manifest digests, reorders events, or truncates audit trails to conceal failures. |
| **Contaminating Workload** | Malicious or buggy payload attempting state carry-over. | Injects canary markers into conversational context to persist state across sessions. |
| **Resource Starvation Attacker** | Submits algorithmic-complexity prompts. | Spikes CPU/memory to starve defense filters and cause silent fallbacks or timing anomalies. |
| **Compromised Host Admin** | Root access to host kernel, memory scraper, hypervisor operator. | **Explicit Residual Risk**: Can forge local events or extract signing keys. Requires multi-host remote witness in production. |

---

## 3. Security Controls Status: Implemented vs. Tested vs. Simulated vs. Unimplemented

| Control | Mechanism | Status | Evidence / Test |
|---|---|---|---|
| **Tenant Vault Boundary** | Path-normalized directories per tenant (`red/`, `blue/`, `model/`, `system/`), anti-traversal check. | **IMPLEMENTED & TESTED** | `test_path_traversal_prevention_on_read_and_write` in `test_phase2_broker_and_vaults.py`. |
| **Server-Side Token Auth** | HMAC-SHA256 capability tokens bound to actor, tenant, and roles. | **IMPLEMENTED & TESTED** | `test_altered_tenant_token_tampering` in `test_phase2_broker_and_vaults.py`. |
| **Staged Red Disclosure** | Staged release policy: `SEALED` → `BLINDED` → `VERIFIED` → `RELEASED`. Premature & invalidated release forbidden. | **IMPLEMENTED & TESTED** | `test_premature_release_attempt_blocked`, `test_release_forbidden_on_invalidated_run`, `test_authorized_post_verification_release`. |
| **Zero Raw Leakage in Audit** | Broker logs structured metadata and SHA-256 digests; raw payload text stripped from events. | **IMPLEMENTED & TESTED** | `test_audit_ledger_records_all_access_attempts_without_raw_secrets`. |
| **Tamper-Evident Ledger** | RFC 8785 canonical JSON, SHA-256 hash chaining, Ed25519 checkpoint signature. | **IMPLEMENTED & TESTED** | 18 automated tests in `test_phase1_evidence_core.py` covering modification, reordering, deletion, truncation, key substitution, and removal. |
| **Deterministic Validity Gate** | 4-state verdict machine: `VALID`, `INVALIDATED`, `INCONCLUSIVE`, `NOT_EVALUATED`. | **IMPLEMENTED & TESTED** | `test_tripwire_canary_breach_detection`, `test_telemetry_offline_is_inconclusive`, `test_lifecycle_pre_execution_is_not_evaluated`. |
| **Hardened Container Profile** | Docker Compose with non-root UID 10001, read-only rootfs, dropped capabilities, isolated bridge network, cgroup quotas. | **IMPLEMENTED (Configuration Artifact)** | `docker-compose.yml`, `Dockerfile.worker`. |
| **Session Canary Tripwires** | Synthetic canary markers in prompts to detect conversational state carry-over. | **PHASE 3 SCOPE** | Planned for Phase 3 integration with inference adapter. |
| **Resource Interference Monitor** | psutil/cgroup tracking of latency, CPU times, and memory limits against declared profile. | **PHASE 3 SCOPE** | Planned for Phase 3 observer. |
| **Hardware TEE Attestation** | AMD SEV-SNP / Intel TDX remote hardware memory attestation. | **UNIMPLEMENTED / PRODUCTION REQUIREMENT** | Not available on local development host; documented as production cloud requirement. |
| **External Transparency Log** | Sigstore/Rekor public log anchoring to protect against fully compromised host root user. | **UNIMPLEMENTED / PRODUCTION REQUIREMENT** | Out of scope for single-machine hackathon; documented in residual risks. |

---

## 4. Explicit Non-Guarantees and Residual Risks

1. **Black-Box Statistical Inference:** If an attacker can adaptively query the model and observe output classifications over hundreds of runs, some defensive properties may be statistically inferable. We prevent direct code and config access, but cannot eliminate mathematical inference over observable model outputs.
2. **Host Kernel Compromise:** Ordinary container isolation and process sandboxing share the underlying OS kernel. A root exploit against the host operating system bypasses software-enforced boundaries.
3. **Microarchitectural Timing Channels:** Software resource throttling detects macro-level CPU and memory starvation, but does not eliminate physical L1/L2/L3 cache timing side-channels on shared CPU cores.
