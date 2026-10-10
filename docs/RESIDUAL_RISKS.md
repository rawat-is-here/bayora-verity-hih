# Bayora BlindSeal: Residual Risks & Production Hardening Requirements

A credible security architecture is defined by the honesty of its trust boundaries. This document outlines the explicit technical limitations of the current implementation and the production engineering required to deploy Bayora BlindSeal at cloud scale.

---

## 1. Explicit Residual Risks in Current Architecture

### 1.1 Shared Host Kernel & Host Administrator Compromise
- **Current Limitation:** In single-host deployments, the operating system kernel is shared across process sandboxes or Docker containers. A malicious root administrator on the host machine or a kernel privilege-escalation vulnerability can bypass container namespaces, inspect process memory, or extract the evaluator Ed25519 signing key.
- **Production Requirement:**
  1. Multi-host architectural separation: The Evaluator signing service must execute on an isolated, physically distinct machine from tenant workloads.
  2. Public transparency log checkpointing: Post-run checkpoints must be anchored into an immutable, append-only public transparency log (e.g., Sigstore Rekor) to ensure that even a compromised host cannot rewrite historical audit ledgers retroactively without public detection.
  3. Hardware Security Modules (HSM): Signing keys must be held within an HSM or KMS with hardware-enforced non-exportability.

---

### 1.2 Microarchitectural & Cache Timing Side-Channels
- **Current Limitation:** Modern multi-tenant CPU architectures share L1, L2, and L3 caches, memory buses, and execution units. While Bayora's `ResourceGovernanceMonitor` measures macro-level latency spikes and memory starvation, software throttling cannot eliminate physical microarchitectural cache timing differences between threads running on adjacent CPU cores.
- **Production Requirement:**
  1. Core pinning & cache partitioning: Use Linux `taskset` and Intel Resource Director Technology (RDT) / AMD PQOS to assign dedicated L3 cache ways and memory bandwidth to inference workers.
  2. Hardware Confidential Computing (TEE): Deploy inference workers on confidential cloud instances (AMD SEV-SNP or Intel TDX) with encrypted memory and hypervisor isolation.

---

### 1.3 Black-Box Statistical Inference
- **Current Limitation:** The Blue Guard sanitizes its external responses to Red, returning only `BLOCKED` or `PERMITTED` without rule IDs, weights, or confidence scores. However, if an attacker is granted thousands of adaptive queries over time, the boundary of the defensive classifier can theoretically be estimated through statistical black-box query probing.
- **Production Requirement:**
  1. Per-campaign query rate limiting and anomaly gating: Impose hard limits on the total number of probe mutations an attacker can dispatch per round.
  2. Output jitter & differential privacy: Introduce controlled latency jitter or randomized response perturbations for edge-case classifications to frustrate gradient-free estimation attacks.

---

### 1.5 Resource Telemetry Observation vs Hard Kernel Limits
- **Current Limitation:** The `ResourceGovernanceMonitor` uses `psutil` to sample process metrics (latency, RSS memory, CPU time). When a budget is breached, it flags the run for deterministic invalidation (`Verdict.INVALIDATED`). However, `psutil` **observes and detects**; it does not enforce kernel-level preemptive resource preemption or memory ceilings.
- **Production Requirement:**
  1. Linux cgroups v2 kernel controllers: Configure `memory.max` and `cpu.max` in systemd or containerd to enforce hard preemptive kill/throttle limits at the OS kernel level.
  2. MicroVM sandboxing: Wrap each inference execution in an isolated Firecracker or gVisor microVM with fixed memory allocation.

---

### 1.6 Synthetic Canary Detection vs Physical LLM Memory Isolation
- **Current Limitation:** Synthetic canary tripwires prove that if context bleeding occurs, the detection pipeline triggers an immediate invalidation and blocks staged release. However, a synthetic canary cannot guarantee that unmodeled subtle semantic context (e.g. weight adjustments or unevicted KV-cache tokens without canary text) is physically erased from GPU memory.
- **Production Requirement:**
  1. Dedicated worker process recycling: Destroy and re-instantiate worker inference processes between evaluation sessions to guarantee fresh memory state.
  2. Hardware TEEs (AMD SEV-SNP): Deploy inference inside confidential virtual machines with encrypted memory and hypervisor isolation.

---

## 2. Security Claims Matrix

| Claim | Verified in Prototype? | Residual Risk / Scope |
|---|---|---|
| **Zero Direct File Traversal** | **YES** | Enforced by path normalization, TOCTOU checks, and anti-traversal resolvers within tenant storage. |
| **Tamper-Evident Event Ledger** | **YES** | RFC 8785 canonical JSON, SHA-256 hash chaining, and Ed25519 signatures detect all tested modifications, deletions, reorderings, and truncations. |
| **Cryptographic Release Gate** | **YES** | Broker independently verifies signed checkpoint, run ID, manifest digest, and trusted key before transitioning to VERIFIED. Unverified caller objects claiming VALID are rejected. |
| **Server-Side API Enforcement** | **YES** | Dashboard routes all artifact access through the broker with HMAC capability tokens; unauthenticated and cross-tenant requests return 401/403. |
| **Canary Contamination Detection** | **YES** | Detects synthetic decoy token carryover across sessions; does not guarantee physical GPU memory wipe without process restarts. |
| **Macro Resource Governance** | **YES (Observed)** | Detects process latency and memory violations beyond declared budget; does not enforce hard kernel cgroup preemption. |
| **Benchmark Generalizability** | **Bounded Scope** | 0% false acceptance rate is an empirical measurement across the 8 tested adversarial scenarios; ~4ms overhead reflects the tested host environment, not a universal guarantee. |
| **Universal Leakage Immunity** | **NO (Non-Claim)** | We explicitly reject absolute claims of "zero leakage" or "100% security." |

