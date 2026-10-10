# Architecture Decision Record (ADR 001): BlindSeal Core Architecture

**Title:** BlindSeal Proof-Carrying Validity-Gated Evaluation Architecture  
**Status:** Accepted  
**Date:** 2026-10-09  
**Authors:** Bayora Security & Architecture Team  

---

## 1. Context and Problem Definition

Adversarial AI safety testing requires three mutually untrusted entities:
1. **Red Team:** Authors adversarial test suites that must remain confidential from defenders before permitted release.
2. **Blue Team:** Authors defensive guards whose private rules must not be exposed to attackers.
3. **Client LLM:** Processes prompts through guards without retaining state, leaking context, or contaminating subsequent sessions.

Conventional systems deploy these services into Docker containers and output a binary safety score (`PASS` or `FAIL`). This is dangerous: an apparent `PASS` may be caused by a silently crashed guard, an altered test suite, a mid-run defense edit, a stale context, or resource starvation.

**Core Thesis:**
An AI safety evaluation outcome is only meaningful if the execution environment is provably trustworthy and uncontaminated. The evaluation must produce an explicit environmental validity verdict supported by independent cryptographic evidence.

---

## 2. Verdicts vs. Lifecycle States

To avoid conflating execution progression with evaluation integrity, we enforce a strict separation between **Lifecycle States** and **Verdict Outcomes**.

### 2.1 Lifecycle States (Process State Machine)
- `CREATED`: Run initialized with configuration and declared boundaries.
- `SEALED`: Pre-run manifest committed (test suite hash, defense digest, model version, policy digest).
- `EXECUTING`: Workloads running; broker routing prompts; observer recording events.
- `COMPLETED`: Workloads finished execution; terminal checkpoint generated.
- `ABORTED`: Run terminated early due to unrecoverable system error or manual cancellation.

### 2.2 Verdict Outcomes (Integrity Assessment)
The system produces exactly one of four mutually exclusive verdicts:

| Verdict | Definition | Explicit Deterministic Criteria |
|---|---|---|
| `VALID` | The evaluation environment satisfied all declared integrity, isolation, and provenance conditions. | All required lifecycle events present; event hash chain intact; terminal checkpoint Ed25519 signature valid; sealed artifact digests match runtime digests; zero critical canary/isolation violations; resource measurements within declared profile tolerance. |
| `INVALIDATED` | A required integrity condition failed, rendering the evaluation untrustworthy. | Any of: hash chain broken, terminal checkpoint signature invalid, sequence gap or reordering, artifact digest mismatch, critical canary breach detected, unauthorized boundary traversal observed, or declared resource/latency budget exceeded. |
| `INCONCLUSIVE` | The system lacks sufficient evidence to establish validity, or output classification timed out/failed. | Required telemetry monitor offline; missing non-fatal checkpoint signal under fail-closed policy; worker timeout; or ambiguous classifier output. |
| `NOT_EVALUATED` | The run was terminated before evaluation commenced or was explicitly bypassed. | Run aborted in `CREATED` or `SEALED` state prior to execution, or run created under dry-run inspection mode. |

> **Crucial Distinction:** A `VALID` infrastructure verdict does **not** mean the client LLM is safe. It means the experiment was uncontaminated. Within a `VALID` run, the model outcome may be `FINDING` (vulnerability found) or `NO_FINDING_IN_TESTED_SCOPE` (no vulnerability found in this specific test set). An `INVALIDATED` run rejects the entire test result regardless of model output.

---

## 3. Cryptographic Evidence Verifier & Terminal Checkpoint

To enable independent verification without third-party trust, the evidence pipeline implements an ordered, tamper-evident audit ledger anchored by a trusted terminal checkpoint.

### 3.1 Event Structure
Each event is serialized using deterministic canonical JSON (`RFC 8785` key sorting, no superfluous whitespace, UTF-8 encoded) and linked:
```
event_hash = SHA-256( canonical_json(event_without_hash) || previous_event_hash )
```
Genesis event uses `previous_event_hash = "0" * 64`.

### 3.2 Terminal Checkpoint Mechanism
At completion, the evaluator signing service creates and signs a `RunCheckpoint`:
```json
{
  "run_id": "uuid",
  "manifest_digest": "sha256:...",
  "event_count": 14,
  "final_sequence_number": 13,
  "final_event_hash": "sha256:...",
  "created_at": "2026-10-09T12:00:00Z"
}
```
The checkpoint is signed using an **Ed25519** private key held only by the trusted evaluator service. The corresponding public key is bundled with the verifier.

### 3.3 Tamper Detection Guarantees
The standalone verifier (`verify.py`) deterministically detects:
1. **Modification:** Changing any field in any event causes recalculation of that event's hash to mismatch the recorded `event_hash` and breaks downstream links.
2. **Reordering:** Invariant `event[i].sequence_number == i` and `event[i].previous_event_hash == event[i-1].event_hash` detects swapped events.
3. **Deletion:** Removing an event introduces a sequence number gap and breaks the hash chain linkage.
4. **Truncation:** Removing events from the tail reduces `event_count` or produces an end hash that does not match `final_event_hash` in the signed `RunCheckpoint`.
5. **Invalid Signature:** Corrupting the checkpoint or signature fails Ed25519 cryptographic verification against the public key.
6. **Missing Required Events:** The verifier checks an explicit set of required event types (`RUN_SEALED`, `EXECUTION_STARTED`, `EXECUTION_COMPLETED`, `CHECKPOINT_CREATED`). If any is absent, the run is rejected.

---

## 4. Precisely Scoped Security Properties (No Absolute Claims)

We replace unsupportable claims with precise, falsifiable guarantees:

- **Audit Ledger Integrity:** Detects any single-byte or multi-byte modification, reordering, deletion, or truncation within the recorded event stream, relative to the signed terminal checkpoint, assuming the collision resistance of SHA-256 and an uncompromised Ed25519 signing key.
- **Tenant Access Boundary:** Enforces token-based route authorization at the broker, rejecting direct unauthorized API access between tenant identities and preventing pre-release exposure of raw test payloads through authorized endpoints.
- **Canary Breach Detection:** Detects read or query access to designated synthetic canary artifacts within monitored storage and API paths; does not guarantee detection of accesses that successfully bypass monitored paths without touching canaries.
- **Session State Independence:** Enforces fresh session contexts per test case and detects synthetic canary markers echoed in subsequent sessions; does not guarantee mathematical absence of microarchitectural hardware-level cache persistence.
- **Resource Governance:** Measures process CPU time, memory RSS, and latency percentiles, triggering invalidation when measured values exceed predeclared profile limits; does not eliminate physical hardware timing side channels on shared CPU cores.

---

## 5. Security Taxonomy: Prevention, Detection, Verification, Simulation, and Residual Risk

| Category | Definition | Implemented Mechanisms in Bayora |
|---|---|---|
| **Prevention** | Active controls that block unauthorized actions before they occur. | Token-based broker authorization, strict request schema filtering, isolated tenant file vaults, non-root execution. |
| **Detection** | Reactive monitors that alert when an unauthorized event or boundary crossing occurs. | Canary file access tripwires, cross-session marker probes, latency/CPU starvation anomaly monitors. |
| **Verification** | Post-hoc cryptographic checks proving integrity relative to a trusted anchor. | SHA-256 hash-chain verification, artifact digest matching against sealed manifest, Ed25519 checkpoint signature verification. |
| **Simulation** | Explicitly modeled environments used when physical infrastructure is unavailable. | Synthetic canary marker echo injection, simulated resource contention throttles, mock inference adapter for testing control plane logic. |
| **Residual Risk** | Known limitations and unaddressed threats given system boundaries. | Shared OS kernel compromise, hardware-level cache/timing side channels, black-box statistical inference over model outputs. |

---

## 6. Limits of Enforced Controls

1. **Limits of Container Isolation:** Standard containers share the host Linux kernel. A kernel vulnerability or misconfigured volume mount can undermine process isolation. Containers do not provide cryptographic hardware memory protection.
2. **Limits of Canary Detection:** Canaries detect only attempts that touch the decoy artifact. If an attacker navigates directly to legitimate targets without touching the canary, the tripwire will not fire.
3. **Limits of Broker Authorization:** The broker is part of the Trusted Computing Base (TCB). A flaw in the broker’s routing logic compromises isolation. Furthermore, the broker cannot prevent statistical inference if an attacker analyzes thousands of sanitized outputs.
4. **Limits of Session Isolation:** Creating fresh session IDs prevents context memory leakage at the API layer, but cannot eliminate internal model prefix caching or server-side memory reuse in proprietary managed LLM endpoints.

---

## 7. Environment Capability Assessment & Feasibility

### 7.1 Local Runtime Capabilities (Windows 11 Laptop)
- **Available:**
  - Python 3.14.6 with `cryptography` (49.0.0), `psutil` (7.2.2), `fastapi`, `pydantic`, `pytest`.
  - Ed25519 asymmetric cryptography and SHA-256 canonical hashing.
  - Process-level isolation with token-scoped broker sockets and tenant-isolated storage directories.
  - Fine-grained CPU and memory accounting via `psutil`.
- **Unavailable on Bare Host:**
  - `docker` CLI is not installed / not in PATH.
  - Linux kernel namespaces, cgroups v2, and seccomp filters cannot be executed natively on Windows without Docker Desktop / WSL2.
- **Hardware Confidential Computing (TEE) Feasibility:**
  - The local development machine lacks AMD SEV-SNP or Intel TDX/SGX hypervisor support. Hardware remote attestation is physically unavailable in this environment.
  - *Engineering Decision:* We do not simulate fake TEE attestation. We document TEE integration as a production cloud requirement and implement our cryptographic verification at the software evidence and broker layer.

### 7.2 Cloud Deployment Profile (Preserved Container Baseline)
- We provide production `Dockerfile` and `docker-compose.yml` configured for Linux hosts:
  - Non-root UID (`10001`), read-only root filesystems (`read_only: true`), dropped capabilities (`cap_drop: ALL`), isolated user-defined bridge networks, and CPU/memory limits (`cpus: 1.0`, `mem_limit: 1g`).
- We preserve a **Hardened Container Baseline** comparison: running identical evaluations in standard containers with shared logs vs. BlindSeal with validity gating, demonstrating that the baseline silently misses audit tampering and state leakage.

---

## 8. Staged Implementation Plan

- **Phase 1 (Immediate Scope): Evidence Core & Validity Gate**
  - Canonical JSON serialization (`bayora/core/canonical.py`).
  - Cryptographic primitives: SHA-256, Ed25519 signing/verifying (`bayora/core/crypto.py`).
  - Core data schemas: Lifecycle states, 4-state verdicts, manifests, events, checkpoints (`bayora/core/models.py`).
  - Deterministic validity state machine (`bayora/core/engine.py`).
  - Standalone verifier detecting modification, reordering, deletion, truncation, signature failure, missing events (`bayora/verifier/verify.py`).
  - Automated tests validating all six failure modes with actual test execution (`tests/test_core.py`).
- **Phase 2:** Tenant Vaults, Broker, and Sealed Submission Pipeline.
- **Phase 3:** Observer, Canary Tripwires, Model Adapter, and Resource Governance.
- **Phase 4:** Hardened Container Baseline Comparison & Interactive Operator Interface.
