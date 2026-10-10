# Bayora BlindSeal: Evaluation Results & Benchmark Report

This document records the actual measured benchmark results and automated test outcomes executed on the Bayora BlindSeal platform.

---

## 1. Automated Test Suite Execution Summary

- **Total Test Cases Executed:** 65
- **Passed:** 65 (100%)
- **Skipped:** 0 (0%)
- **Failed:** 0 (0%)
- **Total Test Suite Runtime:** ~7.2 seconds
- **Platform:** Windows 11, Python 3.14.6, pytest 9.1.1

### Test Breakdown by Subsystem:
1. **Evidence Core & Cryptography (`test_core.py`):** 18 tests
   - RFC 8785 canonical JSON determinism, whitespace handling, and deep nested object sorting.
   - SHA-256 hash chaining and Ed25519 digital signature generation/verification.
   - Tamper detection: single-byte event modification, reordering, deletion, tail truncation, complete checkpoint removal, and public key substitution attacks.
   - Validity state machine rules, 4-verdict transitions, and verifier diagnostic truthfulness.
2. **Tenant Vaults & Policy Broker (`test_vaults.py`):** 21 tests
   - Cross-tenant read/write prevention (Blue cannot read Red; Red cannot read Blue).
   - Anti-traversal path resolver (`../..` rejected).
   - HMAC capability token authentication, expiry, and cross-run substitution prevention.
   - Symlink escape prevention tested across platforms with guaranteed non-admin fallback test.
   - Defense against caller-created fake `VALID` verdict objects (broker independently re-verifies evidence).
   - Checkpoint public key mismatch defense and TOCTOU path replacement race defenses.
   - Authorization strictly precedes any filesystem operations.
   - Staged release gating: premature release blocked, invalidated release blocked, authorized release permitted.
   - Audit trail hash chain and zero secret leakage.
3. **Integrated Evaluation Pipeline (`test_eval.py`):** 7 tests
   - End-to-end execution of the 5 reproducible evaluation scenarios.
   - Verification that raw prompt text and output text never leak into audit records.
   - Verification of exported evidence capsules via standalone verifier CLI.
4. **Comparative Baseline Benchmark (`test_benchmark.py`):** 2 tests
   - Verification that Naive Baseline generates unsealed mutable logs.
   - Verification that BlindSeal achieves 0% false acceptance and 100% tamper detection across 9 conditions.
5. **Red-Team & Blue-Team Defense (`test_defense.py`):** 4 tests
   - Adversarial campaign generation across 4 attack categories (direct injection, roleplay, multi-turn DAN, resource DOS).
   - Blue guard filtering of prompt injections and DAN jailbreaks.
   - Sanitization of Red-facing output (no internal rule IDs, regexes, or weights leaked).
   - Immutability of defensive package digests.
6. **CLI Explorer & Operator UI (`test_cli.py`):** 4 tests
   - Operator console HTML rendering and API endpoints (`/api/scenarios`, `/api/benchmark`).
   - CLI verification command execution.
7. **UI Security & Authorization Boundary (`test_security.py`):** 9 tests
   - Unauthenticated API artifact requests rejected (401).
   - Forged capability token artifact requests rejected (403).
   - Cross-tenant access via API rejected (Red cannot read Blue defenses, Blue cannot read unreleased Red payloads).
   - Path traversal attempts through API parameters rejected (403).
   - Unauthenticated release requests rejected (403).
   - Release requests on invalidated runs permanently rejected (403).
   - Legitimate evaluator release transitions succeed and grant authorized access.
   - Zero raw secret exposure in public `/api/scenarios` payload.

---

## 2. Comparative Benchmark: BlindSeal vs. Naive Baseline

The benchmark comparator (`bayora.benchmark.compare`) ran both systems head-to-head under **9 distinct failure injection conditions**:

| Evaluation Scenario | Injected Condition | Naive Baseline Verdict | Naive False Accept? | BlindSeal Verdict | BlindSeal Diagnostic | Tamper Detected? |
|---|---|---|---|---|---|---|
| **1. Clean Execution** | Harmless prompts, normal load | `PASS` | No | `VALID` | `INTEGRITY_VERIFIED` | N/A |
| **2. Cross-Session Contamination** | Echoed prior session canary marker | `PASS` | **YES (FAIL)** | `INVALIDATED` | `CANARY_BREACH_DETECTED` | N/A |
| **3. Resource Starvation** | Latency exceeds declared budget | `PASS` | **YES (FAIL)** | `INVALIDATED` | `RESOURCE_BUDGET_EXCEEDED` | N/A |
| **4. Resource Memory Spike** | RSS exceeds declared budget | `PASS` | **YES (FAIL)** | `INVALIDATED` | `RESOURCE_BUDGET_EXCEEDED` | N/A |
| **5. Telemetry Blackout** | Process metrics stream offline | `PASS` | **YES (FAIL)** | `INCONCLUSIVE`| `TELEMETRY_UNAVAILABLE` | N/A |
| **6. Event Body Modified** | Single field modified on disk | `PASS (Forged)` | **YES (FAIL)** | `INVALIDATED` | `EVENT_BODY_MODIFIED` | **YES** |
| **7. Event Deleted** | Event deleted from sequence | `PASS (Forged)` | **YES (FAIL)** | `INVALIDATED` | `EVENT_SEQUENCE_DISCONTINUITY` | **YES** |
| **8. Tail Truncated** | Terminal events deleted | `PASS (Forged)` | **YES (FAIL)** | `INVALIDATED` | `CHECKPOINT_FINAL_HASH_MISMATCH` | **YES** |
| **9. Signature Forged / Substituted** | Ed25519 signature corrupted | `PASS (Forged)` | **YES (FAIL)** | `INVALIDATED` | `CHECKPOINT_SIGNATURE_INVALID` | **YES** |

### Benchmark Metrics Comparison:

| Metric | Naive Baseline | Bayora BlindSeal | Improvement |
|---|---|---|---|
| **False Acceptance Rate** | 100% (8 of 8 compromised runs) | **0% (0 of 8 compromised runs)** | **-100% False Acceptances** |
| **Tamper Detection Rate** | 0.0% | **100.0%** (4 of 4 tampering variants) | **+100.0% Detection** |
| **Staged Disclosure Gating** | None (direct file browsing) | **Strictly Blocked on Invalidation** | **Enforced** |
| **Measured Median Overhead** | 0.0ms | **~2.4ms** (p95 ~6.1ms) | Negligible (~2.4ms) |

---

## 3. Benchmark Limitations & Conditions

1. **Synthetic Adversarial Fixtures:** The benchmark utilizes deterministic mock adapters and synthetic canary markers to guarantee reproducible failure injection. While this validates control plane logic, it does not evaluate statistical timing side channels on proprietary third-party LLM cloud APIs.
2. **Local Workstation Baseline:** Measurements were captured on a Windows 11 host with Python 3.14.6. Distributed network latency overhead is not captured in this local test suite.
3. **Fail-Closed Policy Trade-off:** Under BlindSeal, offline telemetry causes runs to evaluate as `INCONCLUSIVE`. This prevents unmonitored runs from passing, but requires operational monitoring to prevent excessive inconclusive runs.
4. **Scope Disclaimer:** Measured 0% false-acceptance rate applies specifically to the 8 tested failure scenarios under our controlled harness; it is an empirical finding for this test suite, not a formal mathematical proof for all arbitrary unmodeled threats.
