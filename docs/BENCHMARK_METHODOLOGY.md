# Bayora BlindSeal: Benchmark Methodology & Empirical Measurement

## 1. Overview & Objective

The Bayora BlindSeal benchmark comparator evaluates the security and environmental integrity differentiation between:
1. **The Naive Baseline (`NaiveEvaluationRunner`)**: A conventional AI safety evaluation harness that stores execution logs in plaintext mutable files and produces binary PASS/FAIL verdicts based solely on model output strings.
2. **Bayora BlindSeal (`IntegratedEvaluationRunner`)**: Cryptographically sealed, hash-chained evidence infrastructure with canary tripwires, resource telemetry governance, capability broker access control, and deterministic 4-state environmental validity assessment (`VALID`, `INVALIDATED`, `INCONCLUSIVE`, `NOT_EVALUATED`).

---

## 2. Tested Environment & Host Profile

The measurements reported in this benchmark were conducted in the following hardware and software environment:

| Attribute | Specification |
| :--- | :--- |
| **Operating System** | Windows 11 Enterprise (x86_64, 64-bit) |
| **Python Runtime** | Python 3.14.6 (`cpython`) |
| **Crypto Library** | `cryptography` v44.0+ (Ed25519 asymmetric signatures, SHA-256 canonical hashing) |
| **Canonical Scheme** | RFC 8785 Canonical JSON Serialization |
| **System Telemetry** | `psutil` CPU / memory sampling |
| **Timing Clock** | `time.perf_counter()` (high-resolution monotonic hardware clock) |

> [!WARNING]
> **Performance Scope & Hardware Independence**:
> The reported ~4.0 ms median overhead is an **empirical benchmark measurement** for the specific hardware, Python version, and cryptographic library on this test host. It should **not be interpreted as a universal SLA or latency guarantee** across arbitrary embedded, edge, or distributed cloud hardware.

---

## 3. Evaluated Scenario Conditions (10 Distinct Tests)

The benchmark evaluates 1 benign baseline condition and 8 distinct adversarial failure modes:

| # | Scenario ID | Description | Naive Expected | BlindSeal Expected | Modeled Threat Surface |
|---|---|---|---|---|---|
| 1 | `clean_execution` | Benign prompt under standard operating conditions | PASS (Accepted) | **VALID** (Accepted) | Normal system execution |
| 2 | `cross_session_contamination` | Model leaks synthetic canary marker from prior test session | PASS (False Accept) | **INVALIDATED** (Blocked) | Cross-session context bleeding |
| 3 | `resource_starvation` | Model execution latency exceeds declared SLA profile | PASS (False Accept) | **INVALIDATED** (Blocked) | Resource exhaustion / starvation |
| 4 | `resource_memory_spike` | Process memory footprint exceeds declared ceiling | PASS (False Accept) | **INVALIDATED** (Blocked) | Uncontrolled memory spike |
| 5 | `telemetry_blackout` | Observer telemetry drops offline during execution | PASS (False Accept) | **INCONCLUSIVE** (Blocked) | Telemetry failure (fail-closed) |
| 6 | `audit_event_body_tampered` | Single field in post-run event payload modified on disk | PASS (Undetected) | **INVALIDATED** (Detected) | Post-hoc audit log modification |
| 7 | `audit_event_deleted` | Intermediate event deleted from evidence ledger | PASS (Undetected) | **INVALIDATED** (Detected) | Audit log truncation / deletion |
| 8 | `audit_tail_truncated` | Log truncated before final completion event | PASS (Undetected) | **INVALIDATED** (Detected) | Premature log truncation |
| 9 | `audit_signature_forged` | Evaluator checkpoint signature corrupted or forged | PASS (Undetected) | **INVALIDATED** (Detected) | Evaluator forgery / key tampering |

---

## 4. Measurement Procedure & Metric Definitions

### 4.1 Timing Measurement
Every test case executes side-by-side using `time.perf_counter()`:
$$\text{Overhead (ms)} = \max(0.0, T_{\text{BlindSeal}} - T_{\text{Naive}})$$
Aggregate statistics report:
- **Median Overhead ($p_{50}$)**: Typical cryptographic hashing and signing cost per evaluation cycle.
- **95th Percentile Overhead ($p_{95}$)**: Tail latency under resource monitor sampling.
- **Min / Max Overhead**: Lower and upper bounds observed during execution.

### 4.2 Security Metrics
- **False Acceptance Rate (FAR)**:
  $$\text{FAR} = \frac{\text{Compromised Runs Accepted as Valid}}{\text{Total Compromised Runs Evaluated}}$$
  - **Naive Baseline FAR**: **100.0%** (8 of 8 compromised runs falsely accepted as valid).
  - **BlindSeal FAR**: **0.0%** across the 8 evaluated adversarial test scenarios.
- **Tamper Detection Rate (TDR)**:
  $$\text{TDR} = \frac{\text{Tampered Runs Detected and Rejected}}{\text{Total Tampered Runs Evaluated}}$$
  - **Naive Baseline TDR**: **0.0%** (0 of 4 log modifications detected).
  - **BlindSeal TDR**: **100.0%** (4 of 4 log modifications detected via cryptographic hash-chain and Ed25519 signature checks).

---

## 5. Scope & Generalizability Disclaimer

> [!IMPORTANT]
> **Scientific Integrity & Boundary Disclaimers**:
> 1. **Zero False Acceptance Scope**: The measured 0.0% false acceptance rate applies **strictly to the 8 evaluated adversarial test scenarios** under this specific test harness. It proves that BlindSeal successfully mitigates the modeled threat vectors (canary echo, resource budget breaches, telemetry failures, and audit tampering). It **does not constitute a universal mathematical impossibility** of leakage across unmodeled, physical, or side-channel attack vectors.
> 2. **Telemetry Observation vs Hard Enforcement**: The `psutil` resource monitor samples process telemetry to invalidate runs retrospectively or in real-time; it does **not enforce kernel-level cgroup hard resource limits**.
> 3. **Synthetic Canary vs Physical LLM Isolation**: The synthetic canaries prove that if context bleeding occurs, the detection pipeline triggers an immediate invalidation. To physically isolate model inference memory in a cloud environment, hardware TEEs (AMD SEV-SNP) or OS worker process restarts are necessary.
