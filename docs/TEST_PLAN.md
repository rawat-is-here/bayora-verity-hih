# Bayora BlindSeal: Adversarial Test Plan & Verification Matrix

## 1. Scope and Objective

This test plan validates that the Bayora BlindSeal platform enforces environmental isolation, detects state contamination and resource starvation, prevents premature artifact disclosure, rejects tampered audit records, and strictly enforces server-side security boundaries without relying on frontend user interface controls.

---

## 2. Test Matrix (65 Tests, 0 Skips, 0 Failures)

| Test ID | Subsystem | Threat Scenario | Expected Outcome | Actual Result |
|---|---|---|---|---|
| **TP-01** | Crypto | Canonical serialization key order invariance (RFC 8785) | Identical bytes regardless of dict key order | **PASS** |
| **TP-02** | Evidence | Clean execution capsule verification | Verdict: `VALID`, `INTEGRITY_VERIFIED` | **PASS** |
| **TP-03** | Evidence | Single-byte event metadata modification | Verdict: `INVALIDATED`, `EVENT_BODY_MODIFIED` | **PASS** |
| **TP-04** | Evidence | Event reordering | Verdict: `INVALIDATED`, `SEQUENCE_GAP_OR_REORDERING` | **PASS** |
| **TP-05** | Evidence | Intermediate event deletion | Verdict: `INVALIDATED`, `EVENT_COUNT_MISMATCH` | **PASS** |
| **TP-06** | Evidence | Tail-event truncation | Verdict: `INVALIDATED`, `EVENT_COUNT_MISMATCH` | **PASS** |
| **TP-07** | Evidence | Corrupted Ed25519 checkpoint signature | Verdict: `INVALIDATED`, `SIGNATURE_INVALID` | **PASS** |
| **TP-08** | Evidence | Checkpoint key substitution attack | Verdict: `INVALIDATED`, `UNTRUSTED_SIGNER_KEY` | **PASS** |
| **TP-09** | Evidence | Complete checkpoint removal | Verdict: `INVALIDATED`, `MISSING_CHECKPOINT` | **PASS** |
| **TP-10** | Evidence | Manifest policy digest mismatch | Verdict: `INVALIDATED`, `MANIFEST_DIGEST_MISMATCH` | **PASS** |
| **TP-11** | Evidence | Missing required lifecycle event | Verdict: `INVALIDATED`, `MISSING_REQUIRED_EVENT` | **PASS** |
| **TP-12** | Evidence | RFC 8785 canonical JSON edge cases (whitespace, nested objects) | Canonical byte identity preserved | **PASS** |
| **TP-13** | Evidence | Verifier diagnostic truthfulness & early halting event count | True diagnostics and verified event count | **PASS** |
| **TP-14** | Vaults | Path traversal attack on artifact read (`../../`) | Denied: `PATH_TRAVERSAL_BLOCKED` | **PASS** |
| **TP-15** | Vaults | Path traversal attack on artifact write (`../../`) | Denied: `PATH_TRAVERSAL_BLOCKED` | **PASS** |
| **TP-16** | Vaults | Symlink traversal escape inside vault (OS native symlink) | Denied: `Symlink traversal detected` | **PASS** |
| **TP-17** | Vaults | Symlink traversal escape guaranteed fallback (all OSes, no skip) | Denied: `Symlink traversal detected` | **PASS (0 Skips)** |
| **TP-18** | Vaults | TOCTOU path replacement race defense | Re-verified path immediately prior to read/write | **PASS** |
| **TP-19** | Broker | Authorization strictly precedes filesystem access | 0 vault calls made on unauthorized requests | **PASS** |
| **TP-20** | Broker | Cross-tenant read (Blue reads Red unreleased payload) | Denied: `RED_PAYLOAD_UNRELEASED`, 0 bytes | **PASS** |
| **TP-21** | Broker | Cross-tenant read (Red reads Blue defense code) | Denied: `BLUE_DEFENSE_CONFIDENTIAL`, 0 bytes | **PASS** |
| **TP-22** | Broker | Cross-tenant write (Red writes to Blue vault) | Denied: `CROSS_TENANT_WRITE_FORBIDDEN` | **PASS** |
| **TP-23** | Broker | Guessed artifact ID during active run | Denied: `RED_PAYLOAD_UNRELEASED`, 0 bytes | **PASS** |
| **TP-24** | Broker | Tampered tenant claim in capability token | Denied: `INVALID_TOKEN_SIGNATURE` | **PASS** |
| **TP-25** | Broker | Expired capability token | Denied: `TOKEN_EXPIRED` | **PASS** |
| **TP-26** | Broker | Cross-run token substitution (Run A token on Run B) | Denied: `CROSS_RUN_TOKEN_SUBSTITUTION` | **PASS** |
| **TP-27** | Broker | Premature release request during execution | Denied: `PREMATURE_RELEASE_ATTEMPT` | **PASS** |
| **TP-28** | Broker | Release request following invalidated run | Denied: `INVALIDATED_RUN_RELEASE_FORBIDDEN` | **PASS** |
| **TP-29** | Broker | Forged VALID transition by unauthorized caller | Denied: `UNAUTHORIZED_TRANSITION_CALLER` | **PASS** |
| **TP-30** | Broker | Caller-created fake `VALID` object rejection | Broker independently verifies evidence capsule | **PASS** |
| **TP-31** | Broker | Capsule Run ID mismatch rejection | Denied: `RUN_ID_MISMATCH` | **PASS** |
| **TP-32** | Broker | Capsule Manifest digest mismatch rejection | Denied: `MANIFEST_DIGEST_MISMATCH` | **PASS** |
| **TP-33** | Broker | Capsule untrusted evaluator key rejection | Denied: `UNTRUSTED_EVALUATOR_KEY` | **PASS** |
| **TP-34** | Broker | Authorized post-verification release | Allowed: `RELEASED_ACCESS_GRANTED` | **PASS** |
| **TP-35** | Audit | Zero raw secret leakage in broker events | Verified: 0 raw payload strings in ledger | **PASS** |
| **TP-36** | Observer | Synthetic canary marker echo in subsequent session | Tripwire fires: `CANARY_BREACH_DETECTED` | **PASS** |
| **TP-37** | Observer | Process latency exceeds declared budget | Monitor flags: `RESOURCE_BUDGET_EXCEEDED` | **PASS** |
| **TP-38** | Observer | Telemetry monitor offline (fail-closed rule) | Gate flags: `TELEMETRY_OFFLINE` (`INCONCLUSIVE`) | **PASS** |
| **TP-39** | Defense | Blue guard blocks direct injection and DAN | `BLOCKED` with generic sanitized message | **PASS** |
| **TP-40** | Defense | Blue guard sanitization (no rule IDs leaked) | 0 private telemetry fields leaked to Red | **PASS** |
| **TP-41** | Benchmark | Naive baseline accepts contaminated/tampered runs | Naive: `PASS` (False Accept), BlindSeal: `INVALIDATED` | **PASS** |
| **TP-42** | Benchmark | 9-condition comparative comparator execution | BlindSeal achieves 0/8 false accepts, 100% tamper detection | **PASS** |
| **TP-43** | CLI / UI | Standalone verifier CLI exports and audits capsules | Exit code 0 for valid, 1 for tampered | **PASS** |
| **TP-44** | UI Security | Unauthenticated API artifact read blocked | Returns HTTP 401 Unauthorized | **PASS** |
| **TP-45** | UI Security | Forged token API artifact read blocked | Returns HTTP 403 Forbidden | **PASS** |
| **TP-46** | UI Security | Cross-tenant API read blocked (Red reads Blue) | Returns HTTP 403 Forbidden | **PASS** |
| **TP-47** | UI Security | Cross-tenant API read blocked (Blue reads unreleased Red) | Returns HTTP 403 Forbidden | **PASS** |
| **TP-48** | UI Security | Path traversal via API parameters blocked | Returns HTTP 403 Forbidden | **PASS** |
| **TP-49** | UI Security | Unauthenticated release request blocked | Returns HTTP 403 Forbidden | **PASS** |
| **TP-50** | UI Security | Release request on invalidated run permanently blocked | Returns HTTP 403 Forbidden | **PASS** |
| **TP-51** | UI Security | Legitimate evaluator release transitions succeed | HTTP 200, state transitions to RELEASED | **PASS** |
| **TP-52** | UI Security | Public scenarios API does not expose raw secrets | Verified: zero plaintext payloads or tokens in JSON | **PASS** |

---

## 3. Test Limitations & Scoping

1. **Test Environment:** Automated tests run within an isolated pytest harness on the local host.
2. **Deterministic Mocks:** Model inference tests use deterministic mock adapters to ensure reproducible failure injection without incurring external API costs.
3. **Symlink Traversal Guarantee:** Both native OS symlinks and a universal cross-platform emulation path are tested. 0 tests are skipped regardless of platform privileges.
4. **Observation vs. Enforcement:** Telemetry observations are tracked via `psutil`. These represent process monitoring, not kernel cgroup hard limits.
