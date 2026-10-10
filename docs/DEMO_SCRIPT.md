# Bayora V.E.R.I.T.Y: Live Demonstration Script for Judges

**Title:** "Validation of Evidence, Results, Isolation, Trust and Yield"  
**Target Duration:** 3–5 minutes  
**Goal:** Prove technical differentiation by directly showing environmental invalidation, independent verification, and comparative advantage over a naive baseline.

---

## Scene 1: The Naive Baseline Fallacy (30–45s)

### Action:
Run the comparative benchmark from the terminal:
```bash
python -m bayora.cli benchmark
```

### Script to say to Judges:
> *"Most AI safety benchmarks present a green dashboard claiming a model 'passed' a safety test. But in adversarial testing, three mutually untrusted parties—the Red Team attacker, Blue Team defender, and Client LLM—share cloud infrastructure.*  
> *Here is what happens in a standard containerized setup when an experiment is contaminated or tampered with: the Naive Baseline reports 'PASS' across all three failure conditions! It accepts a cross-session data leak as safe, ignores resource starvation, and silently accepts an edited audit log. Our baseline false acceptance rate is 100%."*

---

## Scene 2: Seal & Normal Execution under BlindSeal (45s)

### Action:
Execute a clean evaluation run and export the evidence capsule:
```bash
python -m bayora.cli run --scenario clean --export clean_capsule.json
```

### Script to say to Judges:
> *"Under Bayora, before a test starts, the test suite, defense rules, model details, and limits are locked into a clean, canonical manifest. Access tokens are strictly limited to the test.  
> Each prompt runs in an isolated session with hidden canary markers. The run records every step in an intact SHA-256 hash-chained record with an Ed25519 digital signature.  
> Because all checks passed cleanly, the environment verdict is VALID, and the test attack prompts are safely RELEASED."*

---

## Scene 3: The Cross-Session Contamination Check (45s)

### Action:
Execute the cross-session contamination scenario:
```bash
python -m bayora.cli run --scenario contam
```

### Script to say to Judges:
> *"Now we inject a subtle failure: the model carries over memory from an earlier session and repeats a hidden decoy token.  
> Notice the result: the model output itself looks harmless, but Bayora catches the memory echo. Instead of falsely celebrating a pass, the health gate marks the evaluation INVALIDATED with reason code CANARY_BREACH_DETECTED.  
> Most importantly: test prompts stay BLOCKED. The defense team cannot see this untrustworthy test suite."*

---

## Scene 4: Independent Verification & Tamper Detection (45s)

### Action:
1. Verify the clean capsule independently:
   ```bash
   python -m bayora.cli verify --file clean_capsule.json
   ```
2. Deliberately tamper with one field in the capsule:
   ```bash
   python -c "import json; data=json.load(open('clean_capsule.json')); data['events'][2]['metadata']['score']='FORGED'; json.dump(data, open('tampered.json', 'w'))"
   python -m bayora.cli verify --file tampered.json
   ```

### Script to say to Judges:
> *"Our audit log is not just a text file. It is an ordered, hash-chained ledger with an Ed25519 signature checkpoint.  
> When we run our standalone verifier tool on the original capsule, it verifies in milliseconds.  
> But if an attacker modifies a single byte in an event record, the verifier recalculates the RFC 8785 canonical hash, identifies the broken link at sequence #2, and flags EVENT_BODY_MODIFIED with exit code 1."*

---

## Scene 5: Interactive Operator Dashboard (45s)

### Action:
Launch the web dashboard:
```bash
python -m bayora.cli serve --port 8000
```
Open browser to `http://127.0.0.1:8000`.

### Script to say to Judges:
> *"In our operator dashboard, you can click through all five reproducible scenarios: Clean, Contaminated, Throttled, Telemetry-Offline, and Tampered.  
> You can drill down into the live hash-chain ledger, inspect the manifest digests, and review our honest residual risk panel.  
> We do not claim impossible guarantees like 'zero leakage' or 'unhackable cloud.' We make our security boundaries, tested properties, and residual risks completely explicit."*

---

## Scene 6: Answering Tough Judge Questions on Security Boundaries

When judges ask skeptical questions, lead with technical honesty and architectural precision:

### 1. "Does your resource monitor enforce hard limits or just observe?"
> *"In this prototype, `psutil` **observes and retrospectively invalidates** runs when latency or memory exceed declared budgets. We do **not** claim OS-level hard cgroup limits in this demo. For production cloud deployments, this would be wired directly into Linux cgroups v2 kernel controllers and microVM memory quotas."*

### 2. "Does the mock model prove real LLMs won't leak memory across sessions?"
> *"No, and we are completely transparent about that. The mock model proves that **if a breach or canary echo occurs, our detection and validity engine pipeline immediately catches it and blocks disclosure**. To physically guarantee that weights and GPU KV-caches don't leak in a shared environment, you need hardware TEEs (AMD SEV-SNP) or dedicated worker process isolation."*

### 3. "Can an attacker bypass the broker by passing a forged VALID object?"
> *"No. The broker does not accept a caller-created object just because it claims `VALID`. It independently re-evaluates the signed evidence capsule, checks that the run ID and manifest digest match, verifies the Ed25519 signature against the broker's pre-configured trusted evaluator public key, and audits the canonical hash-chain."*

### 4. "Can someone bypass security via the web dashboard API?"
> *"No. The dashboard does not own security boundaries. Every artifact read and release request routes strictly through the PolicyBroker's server-side authorization methods with HMAC capability tokens, lease expiration, and staged release state checks. Unauthenticated, cross-tenant, and path-traversal requests are rejected with 401/403."*

### 5. "Is the 0% false acceptance rate a universal guarantee?"
> *"No. It is an empirical benchmark measurement across the 8 evaluated adversarial conditions in our test harness. It demonstrates that BlindSeal catches the modeled attack surfaces that the Naive Baseline completely ignores."*
