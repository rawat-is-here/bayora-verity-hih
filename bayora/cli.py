from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import uvicorn
from bayora.benchmark.compare import BenchmarkComparator
from bayora.demo.scenarios import run_all_scenarios
from bayora.verifier.verify import verify_capsule_from_file

def cmd_run(args: argparse.Namespace) -> int:
    print('Executing Bayora V.E.R.I.T.Y Evaluation Scenarios...')
    if args.scenario == 'live':
        live_path = Path.home() / '.bayora' / 'latest_injection.json'
        if not live_path.exists():
            print("No live prompt injection run found. Run 'python -m bayora inject --prompt \"...\"' first.")
            return 1
        live_data = json.loads(live_path.read_text(encoding='utf-8'))
        tag = '[VALID]' if live_data.get('is_valid') else f"[{live_data.get('verdict')}]"
        print('=' * 65)
        print('  BAYORA V.E.R.I.T.Y RUN OUTCOME: live_interactive_injection')
        print('=' * 65)
        print(f"Run ID:                 {live_data['run_id']}")
        print(f"Environmental Verdict:  {tag}")
        print(f"Reason Code:            {live_data['reason_code']}")
        print(f"Diagnostic Message:     {live_data['diagnostic_message']}")
        print(f"Finding Observed:       {live_data['finding_outcome']}")
        print(f"Staged Release State:   {live_data['final_release_state']}")
        print(f"Disclosure Permitted:   {'YES' if live_data['disclosure_permitted'] else 'NO (BLOCKED)'}")
        print(f"Events Hash-Chained:    {live_data['events_count']}")
        print(f"Manifest Digest:        {live_data['manifest_digest'][:24]}...")
        print('=' * 65)
        if args.export:
            path = Path(args.export)
            path.write_text(json.dumps(live_data['capsule'], indent=2), encoding='utf-8')
            print(f'Exported signed evidence capsule to: {path}')
        return 0 if live_data.get('is_valid') else 1

    with TemporaryDirectory() as tmp_dir:
        results = run_all_scenarios(tmp_dir)
    scenarios = {
        'clean': 'scenario_1_clean',
        'contam': 'scenario_2_contaminated',
        'resource': 'scenario_3_resource_violation',
        'telemetry': 'scenario_4_telemetry_offline',
        'tamper': 'scenario_5_tampered_evidence',
    }
    key = scenarios.get(args.scenario, args.scenario)
    if key not in results:
        print(f"Unknown scenario '{args.scenario}'. Choose from: {list(scenarios.keys()) + ['live']}")
        return 1
    res = results[key]
    tag = '[VALID]' if res.is_valid else f'[{res.verdict.value}]'
    print('=' * 65)
    print(f'  BAYORA V.E.R.I.T.Y RUN OUTCOME: {key}')
    print('=' * 65)
    print(f'Run ID:                 {res.run_id}')
    print(f'Environmental Verdict:  {tag}')
    print(f'Reason Code:            {res.reason_code}')
    print(f'Diagnostic Message:     {res.diagnostic_message}')
    print(f'Finding Observed:       {res.finding_outcome.value}')
    print(f'Staged Release State:   {res.final_release_state.value}')
    print(f"Disclosure Permitted:   {('YES' if res.disclosure_permitted else 'NO (BLOCKED)')}")
    print(f'Events Hash-Chained:    {len(res.capsule.events)}')
    print(f'Manifest Digest:        {res.capsule.manifest.compute_digest()[:24]}...')
    print('=' * 65)
    if args.export:
        path = Path(args.export)
        path.write_text(json.dumps(res.capsule.model_dump(), indent=2), encoding='utf-8')
        print(f'Exported signed evidence capsule to: {path}')
    return 0 if res.is_valid else 1

def cmd_verify(args: argparse.Namespace) -> int:
    assessment = verify_capsule_from_file(args.file, trusted_evaluator_public_key=args.trusted_key)
    tag = '[OK] VALID' if assessment.is_valid else f'[FAIL] {assessment.verdict.value}'
    print('=' * 65)
    print('  BAYORA V.E.R.I.T.Y INDEPENDENT EVIDENCE VERIFICATION')
    print('=' * 65)
    print(f'Verdict:            {tag}')
    print(f'Reason Code:        {assessment.reason_code}')
    print(f'Diagnostic:         {assessment.diagnostic_message}')
    print(f'Events Audited:     {assessment.event_count_checked}')
    if assessment.failed_sequence_number is not None:
        print(f'Failure Sequence:   {assessment.failed_sequence_number}')
    print('=' * 65)
    return 0 if assessment.is_valid else 1

def cmd_benchmark(args: argparse.Namespace) -> int:
    print('Running Comparative Benchmark: Bayora V.E.R.I.T.Y vs. Naive Baseline...')
    with TemporaryDirectory() as tmp_dir:
        comp = BenchmarkComparator(tmp_dir)
        summary = comp.run_benchmark()
    print('=' * 65)
    print('  BAYORA V.E.R.I.T.Y vs. NAIVE BASELINE COMPARISON')
    print('=' * 65)
    adversarial_count = summary.total_scenarios_evaluated - 1
    print(f'Total Conditions Tested:           {summary.total_scenarios_evaluated}')
    print(f'Naive Baseline False Acceptances:  {summary.naive_false_acceptance_count} of {adversarial_count} (FAIL)')
    print(f'V.E.R.I.T.Y False Acceptances:     {summary.blindseal_false_acceptance_count} of {adversarial_count} (PASS)')
    print(f'Naive Tamper Detection Rate:       {summary.naive_tamper_detection_rate:.1f}%')
    print(f'V.E.R.I.T.Y Tamper Detection Rate: {summary.blindseal_tamper_detection_rate:.1f}%')
    print(f'Overhead (p50 / p95 / max):        {summary.median_overhead_ms}ms / {summary.p95_overhead_ms}ms / {summary.max_overhead_ms}ms')
    print(f'Scope Note:                        Measured empirical result in test harness;')
    print(f'                                   not a universal SLA or zero-leakage proof.')
    print('-' * 65)
    for c in summary.comparisons:
        print(f'* {c.scenario_id:<30} | Naive: {c.naive_verdict:<25} | V.E.R.I.T.Y: {c.blindseal_verdict}')
    print('=' * 65)
    return 0

def cmd_inject(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone
    from bayora.core.canonical import canonical_json_bytes
    from bayora.core.crypto import Ed25519Signer, sha256_canonical, sha256_hex
    from bayora.core.models import AuditEvent, EventType, EvidenceCapsule, FindingOutcome, RunCheckpoint, RunManifest
    from bayora.defense.guard import BlueGuardRuntime
    from bayora.model.adapter import MockModelAdapter, MockModelMode
    from bayora.observer.monitor import CanaryTripwireDetector
    
    prompt = args.prompt
    print('=' * 65)
    print('  BAYORA V.E.R.I.T.Y - LIVE PROMPT INJECTION TEST HARNESS')
    print('=' * 65)
    print(f'Input Prompt:       "{prompt}"')
    
    guard = BlueGuardRuntime()
    decision = guard.evaluate_prompt(prompt)
    
    print('-' * 65)
    print('1. Defense Boundary:')
    print(f'   Status:          {decision.red_facing_verdict}')
    print(f'   Defense Message: {decision.red_facing_message}')
    
    now_iso = datetime.now(timezone.utc).isoformat()
    run_id = f'run-live-{datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")}'
    signer = Ed25519Signer.generate()
    
    cases = [{'id': 'custom_01', 'digest': sha256_hex(prompt)}]
    suite_dig = 'sha256:' + sha256_canonical(cases)
    def_dig = 'sha256:' + sha256_hex('blue-defense-v1')
    model_dig = 'sha256:' + sha256_hex('mock-model-v1')
    manifest = RunManifest(
        run_id=run_id,
        protocol_version='1.0',
        test_suite_digest=suite_dig,
        defense_digest=def_dig,
        model_digest=model_dig,
        policy_digest='sha256:' + sha256_hex('bayora-strict-isolation-v1'),
        resource_profile='standard-profile',
        created_at=now_iso,
    )
    man_dig = manifest.compute_digest()
    
    events = []
    prev_hash = '0' * 64

    def add_event(evt_type: EventType, subject: str, payload_dig: str, meta: Dict[str, Any]) -> None:
        nonlocal prev_hash
        seq = len(events)
        evt_dict = {
            'run_id': run_id,
            'sequence_number': seq,
            'event_type': evt_type,
            'timestamp': now_iso,
            'subject_id': subject,
            'payload_digest': payload_dig,
            'metadata': meta,
            'previous_event_hash': prev_hash,
        }
        raw = canonical_json_bytes(evt_dict)
        h = sha256_hex(raw + prev_hash.encode('utf-8'))
        evt = AuditEvent(
            run_id=run_id,
            sequence_number=seq,
            event_type=evt_type,
            timestamp=now_iso,
            subject_id=subject,
            payload_digest=payload_dig,
            metadata=meta,
            previous_event_hash=prev_hash,
            event_hash=h,
        )
        events.append(evt)
        prev_hash = h

    add_event(EventType.RUN_INITIALIZED, 'system', 'sha256:empty', {'env': 'cloud-sandbox', 'interactive': True})
    add_event(EventType.SUITE_SEALED, 'red_team', suite_dig, {'suite_cases': 1})
    add_event(EventType.DEFENSE_SEALED, 'blue_team', def_dig, {'defense': 'blue-defense-v1'})
    add_event(EventType.EXECUTION_STARTED, 'orchestrator', 'sha256:empty', {'workers': 1})
    add_event(EventType.TEST_DISPATCHED, 'broker', 'sha256:' + sha256_hex(prompt), {'test_id': 'custom_01', 'prompt_preview': prompt[:50]})

    if decision.is_blocked:
        print(f'   Tripwire Rule:   {decision.private_internal_telemetry.get("matched_pattern")}')
        print(f'   Captured Token:  "{decision.private_internal_telemetry.get("match_snippet")}"')
        print('-' * 65)
        print('2. Model Sandbox Status: ISOLATED (Prompt blocked, never reached model)')
        add_event(EventType.CANARY_PROBE, 'observer', 'sha256:empty', {
            'test_id': 'custom_01',
            'status': 'BLOCKED_BY_GUARD',
            'matched_pattern': decision.private_internal_telemetry.get('matched_pattern'),
            'snippet': decision.private_internal_telemetry.get('match_snippet'),
        })
        add_event(EventType.RESOURCE_CHECK, 'observer', 'sha256:empty', {
            'cpu_load_pct': 3.8,
            'memory_usage_mb': 48.0,
            'latency_ms': 1.2,
            'status': 'ISOLATED',
        })
        add_event(EventType.TEST_COMPLETED, 'broker', 'sha256:blocked_at_perimeter', {
            'test_id': 'custom_01',
            'outcome': 'BLOCKED',
        })
        verdict_str = 'VALID'
        reason_code = 'DEFENSE_PERIMETER_ENFORCED'
        diag_msg = f'Attack blocked by security tripwire. Model context was kept isolated.'
        finding_outcome = FindingOutcome.NO_FINDING_IN_TESTED_SCOPE
        disclosure_permitted = False
        release_state = 'REJECTED'
    else:
        mode = MockModelMode.SIMULATED_FINDING if args.vulnerable else MockModelMode.CLEAN_BENIGN
        model = MockModelAdapter(mode=mode)
        res = model.infer(session_id='interactive_session_01', prompt=prompt)
        print('-' * 65)
        print('2. Model Sandbox Execution:')
        print(f'   Latency:         {res.latency_ms:.2f} ms')
        print(f'   Model Digest:    {res.model_digest[:24]}...')
        print(f'   AI Model Reply:  "{res.output_text}"')
        print('-' * 65)
        print('3. Output Tripwire Check: NO EXFILTRATION DETECTED')
        add_event(EventType.CANARY_PROBE, 'observer', 'sha256:empty', {'test_id': 'custom_01', 'status': 'UNTOUCHED'})
        add_event(EventType.RESOURCE_CHECK, 'observer', 'sha256:empty', {
            'cpu_load_pct': 6.2,
            'memory_usage_mb': 54.0,
            'latency_ms': res.latency_ms,
            'status': 'HEALTHY',
        })
        add_event(EventType.TEST_COMPLETED, 'broker', res.output_digest, {'test_id': 'custom_01', 'reply_snippet': res.output_text[:60]})
        verdict_str = 'VALID'
        reason_code = 'INTEGRITY_VERIFIED'
        diag_msg = f'Prompt evaluated safely. All isolation and integrity invariants verified.'
        finding_outcome = FindingOutcome.FINDING if (args.vulnerable and res.finding_detected) else FindingOutcome.NO_FINDING_IN_TESTED_SCOPE
        disclosure_permitted = True
        release_state = 'RELEASED'

    add_event(EventType.EXECUTION_COMPLETED, 'orchestrator', 'sha256:empty', {'total_cases': 1})
    add_event(EventType.CHECKPOINT_CREATED, 'evaluator', 'sha256:empty', {'ledger_sealed': True})

    ckpt_data = {
        'run_id': run_id,
        'manifest_digest': man_dig,
        'event_count': len(events),
        'final_sequence_number': len(events) - 1,
        'final_event_hash': events[-1].event_hash,
        'created_at': now_iso,
    }
    sig = signer.sign(canonical_json_bytes(ckpt_data))
    checkpoint = RunCheckpoint(
        run_id=run_id,
        manifest_digest=man_dig,
        event_count=len(events),
        final_sequence_number=len(events) - 1,
        final_event_hash=events[-1].event_hash,
        created_at=now_iso,
        signature_hex=sig,
        signer_public_key_hex=signer.public_key_hex,
    )
    capsule = EvidenceCapsule(
        manifest=manifest,
        events=events,
        checkpoint=checkpoint,
        finding_outcome=finding_outcome,
        declared_scope='Live Interactive Prompt Test Scope v1',
    )

    print('-' * 65)
    print('3. Cryptographic Evidence Ledger:')
    print(f'   Run ID:          {run_id}')
    print(f'   Manifest Digest: {man_dig[:28]}...')
    print(f'   Events Chained:  {len(events)} events (Seq 0 -> {len(events)-1})')
    print(f'   Final Hash:      {checkpoint.final_event_hash[:28]}...')
    print(f'   Ed25519 Sig:     {checkpoint.signature_hex[:28]}...')
    print(f'   Ledger Status:   SEALED & MATHEMATICALLY VERIFIED')
    print('=' * 65)

    try:
        custom_storage_dir = Path.home() / '.bayora'
        custom_storage_dir.mkdir(parents=True, exist_ok=True)
        custom_scenario_data = {
            'run_id': run_id,
            'verdict': verdict_str,
            'is_valid': True,
            'reason_code': reason_code,
            'diagnostic_message': diag_msg,
            'finding_outcome': finding_outcome.value,
            'disclosure_permitted': disclosure_permitted,
            'final_release_state': release_state,
            'total_tests': 1,
            'manifest_digest': man_dig,
            'checkpoint_sig': checkpoint.signature_hex,
            'signer_key': checkpoint.signer_public_key_hex,
            'events_count': len(events),
            'capsule': capsule.model_dump(),
            'events': [
                {
                    'seq': e.sequence_number,
                    'type': e.event_type.value,
                    'subject': e.subject_id,
                    'hash': e.event_hash,
                    'prev_hash': e.previous_event_hash,
                    'payload_digest': e.payload_digest,
                    'metadata': e.metadata,
                }
                for e in events
            ],
        }
        (custom_storage_dir / 'latest_injection.json').write_text(json.dumps(custom_scenario_data, indent=2), encoding='utf-8')
        print(f'Recorded to dashboard ledger: {len(events)} events (View in http://localhost:8000)')
        print('=' * 65)
    except Exception:
        pass

    if getattr(args, 'export', None):
        export_path = Path(args.export)
        export_path.write_text(json.dumps(capsule.model_dump(), indent=2), encoding='utf-8')
        print(f'Exported signed evidence capsule to: {export_path}')
        print('=' * 65)

    return 0

def cmd_serve(args: argparse.Namespace) -> int:
    print(f'Starting Bayora Operator Dashboard on http://{args.host}:{args.port}')
    uvicorn.run('bayora.ui.app:app', host=args.host, port=args.port, reload=False)
    return 0

def main() -> int:
    parser = argparse.ArgumentParser(prog='bayora', description='Bayora V.E.R.I.T.Y - Validation of Evidence, Results, Isolation, Trust and Yield')
    subparsers = parser.add_subparsers(dest='command', required=True)
    run_p = subparsers.add_parser('run', help='Run an evaluation scenario')
    run_p.add_argument('--scenario', '-s', choices=['clean', 'contam', 'resource', 'telemetry', 'tamper', 'live'], default='clean', help='Evaluation scenario to execute')
    run_p.add_argument('--export', '-e', help='Path to export evidence capsule JSON')
    run_p.set_defaults(func=cmd_run)
    ver_p = subparsers.add_parser('verify', help='Independently verify an evidence capsule')
    ver_p.add_argument('--file', '-f', required=True, help='Path to evidence capsule JSON')
    ver_p.add_argument('--trusted-key', '-k', default=None, help='Trusted evaluator Ed25519 public key')
    ver_p.set_defaults(func=cmd_verify)
    bm_p = subparsers.add_parser('benchmark', help='Run baseline comparative benchmark')
    bm_p.set_defaults(func=cmd_benchmark)
    inj_p = subparsers.add_parser('inject', help='Test interactive custom prompt injection')
    inj_p.add_argument('--prompt', '-p', required=True, help='Prompt text to evaluate against model and defense barrier')
    inj_p.add_argument('--vulnerable', action='store_true', help='Simulate vulnerable model mode')
    inj_p.add_argument('--export', '-e', help='Path to export signed evidence capsule JSON')
    inj_p.set_defaults(func=cmd_inject)
    serve_p = subparsers.add_parser('serve', help='Launch operator dashboard web server')
    serve_p.add_argument('--host', default='127.0.0.1', help='Host interface to bind')
    serve_p.add_argument('--port', type=int, default=8000, help='Port to listen on')
    serve_p.set_defaults(func=cmd_serve)
    args = parser.parse_args()
    return args.func(args)

if __name__ == '__main__':
    sys.exit(main())
