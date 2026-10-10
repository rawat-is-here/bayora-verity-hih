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
        print(f"Unknown scenario '{args.scenario}'. Choose from: {list(scenarios.keys())}")
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

def cmd_serve(args: argparse.Namespace) -> int:
    print(f'Starting Bayora Operator Dashboard on http://{args.host}:{args.port}')
    uvicorn.run('bayora.ui.app:app', host=args.host, port=args.port, reload=False)
    return 0

def main() -> int:
    parser = argparse.ArgumentParser(prog='bayora', description='Bayora V.E.R.I.T.Y - Validation of Evidence, Results, Isolation, Trust and Yield')
    subparsers = parser.add_subparsers(dest='command', required=True)
    run_p = subparsers.add_parser('run', help='Run an evaluation scenario')
    run_p.add_argument('--scenario', '-s', choices=['clean', 'contam', 'resource', 'telemetry', 'tamper'], default='clean', help='Evaluation scenario to execute')
    run_p.add_argument('--export', '-e', help='Path to export evidence capsule JSON')
    run_p.set_defaults(func=cmd_run)
    ver_p = subparsers.add_parser('verify', help='Independently verify an evidence capsule')
    ver_p.add_argument('--file', '-f', required=True, help='Path to evidence capsule JSON')
    ver_p.add_argument('--trusted-key', '-k', default=None, help='Trusted evaluator Ed25519 public key')
    ver_p.set_defaults(func=cmd_verify)
    bm_p = subparsers.add_parser('benchmark', help='Run baseline comparative benchmark')
    bm_p.set_defaults(func=cmd_benchmark)
    serve_p = subparsers.add_parser('serve', help='Launch operator dashboard web server')
    serve_p.add_argument('--host', default='127.0.0.1', help='Host interface to bind')
    serve_p.add_argument('--port', type=int, default=8000, help='Port to listen on')
    serve_p.set_defaults(func=cmd_serve)
    args = parser.parse_args()
    return args.func(args)

if __name__ == '__main__':
    sys.exit(main())
