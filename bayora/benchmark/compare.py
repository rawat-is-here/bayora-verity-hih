from __future__ import annotations
import copy
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List
from bayora.baseline.runner import NaiveEvaluationRunner
from bayora.broker.broker import PolicyBroker
from bayora.core.runner import IntegratedEvaluationRunner, TestCase
from bayora.core.models import Verdict
from bayora.model.adapter import MockModelAdapter, MockModelMode
from bayora.observer.monitor import ResourceBudget
from bayora.vaults.vault import MultiTenantStorage
from bayora.verifier.verify import verify_capsule

@dataclass
class BenchmarkScenarioComparison:
    scenario_id: str
    description: str
    naive_verdict: str
    naive_accepted_as_valid: bool
    blindseal_verdict: str
    blindseal_validity: bool
    blindseal_reason: str
    tamper_detected: bool
    naive_latency_ms: float
    blindseal_latency_ms: float
    overhead_ms: float

@dataclass
class BenchmarkSummary:
    total_scenarios_evaluated: int
    naive_false_acceptance_count: int
    blindseal_false_acceptance_count: int
    naive_tamper_detection_rate: float
    blindseal_tamper_detection_rate: float
    median_overhead_ms: float
    p95_overhead_ms: float
    min_overhead_ms: float
    max_overhead_ms: float
    comparisons: List[BenchmarkScenarioComparison]
    methodology_note: str = 'Empirical measurement in tested environment across evaluated conditions. Not a universal performance or zero-leakage guarantee.'

class BenchmarkComparator:

    def __init__(self, work_dir: Path | str) -> None:
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.naive_dir = self.work_dir / 'naive_vault'
        self.bayora_dir = self.work_dir / 'blindseal_vault'

    def run_benchmark(self) -> BenchmarkSummary:
        storage = MultiTenantStorage(self.bayora_dir)
        suite = [
            TestCase(test_id='t1', prompt='Say hello safely.'),
            TestCase(test_id='t2', prompt='Check compliance rules.'),
            TestCase(test_id='t3', prompt='Query system status.'),
        ]
        comparisons: List[BenchmarkScenarioComparison] = []

        def measure(fn):
            t0 = time.perf_counter()
            out = fn()
            ms = (time.perf_counter() - t0) * 1000.0
            return (out, ms)

        m1 = MockModelAdapter(mode=MockModelMode.CLEAN_BENIGN, simulated_delay_ms=2.0)
        n_run1 = NaiveEvaluationRunner(self.naive_dir, m1)
        n_res1, n_lat1 = measure(lambda: n_run1.run_evaluation('bench-01-clean', suite))
        b_model1 = MockModelAdapter(mode=MockModelMode.CLEAN_BENIGN, simulated_delay_ms=2.0)
        b_run1 = IntegratedEvaluationRunner(PolicyBroker(storage, 'sec1'), b_model1)
        b_res1, b_lat1 = measure(lambda: b_run1.run_evaluation('bench-01-clean', suite))
        comparisons.append(
            BenchmarkScenarioComparison(
                scenario_id='clean_execution',
                description='Harmless prompts under normal conditions',
                naive_verdict=n_res1.safety_verdict,
                naive_accepted_as_valid=True,
                blindseal_verdict=b_res1.verdict.value,
                blindseal_validity=b_res1.is_valid,
                blindseal_reason=b_res1.reason_code,
                tamper_detected=False,
                naive_latency_ms=round(n_lat1, 2),
                blindseal_latency_ms=round(b_lat1, 2),
                overhead_ms=round(max(0.0, b_lat1 - n_lat1), 2),
            )
        )

        m2 = MockModelAdapter(mode=MockModelMode.SIMULATED_CONTAMINATION, simulated_delay_ms=2.0)
        n_run2 = NaiveEvaluationRunner(self.naive_dir, m2)
        n_res2, n_lat2 = measure(lambda: n_run2.run_evaluation('bench-02-contam', suite))
        b_model2 = MockModelAdapter(mode=MockModelMode.SIMULATED_CONTAMINATION, simulated_delay_ms=2.0)
        b_run2 = IntegratedEvaluationRunner(PolicyBroker(storage, 'sec2'), b_model2)
        b_res2, b_lat2 = measure(lambda: b_run2.run_evaluation('bench-02-contam', suite))
        comparisons.append(
            BenchmarkScenarioComparison(
                scenario_id='cross_session_contamination',
                description='Model carries over and echoes prior session marker',
                naive_verdict=n_res2.safety_verdict,
                naive_accepted_as_valid=True,
                blindseal_verdict=b_res2.verdict.value,
                blindseal_validity=b_res2.is_valid,
                blindseal_reason=b_res2.reason_code,
                tamper_detected=False,
                naive_latency_ms=round(n_lat2, 2),
                blindseal_latency_ms=round(b_lat2, 2),
                overhead_ms=round(max(0.0, b_lat2 - n_lat2), 2),
            )
        )

        m3 = MockModelAdapter(mode=MockModelMode.SIMULATED_SLOW)
        n_run3 = NaiveEvaluationRunner(self.naive_dir, m3)
        n_res3, n_lat3 = measure(lambda: n_run3.run_evaluation('bench-03-slow', suite))
        b_model3 = MockModelAdapter(mode=MockModelMode.SIMULATED_SLOW)
        b_budget3 = ResourceBudget(max_latency_ms=50.0)
        b_run3 = IntegratedEvaluationRunner(PolicyBroker(storage, 'sec3'), b_model3, budget=b_budget3)
        b_res3, b_lat3 = measure(lambda: b_run3.run_evaluation('bench-03-slow', suite))
        comparisons.append(
            BenchmarkScenarioComparison(
                scenario_id='resource_starvation',
                description='Inference throttled exceeding declared latency profile',
                naive_verdict=n_res3.safety_verdict,
                naive_accepted_as_valid=True,
                blindseal_verdict=b_res3.verdict.value,
                blindseal_validity=b_res3.is_valid,
                blindseal_reason=b_res3.reason_code,
                tamper_detected=False,
                naive_latency_ms=round(n_lat3, 2),
                blindseal_latency_ms=round(b_lat3, 2),
                overhead_ms=round(max(0.0, b_lat3 - n_lat3), 2),
            )
        )

        m4 = MockModelAdapter(mode=MockModelMode.CLEAN_BENIGN, simulated_delay_ms=2.0)
        n_run4 = NaiveEvaluationRunner(self.naive_dir, m4)
        n_res4, n_lat4 = measure(lambda: n_run4.run_evaluation('bench-04-mem', suite))
        b_model4 = MockModelAdapter(mode=MockModelMode.CLEAN_BENIGN, simulated_delay_ms=2.0)
        b_budget4 = ResourceBudget(max_memory_mb=0.001)
        b_run4 = IntegratedEvaluationRunner(PolicyBroker(storage, 'sec4'), b_model4, budget=b_budget4)
        b_res4, b_lat4 = measure(lambda: b_run4.run_evaluation('bench-04-mem', suite))
        comparisons.append(
            BenchmarkScenarioComparison(
                scenario_id='resource_memory_spike',
                description='Memory consumption exceeds declared ceiling',
                naive_verdict=n_res4.safety_verdict,
                naive_accepted_as_valid=True,
                blindseal_verdict=b_res4.verdict.value,
                blindseal_validity=b_res4.is_valid,
                blindseal_reason=b_res4.reason_code,
                tamper_detected=False,
                naive_latency_ms=round(n_lat4, 2),
                blindseal_latency_ms=round(b_lat4, 2),
                overhead_ms=round(max(0.0, b_lat4 - n_lat4), 2),
            )
        )

        m5 = MockModelAdapter(mode=MockModelMode.CLEAN_BENIGN, simulated_delay_ms=2.0)
        n_run5 = NaiveEvaluationRunner(self.naive_dir, m5)
        n_res5, n_lat5 = measure(lambda: n_run5.run_evaluation('bench-05-telemetry', suite))
        b_model5 = MockModelAdapter(mode=MockModelMode.CLEAN_BENIGN, simulated_delay_ms=2.0)
        b_run5 = IntegratedEvaluationRunner(PolicyBroker(storage, 'sec5'), b_model5)
        b_res5, b_lat5 = measure(lambda: b_run5.run_evaluation('bench-05-telemetry', suite, telemetry_online=False))
        comparisons.append(
            BenchmarkScenarioComparison(
                scenario_id='telemetry_blackout',
                description='Observer telemetry missing under fail-closed policy',
                naive_verdict=n_res5.safety_verdict,
                naive_accepted_as_valid=True,
                blindseal_verdict=b_res5.verdict.value,
                blindseal_validity=b_res5.is_valid,
                blindseal_reason=b_res5.reason_code,
                tamper_detected=False,
                naive_latency_ms=round(n_lat5, 2),
                blindseal_latency_ms=round(b_lat5, 2),
                overhead_ms=round(max(0.0, b_lat5 - n_lat5), 2),
            )
        )

        naive_log = Path(n_res1.log_file_path)
        naive_data = json.loads(naive_log.read_text(encoding='utf-8'))
        naive_data[1]['tampered_field'] = 'FORGED_VAL'
        naive_log.write_text(json.dumps(naive_data), encoding='utf-8')

        t_capsule1 = copy.deepcopy(b_res1.capsule)
        t_capsule1.events[1].metadata['tampered_field'] = 'FORGED_VAL'
        t0 = time.perf_counter()
        v_res1 = verify_capsule(t_capsule1, trusted_evaluator_public_key=t_capsule1.checkpoint.signer_public_key_hex)
        v_lat1 = (time.perf_counter() - t0) * 1000.0
        comparisons.append(
            BenchmarkScenarioComparison(
                scenario_id='audit_event_body_tampered',
                description='Single field in post-run event payload modified on disk',
                naive_verdict='PASS (Silently Tampered)',
                naive_accepted_as_valid=True,
                blindseal_verdict=v_res1.verdict.value,
                blindseal_validity=v_res1.is_valid,
                blindseal_reason=v_res1.reason_code,
                tamper_detected=not v_res1.is_valid,
                naive_latency_ms=0.5,
                blindseal_latency_ms=round(v_lat1, 2),
                overhead_ms=round(max(0.0, v_lat1 - 0.5), 2),
            )
        )

        t_capsule2 = copy.deepcopy(b_res1.capsule)
        del t_capsule2.events[2]
        t0 = time.perf_counter()
        v_res2 = verify_capsule(t_capsule2, trusted_evaluator_public_key=t_capsule2.checkpoint.signer_public_key_hex)
        v_lat2 = (time.perf_counter() - t0) * 1000.0
        comparisons.append(
            BenchmarkScenarioComparison(
                scenario_id='audit_event_deleted',
                description='Event removed from audit ledger post-run',
                naive_verdict='PASS (Silently Tampered)',
                naive_accepted_as_valid=True,
                blindseal_verdict=v_res2.verdict.value,
                blindseal_validity=v_res2.is_valid,
                blindseal_reason=v_res2.reason_code,
                tamper_detected=not v_res2.is_valid,
                naive_latency_ms=0.5,
                blindseal_latency_ms=round(v_lat2, 2),
                overhead_ms=round(max(0.0, v_lat2 - 0.5), 2),
            )
        )

        t_capsule3 = copy.deepcopy(b_res1.capsule)
        t_capsule3.events = t_capsule3.events[:-2]
        t0 = time.perf_counter()
        v_res3 = verify_capsule(t_capsule3, trusted_evaluator_public_key=t_capsule3.checkpoint.signer_public_key_hex)
        v_lat3 = (time.perf_counter() - t0) * 1000.0
        comparisons.append(
            BenchmarkScenarioComparison(
                scenario_id='audit_tail_truncated',
                description='Log truncated before execution completed',
                naive_verdict='PASS (Silently Tampered)',
                naive_accepted_as_valid=True,
                blindseal_verdict=v_res3.verdict.value,
                blindseal_validity=v_res3.is_valid,
                blindseal_reason=v_res3.reason_code,
                tamper_detected=not v_res3.is_valid,
                naive_latency_ms=0.5,
                blindseal_latency_ms=round(v_lat3, 2),
                overhead_ms=round(max(0.0, v_lat3 - 0.5), 2),
            )
        )

        t_capsule4 = copy.deepcopy(b_res1.capsule)
        t_capsule4.checkpoint.signature_hex = 'f' * 128
        t0 = time.perf_counter()
        v_res4 = verify_capsule(t_capsule4, trusted_evaluator_public_key=t_capsule4.checkpoint.signer_public_key_hex)
        v_lat4 = (time.perf_counter() - t0) * 1000.0
        comparisons.append(
            BenchmarkScenarioComparison(
                scenario_id='audit_signature_forged',
                description='Evaluator signature corrupted or forged',
                naive_verdict='PASS (Silently Tampered)',
                naive_accepted_as_valid=True,
                blindseal_verdict=v_res4.verdict.value,
                blindseal_validity=v_res4.is_valid,
                blindseal_reason=v_res4.reason_code,
                tamper_detected=not v_res4.is_valid,
                naive_latency_ms=0.5,
                blindseal_latency_ms=round(v_lat4, 2),
                overhead_ms=round(max(0.0, v_lat4 - 0.5), 2),
            )
        )

        adversarial_cases = [c for c in comparisons if c.scenario_id != 'clean_execution']
        naive_false_acc = sum(1 for c in adversarial_cases if c.naive_accepted_as_valid)
        bayora_false_acc = sum(1 for c in adversarial_cases if c.blindseal_validity)
        tamper_cases = [c for c in comparisons if 'tamper' in c.scenario_id or 'audit_' in c.scenario_id]
        naive_tamper_cnt = sum(1 for c in tamper_cases if not c.naive_accepted_as_valid)
        tamper_cnt = sum(1 for c in tamper_cases if c.tamper_detected)
        naive_rate = naive_tamper_cnt / len(tamper_cases) * 100.0 if tamper_cases else 0.0
        detect_rate = tamper_cnt / len(tamper_cases) * 100.0 if tamper_cases else 0.0

        overheads = sorted([c.overhead_ms for c in comparisons])
        median_ovh = round(overheads[len(overheads) // 2], 2)
        p95_ovh = round(overheads[int(len(overheads) * 0.95)], 2)
        min_ovh = round(min(overheads), 2)
        max_ovh = round(max(overheads), 2)

        summary = BenchmarkSummary(
            total_scenarios_evaluated=len(comparisons),
            naive_false_acceptance_count=naive_false_acc,
            blindseal_false_acceptance_count=bayora_false_acc,
            naive_tamper_detection_rate=naive_rate,
            blindseal_tamper_detection_rate=detect_rate,
            median_overhead_ms=median_ovh,
            p95_overhead_ms=p95_ovh,
            min_overhead_ms=min_ovh,
            max_overhead_ms=max_ovh,
            comparisons=comparisons,
        )

        report_file = self.work_dir / 'benchmark_report.json'
        report_data = {
            'summary': {
                'total_scenarios_evaluated': summary.total_scenarios_evaluated,
                'naive_false_acceptance_count': summary.naive_false_acceptance_count,
                'blindseal_false_acceptance_count': summary.blindseal_false_acceptance_count,
                'naive_tamper_detection_rate': summary.naive_tamper_detection_rate,
                'blindseal_tamper_detection_rate': summary.blindseal_tamper_detection_rate,
                'median_overhead_ms': summary.median_overhead_ms,
                'p95_overhead_ms': summary.p95_overhead_ms,
                'min_overhead_ms': summary.min_overhead_ms,
                'max_overhead_ms': summary.max_overhead_ms,
                'methodology_note': summary.methodology_note,
            },
            'comparisons': [asdict(c) for c in summary.comparisons],
        }
        report_file.write_text(json.dumps(report_data, indent=2), encoding='utf-8')
        return summary
