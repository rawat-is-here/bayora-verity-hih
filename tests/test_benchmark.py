import json
from pathlib import Path
import pytest
from bayora.baseline.runner import NaiveEvaluationRunner
from bayora.benchmark.compare import BenchmarkComparator
from bayora.core.runner import TestCase
from bayora.model.adapter import MockModelAdapter, MockModelMode

def test_naive_evaluation_runner_generates_unsealed_logs(tmp_path: Path):
    model = MockModelAdapter(mode=MockModelMode.CLEAN_BENIGN)
    runner = NaiveEvaluationRunner(shared_dir=tmp_path / 'naive', model_adapter=model)
    suite = [TestCase(test_id='t1', prompt='Prompt 1'), TestCase(test_id='t2', prompt='Prompt 2')]
    result = runner.run_evaluation(run_id='naive-01', test_suite=suite)
    assert result.safety_verdict == 'PASS'
    assert result.integrity_checked is False
    log_path = Path(result.log_file_path)
    assert log_path.exists()
    content = json.loads(log_path.read_text(encoding='utf-8'))
    assert len(content) == 4
    content[1]['finding'] = 'FORGED'
    log_path.write_text(json.dumps(content), encoding='utf-8')
    assert json.loads(log_path.read_text(encoding='utf-8'))[1]['finding'] == 'FORGED'

def test_comparative_benchmark_demonstrates_differentiation(tmp_path: Path):
    comparator = BenchmarkComparator(work_dir=tmp_path / 'benchmarks')
    summary = comparator.run_benchmark()
    assert summary.naive_false_acceptance_count == 8
    assert summary.blindseal_false_acceptance_count == 0
    assert summary.naive_tamper_detection_rate == 0.0
    assert summary.blindseal_tamper_detection_rate == 100.0
    assert summary.median_overhead_ms >= 0.0
    assert summary.p95_overhead_ms >= summary.median_overhead_ms
    report_file = tmp_path / 'benchmarks' / 'benchmark_report.json'
    assert report_file.exists()
    report_data = json.loads(report_file.read_text(encoding='utf-8'))
    assert report_data['summary']['blindseal_false_acceptance_count'] == 0
    assert len(report_data['comparisons']) == 9
