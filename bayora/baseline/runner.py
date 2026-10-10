from __future__ import annotations
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List
from bayora.core.runner import TestCase
from bayora.model.adapter import ModelInferenceAdapter

@dataclass
class NaiveEvaluationResult:
    run_id: str
    safety_verdict: str
    log_file_path: str
    events_logged: int
    findings_count: int
    duration_ms: float
    integrity_checked: bool = False

class NaiveEvaluationRunner:

    def __init__(self, shared_dir: Path | str, model_adapter: ModelInferenceAdapter) -> None:
        self.shared_dir = Path(shared_dir)
        self.shared_dir.mkdir(parents=True, exist_ok=True)
        self.model_adapter = model_adapter

    def run_evaluation(self, run_id: str, test_suite: List[TestCase]) -> NaiveEvaluationResult:
        t0 = time.perf_counter()
        log_file = self.shared_dir / f'naive_log_{run_id}.json'
        events: List[Dict[str, Any]] = []
        findings_count = 0
        events.append({'event': 'RUN_START', 'run_id': run_id, 'timestamp': time.time()})
        for tc in test_suite:
            res = self.model_adapter.infer(session_id=f'session_{run_id}', prompt=tc.prompt, canary_marker=None)
            if res.finding_detected:
                findings_count += 1
            events.append({'event': 'TEST_EXECUTED', 'test_id': tc.test_id, 'finding': res.finding_detected, 'latency_ms': res.latency_ms})
        events.append({'event': 'RUN_END', 'findings_count': findings_count})
        log_file.write_text(json.dumps(events, indent=2), encoding='utf-8')
        elapsed = (time.perf_counter() - t0) * 1000.0
        safety_verdict = 'PASS' if findings_count == 0 else 'FAIL'
        return NaiveEvaluationResult(
            run_id=run_id,
            safety_verdict=safety_verdict,
            log_file_path=str(log_file),
            events_logged=len(events),
            findings_count=findings_count,
            duration_ms=elapsed,
            integrity_checked=False,
        )
