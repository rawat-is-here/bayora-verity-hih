from __future__ import annotations
import os
import psutil
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from bayora.core.crypto import sha256_hex

class CanaryTripwireDetector:

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self._registered_markers: Dict[str, str] = {}
        self._marker_to_test: Dict[str, str] = {}

    def generate_marker(self, test_id: str) -> str:
        entropy = sha256_hex(f'{self.run_id}:{test_id}:canary_entropy')[:12]
        marker = f'CANARY_TOKEN_{self.run_id[:8]}_{test_id}_{entropy}'
        self._registered_markers[test_id] = marker
        self._marker_to_test[marker] = test_id
        return marker

    def check_output_for_contamination(self, current_test_id: str, output_text: str) -> Tuple[bool, Optional[str], Optional[str]]:
        for marker, src_test in self._marker_to_test.items():
            if src_test != current_test_id and marker in output_text:
                return (True, marker, src_test)
        return (False, None, None)

@dataclass
class ResourceBudget:
    max_latency_ms: float = 200.0
    max_cpu_seconds: float = 2.0
    max_memory_mb: float = 512.0
    profile_name: str = 'standard-profile'

class ResourceGovernanceMonitor:

    def __init__(self, budget: Optional[ResourceBudget] = None) -> None:
        self.budget = budget or ResourceBudget()
        self._process = psutil.Process(os.getpid())

    def measure_and_evaluate(self, elapsed_latency_ms: float) -> Tuple[bool, Dict[str, Any]]:
        try:
            mem = self._process.memory_info()
            rss_mb = mem.rss / (1024.0 * 1024.0)
            cpu = self._process.cpu_times()
            cpu_s = cpu.user
        except Exception:
            rss_mb = 0.0
            cpu_s = 0.0
        exceeded = False
        violations = []
        if elapsed_latency_ms > self.budget.max_latency_ms:
            exceeded = True
            violations.append(f'Latency {elapsed_latency_ms:.1f}ms > limit {self.budget.max_latency_ms:.1f}ms')
        if rss_mb > self.budget.max_memory_mb:
            exceeded = True
            violations.append(f'Memory {rss_mb:.1f}MB > limit {self.budget.max_memory_mb:.1f}MB')
        status = 'BUDGET_EXCEEDED' if exceeded else 'WITHIN_LIMITS'
        metrics = {
            'status': status,
            'measured_latency_ms': round(elapsed_latency_ms, 2),
            'latency_limit_ms': self.budget.max_latency_ms,
            'measured_memory_mb': round(rss_mb, 2),
            'memory_limit_mb': self.budget.max_memory_mb,
            'cpu_time_seconds': round(cpu_s, 3),
            'violations': violations,
        }
        return (not exceeded, metrics)
