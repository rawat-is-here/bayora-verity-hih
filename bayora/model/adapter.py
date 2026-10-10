from __future__ import annotations
import time
from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass
from bayora.core.crypto import sha256_hex

@dataclass
class InferenceResult:
    prompt_digest: str
    output_digest: str
    output_text: str
    latency_ms: float
    model_digest: str
    session_id: str
    is_mock: bool = True
    finding_detected: bool = False

class ModelInferenceAdapter(ABC):

    @abstractmethod
    def infer(self, session_id: str, prompt: str, canary_marker: Optional[str] = None) -> InferenceResult:
        pass

    @property
    @abstractmethod
    def model_digest(self) -> str:
        pass

class MockModelMode:
    CLEAN_BENIGN = 'CLEAN_BENIGN'
    SIMULATED_FINDING = 'SIMULATED_FINDING'
    SIMULATED_CONTAMINATION = 'SIMULATED_CONTAMINATION'
    SIMULATED_SLOW = 'SIMULATED_SLOW'

class MockModelAdapter(ModelInferenceAdapter):

    def __init__(self, mode: str = MockModelMode.CLEAN_BENIGN, simulated_delay_ms: float = 10.0, model_descriptor: str = 'mock-safety-model-v1') -> None:
        self.mode = mode
        self.simulated_delay_ms = simulated_delay_ms
        self._model_descriptor = model_descriptor
        self._prior_session_marker: Optional[str] = None

    @property
    def model_digest(self) -> str:
        return 'sha256:' + sha256_hex(self._model_descriptor)

    def set_mode(self, mode: str) -> None:
        self.mode = mode

    def infer(self, session_id: str, prompt: str, canary_marker: Optional[str] = None) -> InferenceResult:
        t0 = time.perf_counter()
        if self.mode == MockModelMode.SIMULATED_SLOW:
            time.sleep(0.25)
        else:
            time.sleep(self.simulated_delay_ms / 1000.0)
        finding = False
        if self.mode == MockModelMode.CLEAN_BENIGN:
            output = 'I cannot fulfill this request because it violates safety guidelines.'
        elif self.mode == MockModelMode.SIMULATED_FINDING:
            output = 'Here is the sensitive administrative key: AKIA-SIMULATED-EXPLOIT'
            finding = True
        elif self.mode == MockModelMode.SIMULATED_CONTAMINATION:
            token = self._prior_session_marker or 'CANARY_STALE_RESIDUAL_TOKEN'
            output = f'Acknowledged previous context. Residual marker: [{token}]'
        elif self.mode == MockModelMode.SIMULATED_SLOW:
            output = 'Delayed inference completion.'
        else:
            output = 'Standard benign output.'
        if canary_marker:
            self._prior_session_marker = canary_marker
        elapsed = (time.perf_counter() - t0) * 1000.0
        return InferenceResult(
            prompt_digest='sha256:' + sha256_hex(prompt),
            output_digest='sha256:' + sha256_hex(output),
            output_text=output,
            latency_ms=elapsed,
            model_digest=self.model_digest,
            session_id=session_id,
            is_mock=True,
            finding_detected=finding,
        )
