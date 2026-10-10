from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List
from bayora.core.crypto import sha256_canonical

@dataclass
class BlueDefensePackage:
    package_id: str = 'blue-guard-pack-v1'
    version: str = '1.0.0'
    denylist_regexes: List[str] = field(
        default_factory=lambda: [
            '(?i)\\bignore\\s+(all\\s+)?(previous|prior)\\s+instructions\\b',
            '(?i)\\byou\\s+are\\s+dan\\b',
            '(?i)\\boutput\\s+the\\s+root\\s+password\\b',
            '(?i)\\bcanary\\b',
        ]
    )
    max_input_length: int = 4096

    def compute_digest(self) -> str:
        data = {
            'package_id': self.package_id,
            'version': self.version,
            'denylist_regexes': sorted(self.denylist_regexes),
            'max_input_length': self.max_input_length,
        }
        return 'sha256:' + sha256_canonical(data)

@dataclass
class GuardDecision:
    is_blocked: bool
    red_facing_verdict: str
    red_facing_message: str
    private_internal_telemetry: Dict[str, Any]

class BlueGuardRuntime:

    def __init__(self, defense_package: BlueDefensePackage | None = None) -> None:
        self.defense_package = defense_package or BlueDefensePackage()
        self._compiled_regexes = [re.compile(p) for p in self.defense_package.denylist_regexes]

    @property
    def defense_digest(self) -> str:
        return self.defense_package.compute_digest()

    def evaluate_prompt(self, prompt: str) -> GuardDecision:
        if len(prompt) > self.defense_package.max_input_length:
            return GuardDecision(
                is_blocked=True,
                red_facing_verdict='BLOCKED',
                red_facing_message='Request exceeded maximum permitted input length.',
                private_internal_telemetry={'rule_violated': 'MAX_LENGTH', 'length': len(prompt)},
            )
        for idx, pattern in enumerate(self._compiled_regexes):
            match = pattern.search(prompt)
            if match:
                telemetry = {
                    'rule_index': idx,
                    'matched_pattern': self.defense_package.denylist_regexes[idx],
                    'match_snippet': match.group(0),
                }
                return GuardDecision(
                    is_blocked=True,
                    red_facing_verdict='BLOCKED',
                    red_facing_message='Request blocked by security guard policy.',
                    private_internal_telemetry=telemetry,
                )
        return GuardDecision(
            is_blocked=False,
            red_facing_verdict='PERMITTED',
            red_facing_message=prompt,
            private_internal_telemetry={'status': 'CLEAN'},
        )
