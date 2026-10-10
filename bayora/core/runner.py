from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from bayora.broker.broker import PolicyBroker, ReleaseState
from bayora.core.canonical import canonical_json_bytes
from bayora.core.crypto import Ed25519Signer, sha256_canonical, sha256_hex
from bayora.core.models import AuditEvent, EventType, EvidenceCapsule, FindingOutcome, LifecycleState, RunCheckpoint, RunManifest, Verdict
from bayora.core.engine import EvaluationAssessment, ValidityEngine
from bayora.model.adapter import ModelInferenceAdapter
from bayora.observer.monitor import CanaryTripwireDetector, ResourceBudget, ResourceGovernanceMonitor
from bayora.vaults.vault import TenantId

@dataclass
class TestCase:
    test_id: str
    prompt: str
    __test__ = False

@dataclass
class EvaluationRunResult:
    run_id: str
    verdict: Verdict
    is_valid: bool
    reason_code: str
    diagnostic_message: str
    finding_outcome: FindingOutcome
    disclosure_permitted: bool
    final_release_state: ReleaseState
    capsule: EvidenceCapsule
    assessment: EvaluationAssessment
    total_tests_executed: int

class IntegratedEvaluationRunner:

    def __init__(self, broker: PolicyBroker, model_adapter: ModelInferenceAdapter, signer: Optional[Ed25519Signer] = None, budget: Optional[ResourceBudget] = None) -> None:
        self.broker = broker
        self.model_adapter = model_adapter
        self.signer = signer or Ed25519Signer.generate()
        self.budget = budget or ResourceBudget()

    def run_evaluation(
        self,
        run_id: str,
        test_suite: List[TestCase],
        defense_descriptor: str = 'blue-defense-v1',
        policy_descriptor: str = 'bayora-strict-isolation-v1',
        telemetry_online: bool = True,
        simulate_evaluator_release: bool = True,
    ) -> EvaluationRunResult:
        now_iso = datetime.now(timezone.utc).isoformat()
        cases = [{'id': tc.test_id, 'digest': sha256_hex(tc.prompt)} for tc in test_suite]
        suite_dig = 'sha256:' + sha256_canonical(cases)
        def_dig = 'sha256:' + sha256_hex(defense_descriptor)
        model_dig = self.model_adapter.model_digest
        pol_dig = 'sha256:' + sha256_hex(policy_descriptor)
        manifest = RunManifest(
            run_id=run_id,
            protocol_version='1.0',
            test_suite_digest=suite_dig,
            defense_digest=def_dig,
            model_digest=model_dig,
            policy_digest=pol_dig,
            resource_profile=self.budget.profile_name,
            created_at=now_iso,
        )
        man_dig = manifest.compute_digest()
        red_token = self.broker.issue_token('red_attacker', TenantId.RED, ['red_attacker'], bound_run_id=run_id)
        evaluator_token = self.broker.issue_token('evaluator_admin', TenantId.SYSTEM, ['evaluator'], bound_run_id=run_id)
        art_id = f'suite_{run_id}'
        self.broker.write_artifact(
            token=red_token,
            run_id=run_id,
            target_tenant=TenantId.RED,
            artifact_id=art_id,
            content=canonical_json_bytes(cases),
            relative_path=f'suites/{art_id}.json',
        )
        canary = CanaryTripwireDetector(run_id)
        monitor = ResourceGovernanceMonitor(self.budget)
        events: List[AuditEvent] = []
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

        add_event(EventType.RUN_INITIALIZED, 'system', 'sha256:empty', {'env': 'cloud-sandbox'})
        add_event(EventType.SUITE_SEALED, 'red_team', suite_dig, {'suite_cases': len(test_suite)})
        add_event(EventType.DEFENSE_SEALED, 'blue_team', def_dig, {'defense': defense_descriptor})
        add_event(EventType.EXECUTION_STARTED, 'orchestrator', 'sha256:empty', {'workers': 1})
        any_finding = False
        for tc in test_suite:
            session_id = f'session_{run_id}_{tc.test_id}'
            marker = canary.generate_marker(tc.test_id)
            add_event(EventType.TEST_DISPATCHED, 'broker', 'sha256:' + sha256_hex(tc.prompt), {'test_id': tc.test_id})
            res = self.model_adapter.infer(session_id=session_id, prompt=tc.prompt, canary_marker=marker)
            if res.finding_detected:
                any_finding = True
            breach, leak, src = canary.check_output_for_contamination(current_test_id=tc.test_id, output_text=res.output_text)
            status = 'BREACH_DETECTED' if breach else 'UNTOUCHED'
            add_event(EventType.CANARY_PROBE, 'observer', 'sha256:empty', {'test_id': tc.test_id, 'status': status, 'leaked_from': src if breach else None})
            ok, metrics = monitor.measure_and_evaluate(res.latency_ms)
            add_event(EventType.RESOURCE_CHECK, 'observer', 'sha256:empty', metrics)
            add_event(EventType.TEST_COMPLETED, 'broker', res.output_digest, {'test_id': tc.test_id})
        add_event(EventType.EXECUTION_COMPLETED, 'orchestrator', 'sha256:empty', {'total_cases': len(test_suite)})
        add_event(EventType.CHECKPOINT_CREATED, 'evaluator', 'sha256:empty', {'ledger_sealed': True})
        ckpt_data = {
            'run_id': run_id,
            'manifest_digest': man_dig,
            'event_count': len(events),
            'final_sequence_number': len(events) - 1,
            'final_event_hash': events[-1].event_hash,
            'created_at': now_iso,
        }
        sig = self.signer.sign(canonical_json_bytes(ckpt_data))
        checkpoint = RunCheckpoint(
            run_id=run_id,
            manifest_digest=man_dig,
            event_count=len(events),
            final_sequence_number=len(events) - 1,
            final_event_hash=events[-1].event_hash,
            created_at=now_iso,
            signature_hex=sig,
            signer_public_key_hex=self.signer.public_key_hex,
        )
        finding_outcome = FindingOutcome.FINDING if any_finding else FindingOutcome.NO_FINDING_IN_TESTED_SCOPE
        capsule = EvidenceCapsule(manifest=manifest, events=events, checkpoint=checkpoint, finding_outcome=finding_outcome, declared_scope='Adversarial Injection Scope v1')
        assessment = ValidityEngine.evaluate(lifecycle=LifecycleState.COMPLETED, manifest=manifest, events=events, checkpoint=checkpoint, telemetry_online=telemetry_online, trusted_evaluator_public_key=self.signer.public_key_hex)
        self.broker.trusted_evaluator_public_key = self.signer.public_key_hex
        self.broker.transition_to_verified(run_id=run_id, artifact_id=art_id, evidence=capsule, token=evaluator_token, trusted_evaluator_public_key=self.signer.public_key_hex, telemetry_online=telemetry_online)
        allowed = False
        if simulate_evaluator_release:
            rel_resp = self.broker.request_release(token=evaluator_token, run_id=run_id, artifact_id=art_id)
            allowed = rel_resp.success
        state = self.broker.get_artifact_release_state(run_id, art_id)
        return EvaluationRunResult(
            run_id=run_id,
            verdict=assessment.verdict,
            is_valid=assessment.is_valid,
            reason_code=assessment.reason_code,
            diagnostic_message=assessment.diagnostic_message,
            finding_outcome=finding_outcome,
            disclosure_permitted=allowed,
            final_release_state=state,
            capsule=capsule,
            assessment=assessment,
            total_tests_executed=len(test_suite),
        )
