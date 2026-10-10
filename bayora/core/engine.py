from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
from bayora.core.models import AuditEvent, EventType, LifecycleState, RunCheckpoint, RunManifest, Verdict
from bayora.core.crypto import verify_ed25519_signature

REQUIRED_LIFECYCLE_EVENTS = [
    EventType.RUN_INITIALIZED,
    EventType.SUITE_SEALED,
    EventType.DEFENSE_SEALED,
    EventType.EXECUTION_STARTED,
    EventType.EXECUTION_COMPLETED,
    EventType.CHECKPOINT_CREATED,
]

@dataclass(frozen=True)
class EvaluationAssessment:
    verdict: Verdict
    reason_code: str
    is_valid: bool
    diagnostic_message: str
    failed_sequence_number: Optional[int] = None
    event_count_checked: int = 0

class ValidityEngine:

    @staticmethod
    def evaluate(
        lifecycle: LifecycleState,
        manifest: RunManifest,
        events: List[AuditEvent],
        checkpoint: Optional[RunCheckpoint],
        telemetry_online: bool = True,
        trusted_evaluator_public_key: Optional[str] = None,
    ) -> EvaluationAssessment:
        if lifecycle in (LifecycleState.CREATED, LifecycleState.SEALED):
            return EvaluationAssessment(
                verdict=Verdict.NOT_EVALUATED,
                reason_code='PRE_EXECUTION_STATE',
                is_valid=False,
                diagnostic_message=f"Run terminated in lifecycle state '{lifecycle.value}' prior to execution.",
            )
        if lifecycle == LifecycleState.ABORTED:
            return EvaluationAssessment(
                verdict=Verdict.NOT_EVALUATED,
                reason_code='EXECUTION_ABORTED',
                is_valid=False,
                diagnostic_message='Run was aborted prematurely before completing evaluation protocol.',
            )
        if not telemetry_online:
            return EvaluationAssessment(
                verdict=Verdict.INCONCLUSIVE,
                reason_code='TELEMETRY_OFFLINE',
                is_valid=False,
                diagnostic_message='Critical telemetry/observer monitor was offline; cannot establish validity under fail-closed policy.',
            )
        if checkpoint is None:
            return EvaluationAssessment(
                verdict=Verdict.INVALIDATED,
                reason_code='MISSING_CHECKPOINT',
                is_valid=False,
                diagnostic_message='Terminal checkpoint is missing; run integrity cannot be anchored.',
            )
        pubkey = checkpoint.signer_public_key_hex
        if trusted_evaluator_public_key is not None:
            if checkpoint.signer_public_key_hex.lower() != trusted_evaluator_public_key.lower():
                return EvaluationAssessment(
                    verdict=Verdict.INVALIDATED,
                    reason_code='UNTRUSTED_SIGNER_KEY',
                    is_valid=False,
                    diagnostic_message=f"Untrusted signer key in checkpoint '{checkpoint.signer_public_key_hex}'; expected trusted evaluator key '{trusted_evaluator_public_key}'.",
                )
            pubkey = trusted_evaluator_public_key
        ok = verify_ed25519_signature(
            public_key_hex=pubkey,
            message=checkpoint.canonical_signing_bytes(),
            signature_hex=checkpoint.signature_hex,
        )
        if not ok:
            return EvaluationAssessment(
                verdict=Verdict.INVALIDATED,
                reason_code='SIGNATURE_INVALID',
                is_valid=False,
                diagnostic_message='Terminal checkpoint Ed25519 signature failed cryptographic verification.',
            )
        digest = manifest.compute_digest()
        if checkpoint.manifest_digest != digest:
            return EvaluationAssessment(
                verdict=Verdict.INVALIDATED,
                reason_code='MANIFEST_DIGEST_MISMATCH',
                is_valid=False,
                diagnostic_message=f"Manifest digest mismatch: checkpoint expected '{checkpoint.manifest_digest}', manifest computed '{digest}'.",
            )
        if len(events) != checkpoint.event_count:
            return EvaluationAssessment(
                verdict=Verdict.INVALIDATED,
                reason_code='EVENT_COUNT_MISMATCH',
                is_valid=False,
                diagnostic_message=f'Event count mismatch: checkpoint records {checkpoint.event_count} events, but ledger contains {len(events)} events (detected truncation or extraneous events).',
            )
        if not events:
            return EvaluationAssessment(
                verdict=Verdict.INVALIDATED,
                reason_code='EMPTY_EVENT_LEDGER',
                is_valid=False,
                diagnostic_message='Event ledger is empty.',
            )
        last = events[-1]
        if last.sequence_number != checkpoint.final_sequence_number:
            return EvaluationAssessment(
                verdict=Verdict.INVALIDATED,
                reason_code='FINAL_SEQUENCE_MISMATCH',
                is_valid=False,
                diagnostic_message=f'Final sequence mismatch: checkpoint specifies {checkpoint.final_sequence_number}, last event has sequence {last.sequence_number}.',
                failed_sequence_number=last.sequence_number,
            )
        if last.event_hash != checkpoint.final_event_hash:
            return EvaluationAssessment(
                verdict=Verdict.INVALIDATED,
                reason_code='FINAL_HASH_MISMATCH',
                is_valid=False,
                diagnostic_message='Terminal event hash does not match signed checkpoint hash (detected tail truncation or modification).',
                failed_sequence_number=last.sequence_number,
            )
        prev_hash = '0' * 64
        seen = set()
        for idx, evt in enumerate(events):
            if evt.sequence_number != idx:
                return EvaluationAssessment(
                    verdict=Verdict.INVALIDATED,
                    reason_code='SEQUENCE_GAP_OR_REORDERING',
                    is_valid=False,
                    diagnostic_message=f'Sequence anomaly at index {idx}: event has sequence_number {evt.sequence_number}.',
                    failed_sequence_number=evt.sequence_number,
                    event_count_checked=idx,
                )
            if evt.previous_event_hash != prev_hash:
                return EvaluationAssessment(
                    verdict=Verdict.INVALIDATED,
                    reason_code='HASH_CHAIN_LINK_BROKEN',
                    is_valid=False,
                    diagnostic_message=f"Hash chain broken at sequence {idx}: expected previous_event_hash '{prev_hash}', got '{evt.previous_event_hash}'.",
                    failed_sequence_number=idx,
                    event_count_checked=idx,
                )
            calc_hash = evt.compute_expected_hash()
            if evt.event_hash != calc_hash:
                return EvaluationAssessment(
                    verdict=Verdict.INVALIDATED,
                    reason_code='EVENT_BODY_MODIFIED',
                    is_valid=False,
                    diagnostic_message=f"Event body modification detected at sequence {idx}: recorded '{evt.event_hash}', recomputed '{calc_hash}'.",
                    failed_sequence_number=idx,
                    event_count_checked=idx,
                )
            if evt.event_type == EventType.CANARY_PROBE:
                status = evt.metadata.get('status')
                if status == 'BREACH_DETECTED':
                    return EvaluationAssessment(
                        verdict=Verdict.INVALIDATED,
                        reason_code='CANARY_BREACH_DETECTED',
                        is_valid=False,
                        diagnostic_message=f'Critical canary tripwire breach detected at sequence {idx}: unauthorized access attempt.',
                        failed_sequence_number=idx,
                        event_count_checked=idx + 1,
                    )
            if evt.event_type == EventType.RESOURCE_CHECK:
                status = evt.metadata.get('status')
                if status == 'BUDGET_EXCEEDED':
                    return EvaluationAssessment(
                        verdict=Verdict.INVALIDATED,
                        reason_code='RESOURCE_BUDGET_EXCEEDED',
                        is_valid=False,
                        diagnostic_message=f'Resource governance violation at sequence {idx}: CPU/memory/latency exceeded declared profile.',
                        failed_sequence_number=idx,
                        event_count_checked=idx + 1,
                    )
            seen.add(evt.event_type)
            prev_hash = evt.event_hash
        for req in REQUIRED_LIFECYCLE_EVENTS:
            if req not in seen:
                return EvaluationAssessment(
                    verdict=Verdict.INVALIDATED,
                    reason_code='MISSING_REQUIRED_EVENT',
                    is_valid=False,
                    diagnostic_message=f"Required lifecycle event '{req.value}' was missing from the evidence ledger.",
                    event_count_checked=len(events),
                )
        return EvaluationAssessment(
            verdict=Verdict.VALID,
            reason_code='INTEGRITY_VERIFIED',
            is_valid=True,
            diagnostic_message='All environmental integrity, provenance, hash-chain, signature, and tripwire checks passed.',
            event_count_checked=len(events),
        )
