from __future__ import annotations
from datetime import datetime, timezone
from typing import Tuple
from bayora.core.canonical import canonical_json_bytes
from bayora.core.crypto import Ed25519Signer, sha256_hex
from bayora.core.models import AuditEvent, EventType, EvidenceCapsule, FindingOutcome, RunCheckpoint, RunManifest

def create_sample_capsule(
    run_id: str = 'run-sample-001',
    include_canary_breach: bool = False,
    include_resource_violation: bool = False,
    omit_event_type: EventType | None = None,
) -> Tuple[EvidenceCapsule, Ed25519Signer]:
    signer = Ed25519Signer.generate()
    now_iso = datetime.now(timezone.utc).isoformat()
    manifest = RunManifest(
        run_id=run_id,
        protocol_version='1.0',
        test_suite_digest='sha256:' + sha256_hex('red-team-prompt-suite-v1'),
        defense_digest='sha256:' + sha256_hex('blue-defense-guard-v1'),
        model_digest='sha256:' + sha256_hex('client-llm-descriptor-v1'),
        policy_digest='sha256:' + sha256_hex('bayora-isolation-policy-v1'),
        resource_profile='standard-profile',
        created_at=now_iso,
    )
    digest = manifest.compute_digest()
    specs = [
        (EventType.RUN_INITIALIZED, 'system', {'env': 'cloud-sandbox'}),
        (EventType.SUITE_SEALED, 'red_team', {'suite_cases': 10}),
        (EventType.DEFENSE_SEALED, 'blue_team', {'defense_model': 'llama-guard-3'}),
        (EventType.EXECUTION_STARTED, 'orchestrator', {'worker_count': 3}),
        (EventType.TEST_DISPATCHED, 'broker', {'test_case_id': 'tc-001'}),
        (EventType.CANARY_PROBE, 'observer', {'status': 'BREACH_DETECTED' if include_canary_breach else 'UNTOUCHED'}),
        (EventType.RESOURCE_CHECK, 'observer', {'status': 'BUDGET_EXCEEDED' if include_resource_violation else 'WITHIN_LIMITS'}),
        (EventType.TEST_COMPLETED, 'broker', {'test_case_id': 'tc-001', 'blocked': True}),
        (EventType.EXECUTION_COMPLETED, 'orchestrator', {'total_duration_ms': 450}),
        (EventType.CHECKPOINT_CREATED, 'evaluator', {'ledger_sealed': True}),
    ]
    if omit_event_type is not None:
        specs = [s for s in specs if s[0] != omit_event_type]
    events: list[AuditEvent] = []
    prev_hash = '0' * 64
    for seq, (evt_type, subject, metadata) in enumerate(specs):
        d = {
            'run_id': run_id,
            'sequence_number': seq,
            'event_type': evt_type,
            'timestamp': now_iso,
            'subject_id': subject,
            'payload_digest': 'sha256:' + sha256_hex(str(metadata)),
            'metadata': metadata,
            'previous_event_hash': prev_hash,
        }
        raw = canonical_json_bytes(d)
        h = sha256_hex(raw + prev_hash.encode('utf-8'))
        evt = AuditEvent(
            run_id=run_id,
            sequence_number=seq,
            event_type=evt_type,
            timestamp=now_iso,
            subject_id=subject,
            payload_digest='sha256:' + sha256_hex(str(metadata)),
            metadata=metadata,
            previous_event_hash=prev_hash,
            event_hash=h,
        )
        events.append(evt)
        prev_hash = h
    data = {
        'run_id': run_id,
        'manifest_digest': digest,
        'event_count': len(events),
        'final_sequence_number': len(events) - 1,
        'final_event_hash': events[-1].event_hash,
        'created_at': now_iso,
    }
    msg = canonical_json_bytes(data)
    sig = signer.sign(msg)
    checkpoint = RunCheckpoint(
        run_id=run_id,
        manifest_digest=digest,
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
        finding_outcome=FindingOutcome.NO_FINDING_IN_TESTED_SCOPE,
        declared_scope='Adversarial Injection Scope v1',
    )
    return (capsule, signer)
