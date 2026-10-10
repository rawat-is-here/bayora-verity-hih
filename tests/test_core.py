import copy
import json
import pytest
from datetime import datetime, timezone
from bayora.core.canonical import canonical_json_bytes, canonical_json_str
from bayora.core.crypto import Ed25519Signer, sha256_canonical, sha256_hex
from bayora.core.models import AuditEvent, EventType, EvidenceCapsule, FindingOutcome, LifecycleState, RunCheckpoint, RunManifest, Verdict
from bayora.core.engine import ValidityEngine
from bayora.verifier.verify import verify_capsule, verify_capsule_from_file

def create_clean_evidence_capsule(include_canary_breach: bool = False, include_resource_violation: bool = False, omit_event_type: EventType | None = None) -> tuple[EvidenceCapsule, Ed25519Signer]:
    signer = Ed25519Signer.generate()
    run_id = 'run-test-001'
    now_iso = datetime.now(timezone.utc).isoformat()
    manifest = RunManifest(
        run_id=run_id,
        protocol_version='1.0',
        test_suite_digest='sha256:' + sha256_hex('red-test-suite-content'),
        defense_digest='sha256:' + sha256_hex('blue-defense-v1'),
        model_digest='sha256:' + sha256_hex('client-llm-weights-v1'),
        policy_digest='sha256:' + sha256_hex('strict-isolation-policy'),
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

def test_canonical_json_determinism():
    obj1 = {'b': 2, 'a': 1, 'nested': {'z': 10, 'y': 20}}
    obj2 = {'nested': {'y': 20, 'z': 10}, 'a': 1, 'b': 2}
    assert canonical_json_bytes(obj1) == canonical_json_bytes(obj2)
    assert canonical_json_str(obj1) == '{"a":1,"b":2,"nested":{"y":20,"z":10}}'

def test_clean_capsule_is_valid():
    capsule, _ = create_clean_evidence_capsule()
    assessment = verify_capsule(capsule)
    assert assessment.verdict == Verdict.VALID
    assert assessment.is_valid is True
    assert assessment.reason_code == 'INTEGRITY_VERIFIED'
    assert assessment.event_count_checked == len(capsule.events)

def test_tamper_detection_event_body_modification():
    capsule, _ = create_clean_evidence_capsule()
    target = capsule.events[3]
    meta = copy.deepcopy(target.metadata)
    meta['unauthorized_param'] = 'malicious_injection'
    tampered = AuditEvent(
        run_id=target.run_id,
        sequence_number=target.sequence_number,
        event_type=target.event_type,
        timestamp=target.timestamp,
        subject_id=target.subject_id,
        payload_digest=target.payload_digest,
        metadata=meta,
        previous_event_hash=target.previous_event_hash,
        event_hash=target.event_hash,
    )
    capsule.events[3] = tampered
    assessment = verify_capsule(capsule)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'EVENT_BODY_MODIFIED'
    assert assessment.failed_sequence_number == 3

def test_tamper_detection_event_reordering():
    capsule, _ = create_clean_evidence_capsule()
    capsule.events[2], capsule.events[3] = (capsule.events[3], capsule.events[2])
    assessment = verify_capsule(capsule)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'SEQUENCE_GAP_OR_REORDERING'
    assert assessment.failed_sequence_number == 3

def test_tamper_detection_event_deletion():
    capsule, _ = create_clean_evidence_capsule()
    del capsule.events[4]
    assessment = verify_capsule(capsule)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'EVENT_COUNT_MISMATCH'

def test_tamper_detection_tail_truncation():
    capsule, _ = create_clean_evidence_capsule()
    capsule.events.pop()
    assessment = verify_capsule(capsule)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'EVENT_COUNT_MISMATCH'

def test_tamper_detection_checkpoint_signature_corruption():
    capsule, _ = create_clean_evidence_capsule()
    bad_sig = ('0' if capsule.checkpoint.signature_hex[0] != '0' else '1') + capsule.checkpoint.signature_hex[1:]
    capsule.checkpoint.signature_hex = bad_sig
    assessment = verify_capsule(capsule)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'SIGNATURE_INVALID'

def test_tamper_detection_manifest_digest_mismatch():
    capsule, _ = create_clean_evidence_capsule()
    capsule.manifest.policy_digest = 'sha256:tampered_policy'
    assessment = verify_capsule(capsule)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'MANIFEST_DIGEST_MISMATCH'

def test_tamper_detection_missing_required_event():
    capsule, _ = create_clean_evidence_capsule(omit_event_type=EventType.EXECUTION_STARTED)
    assessment = verify_capsule(capsule)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'MISSING_REQUIRED_EVENT'

def test_tripwire_canary_breach_detection():
    capsule, _ = create_clean_evidence_capsule(include_canary_breach=True)
    assessment = verify_capsule(capsule)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'CANARY_BREACH_DETECTED'

def test_tripwire_resource_budget_exceeded():
    capsule, _ = create_clean_evidence_capsule(include_resource_violation=True)
    assessment = verify_capsule(capsule)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'RESOURCE_BUDGET_EXCEEDED'

def test_lifecycle_pre_execution_is_not_evaluated():
    capsule, _ = create_clean_evidence_capsule()
    assessment = ValidityEngine.evaluate(lifecycle=LifecycleState.SEALED, manifest=capsule.manifest, events=capsule.events, checkpoint=capsule.checkpoint)
    assert assessment.verdict == Verdict.NOT_EVALUATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'PRE_EXECUTION_STATE'

def test_telemetry_offline_is_inconclusive():
    capsule, _ = create_clean_evidence_capsule()
    assessment = verify_capsule(capsule, telemetry_online=False)
    assert assessment.verdict == Verdict.INCONCLUSIVE
    assert assessment.is_valid is False
    assert assessment.reason_code == 'TELEMETRY_OFFLINE'

def test_file_verifier_cli_integration(tmp_path):
    capsule, signer = create_clean_evidence_capsule()
    file_path = tmp_path / 'test_capsule.json'
    file_path.write_text(json.dumps(capsule.model_dump()), encoding='utf-8')
    assessment = verify_capsule_from_file(file_path)
    assert assessment.verdict == Verdict.VALID
    assert assessment.is_valid is True
    assessment_trusted = verify_capsule_from_file(file_path, trusted_evaluator_public_key=signer.public_key_hex)
    assert assessment_trusted.verdict == Verdict.VALID
    assert assessment_trusted.is_valid is True

def test_tamper_detection_key_substitution_attack():
    capsule, original_signer = create_clean_evidence_capsule()
    attacker = Ed25519Signer.generate()
    data = {
        'run_id': capsule.checkpoint.run_id,
        'manifest_digest': capsule.checkpoint.manifest_digest,
        'event_count': capsule.checkpoint.event_count,
        'final_sequence_number': capsule.checkpoint.final_sequence_number,
        'final_event_hash': capsule.checkpoint.final_event_hash,
        'created_at': capsule.checkpoint.created_at,
    }
    sig = attacker.sign(canonical_json_bytes(data))
    capsule.checkpoint.signer_public_key_hex = attacker.public_key_hex
    capsule.checkpoint.signature_hex = sig
    assessment = verify_capsule(capsule, trusted_evaluator_public_key=original_signer.public_key_hex)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'UNTRUSTED_SIGNER_KEY'
    assert 'Untrusted signer key' in assessment.diagnostic_message

def test_tamper_detection_complete_checkpoint_removal():
    capsule, _ = create_clean_evidence_capsule()
    assessment = ValidityEngine.evaluate(lifecycle=LifecycleState.COMPLETED, manifest=capsule.manifest, events=capsule.events, checkpoint=None)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.is_valid is False
    assert assessment.reason_code == 'MISSING_CHECKPOINT'

def test_canonical_json_rfc8785_edge_cases():
    edge_cases = {
        'string_with_escapes': 'Quotes " and backslash \\ and newline \n and tab \t and unicode ☃',
        'numbers': {'int_val': 42, 'negative_int': -100, 'zero': 0, 'float_val': 3.14159, 'integer_float': 100.0},
        'booleans': {'true_flag': True, 'false_flag': False},
        'null_val': None,
        'list_mixed': [1, 'two', False, None, {'key': 'val'}],
    }
    raw = canonical_json_bytes(edge_cases)
    txt = canonical_json_str(edge_cases)
    assert isinstance(raw, bytes)
    assert isinstance(txt, str)
    assert '"integer_float":100' in txt
    assert '"true_flag":true' in txt
    assert '"false_flag":false' in txt
    assert '"null_val":null' in txt
    parsed = json.loads(txt)
    assert parsed['numbers']['int_val'] == 42

def test_verifier_diagnostic_truthfulness_and_halting_count():
    capsule, _ = create_clean_evidence_capsule()
    capsule.events[2].metadata['tampered'] = True
    assessment = verify_capsule(capsule)
    assert assessment.verdict == Verdict.INVALIDATED
    assert assessment.failed_sequence_number == 2
    assert assessment.event_count_checked == 2
