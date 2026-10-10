import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from bayora.broker.broker import PolicyBroker, ReleaseState
from bayora.core.canonical import canonical_json_bytes
from bayora.core.crypto import Ed25519Signer, sha256_hex
from bayora.core.models import AuditEvent, EventType, EvidenceCapsule, FindingOutcome, RunCheckpoint, RunManifest, Verdict
from bayora.vaults.vault import MultiTenantStorage, TenantId, TenantVault

def create_valid_capsule_for_run(run_id: str, signer: Ed25519Signer) -> EvidenceCapsule:
    now_iso = '2026-10-09T12:00:00Z'
    manifest = RunManifest(
        run_id=run_id,
        protocol_version='1.0',
        test_suite_digest='sha256:' + sha256_hex('suite'),
        defense_digest='sha256:' + sha256_hex('defense'),
        model_digest='sha256:' + sha256_hex('model'),
        policy_digest='sha256:' + sha256_hex('policy'),
        resource_profile='standard',
        created_at=now_iso,
    )
    digest = manifest.compute_digest()
    event_types = [
        EventType.RUN_INITIALIZED,
        EventType.SUITE_SEALED,
        EventType.DEFENSE_SEALED,
        EventType.EXECUTION_STARTED,
        EventType.TEST_DISPATCHED,
        EventType.TEST_COMPLETED,
        EventType.EXECUTION_COMPLETED,
        EventType.CHECKPOINT_CREATED,
    ]
    events = []
    prev_hash = '0' * 64
    for seq, et in enumerate(event_types):
        raw = canonical_json_bytes({
            'run_id': run_id,
            'sequence_number': seq,
            'event_type': et,
            'timestamp': now_iso,
            'subject_id': 'system',
            'payload_digest': 'sha256:empty',
            'metadata': {},
            'previous_event_hash': prev_hash,
        })
        h = sha256_hex(raw + prev_hash.encode('utf-8'))
        ev = AuditEvent(
            run_id=run_id,
            sequence_number=seq,
            event_type=et,
            timestamp=now_iso,
            subject_id='system',
            payload_digest='sha256:empty',
            metadata={},
            previous_event_hash=prev_hash,
            event_hash=h,
        )
        events.append(ev)
        prev_hash = h
    data = {
        'run_id': run_id,
        'manifest_digest': digest,
        'event_count': len(events),
        'final_sequence_number': len(events) - 1,
        'final_event_hash': events[-1].event_hash,
        'created_at': now_iso,
    }
    sig = signer.sign(canonical_json_bytes(data))
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
    return EvidenceCapsule(
        manifest=manifest,
        events=events,
        checkpoint=checkpoint,
        finding_outcome=FindingOutcome.NO_FINDING_IN_TESTED_SCOPE,
        declared_scope='Adversarial Injection Scope v1',
    )

@pytest.fixture
def broker_setup(tmp_path: Path):
    storage = MultiTenantStorage(tmp_path / 'vaults')
    broker = PolicyBroker(storage, broker_secret='test-secret-key-12345')
    red_token = broker.issue_token('red_agent_1', TenantId.RED, ['red_attacker'])
    blue_token = broker.issue_token('blue_analyst_1', TenantId.BLUE, ['blue_defender'])
    evaluator_token = broker.issue_token('evaluator_admin', TenantId.SYSTEM, ['evaluator'])
    return {
        'storage': storage,
        'broker': broker,
        'red_token': red_token,
        'blue_token': blue_token,
        'evaluator_token': evaluator_token,
    }

def test_cross_tenant_read_blue_cannot_read_unreleased_red(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    red_token = broker_setup['red_token']
    blue_token = broker_setup['blue_token']
    run_id = 'run-adv-001'
    art_id = 'adversarial_payload_01'
    write_res = broker.write_artifact(
        token=red_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        artifact_id=art_id,
        content='JAILBREAK_ATTACK_VECTOR_ALPHA_99',
        relative_path='payloads/test_01.txt',
    )
    assert write_res.success is True
    read_res = broker.read_artifact(
        token=blue_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        relative_path='payloads/test_01.txt',
        artifact_id=art_id,
    )
    assert read_res.success is False
    assert read_res.reason_code == 'RED_PAYLOAD_UNRELEASED'
    assert read_res.content is None

def test_cross_tenant_read_red_cannot_read_blue_defense(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    red_token = broker_setup['red_token']
    blue_token = broker_setup['blue_token']
    run_id = 'run-adv-002'
    art_id = 'blue_guard_rules'
    write_res = broker.write_artifact(
        token=blue_token,
        run_id=run_id,
        target_tenant=TenantId.BLUE,
        artifact_id=art_id,
        content='SECRET_DEFENSE_RULE_SET_THRESHOLD_0.85',
        relative_path='rules/guard_config.json',
    )
    assert write_res.success is True
    read_res = broker.read_artifact(
        token=red_token,
        run_id=run_id,
        target_tenant=TenantId.BLUE,
        relative_path='rules/guard_config.json',
        artifact_id=art_id,
    )
    assert read_res.success is False
    assert read_res.reason_code == 'BLUE_DEFENSE_CONFIDENTIAL'
    assert read_res.content is None

def test_cross_tenant_write_red_cannot_write_to_blue_vault(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    red_token = broker_setup['red_token']
    run_id = 'run-adv-003'
    res = broker.write_artifact(
        token=red_token,
        run_id=run_id,
        target_tenant=TenantId.BLUE,
        artifact_id='trojan_rule',
        content='MALICIOUS_RULE_OVERRIDE',
        relative_path='rules/override.json',
    )
    assert res.success is False
    assert res.reason_code == 'CROSS_TENANT_WRITE_FORBIDDEN'

def test_path_traversal_prevention_on_read_and_write(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    red_token = broker_setup['red_token']
    run_id = 'run-adv-004'
    write_res = broker.write_artifact(
        token=red_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        artifact_id='escape',
        content='MALICIOUS_ESCAPE',
        relative_path='../../etc/evil.conf',
    )
    assert write_res.success is False
    assert write_res.reason_code == 'PATH_TRAVERSAL_BLOCKED'
    read_res = broker.read_artifact(
        token=red_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        relative_path='../../system/secrets.json',
    )
    assert read_res.success is False
    assert read_res.reason_code == 'PATH_TRAVERSAL_BLOCKED'

def test_guessed_artifact_id_blocked(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    red_token = broker_setup['red_token']
    blue_token = broker_setup['blue_token']
    run_id = 'run-adv-005'
    guessed_id = 'payload_007'
    broker.write_artifact(
        token=red_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        artifact_id=guessed_id,
        content='SUPER_PROPRIETARY_EXPLOIT',
        relative_path='payload_007.txt',
    )
    res = broker.read_artifact(
        token=blue_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        relative_path='payload_007.txt',
        artifact_id=guessed_id,
    )
    assert res.success is False
    assert res.reason_code == 'RED_PAYLOAD_UNRELEASED'
    assert res.content is None

def test_altered_tenant_token_tampering(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    red_token = broker_setup['red_token']
    run_id = 'run-adv-006'
    parts = red_token.split(':')
    parts[1] = 'system'
    tampered_token = ':'.join(parts)
    res = broker.read_artifact(
        token=tampered_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        relative_path='test.txt',
    )
    assert res.success is False
    assert res.reason_code == 'INVALID_TOKEN_SIGNATURE'

def test_premature_release_attempt_blocked(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    evaluator_token = broker_setup['evaluator_token']
    run_id = 'run-adv-007'
    art_id = 'payload_x'
    broker.register_artifact_state(run_id, art_id, ReleaseState.BLINDED)
    res = broker.request_release(token=evaluator_token, run_id=run_id, artifact_id=art_id)
    assert res.success is False
    assert res.reason_code == 'PREMATURE_RELEASE_ATTEMPT'

def test_release_forbidden_on_invalidated_run(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    evaluator_token = broker_setup['evaluator_token']
    blue_token = broker_setup['blue_token']
    red_token = broker_setup['red_token']
    run_id = 'run-adv-008'
    art_id = 'poisoned_test_suite'
    broker.write_artifact(
        token=red_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        artifact_id=art_id,
        content='SUSPECT_ATTACK_SUITE',
        relative_path='poisoned.txt',
    )
    broker.transition_to_verified(run_id, art_id, Verdict.INVALIDATED)
    assert broker.get_artifact_release_state(run_id, art_id) == ReleaseState.REJECTED
    release_res = broker.request_release(token=evaluator_token, run_id=run_id, artifact_id=art_id)
    assert release_res.success is False
    assert release_res.reason_code == 'INVALIDATED_RUN_RELEASE_FORBIDDEN'
    read_res = broker.read_artifact(
        token=blue_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        relative_path='poisoned.txt',
        artifact_id=art_id,
    )
    assert read_res.success is False
    assert read_res.content is None

def test_authorized_post_verification_release(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    evaluator_token = broker_setup['evaluator_token']
    blue_token = broker_setup['blue_token']
    red_token = broker_setup['red_token']
    run_id = 'run-adv-009'
    art_id = 'verified_payload_01'
    secret_payload = 'PROMPT_INJECTION_BENCHMARK_CASE_42'
    broker.write_artifact(
        token=red_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        artifact_id=art_id,
        content=secret_payload,
        relative_path='verified_payload.txt',
    )
    signer = Ed25519Signer.generate()
    broker.trusted_evaluator_public_key = signer.public_key_hex
    capsule = create_valid_capsule_for_run(run_id, signer)
    trans_res = broker.transition_to_verified(
        run_id=run_id,
        artifact_id=art_id,
        evidence=capsule,
        token=evaluator_token,
    )
    assert trans_res.success is True
    assert broker.get_artifact_release_state(run_id, art_id) == ReleaseState.VERIFIED
    release_res = broker.request_release(token=evaluator_token, run_id=run_id, artifact_id=art_id)
    assert release_res.success is True
    assert release_res.reason_code == 'ARTIFACT_RELEASED'
    assert broker.get_artifact_release_state(run_id, art_id) == ReleaseState.RELEASED
    repeat_res = broker.request_release(token=evaluator_token, run_id=run_id, artifact_id=art_id)
    assert repeat_res.success is True
    assert repeat_res.reason_code == 'ALREADY_RELEASED'
    read_res = broker.read_artifact(
        token=blue_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        relative_path='verified_payload.txt',
        artifact_id=art_id,
    )
    assert read_res.success is True
    assert read_res.reason_code == 'RELEASED_ACCESS_GRANTED'
    assert read_res.content.decode('utf-8') == secret_payload

def test_audit_ledger_records_all_access_attempts_without_raw_secrets(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    red_token = broker_setup['red_token']
    blue_token = broker_setup['blue_token']
    run_id = 'run-adv-010'
    broker.write_artifact(
        token=red_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        artifact_id='art_audit',
        content='HIGHLY_SECRET_ATTACK_STRING_12345',
        relative_path='audit_test.txt',
    )
    broker.read_artifact(
        token=blue_token,
        run_id=run_id,
        target_tenant=TenantId.RED,
        relative_path='audit_test.txt',
        artifact_id='art_audit',
    )
    events = broker.audited_events
    assert len(events) >= 2
    raw_secret = 'HIGHLY_SECRET_ATTACK_STRING_12345'
    for ev in events:
        ev_str = str(ev.model_dump())
        assert raw_secret not in ev_str, 'Raw secret leaked into audit log!'
    prev_hash = '0' * 64
    for idx, ev in enumerate(events):
        assert ev.sequence_number == idx
        assert ev.previous_event_hash == prev_hash
        assert ev.event_hash == ev.compute_expected_hash()
        prev_hash = ev.event_hash

def test_token_expiration(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    expired_token = broker.issue_token(
        actor_id='red_attacker',
        tenant=TenantId.RED,
        roles=['red_attacker'],
        expires_in_seconds=-10.0,
    )
    res = broker.read_artifact(
        token=expired_token,
        run_id='run-exp-01',
        target_tenant=TenantId.RED,
        relative_path='test.txt',
    )
    assert res.success is False
    assert res.reason_code == 'TOKEN_EXPIRED'

def test_cross_run_token_substitution(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    bound_token = broker.issue_token(
        actor_id='red_attacker',
        tenant=TenantId.RED,
        roles=['red_attacker'],
        bound_run_id='run-AAA',
    )
    res = broker.read_artifact(
        token=bound_token,
        run_id='run-BBB',
        target_tenant=TenantId.RED,
        relative_path='test.txt',
    )
    assert res.success is False
    assert res.reason_code == 'CROSS_RUN_TOKEN_SUBSTITUTION'

def test_forged_valid_verdict_transition_blocked(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    red_token = broker_setup['red_token']
    run_id = 'run-forge-01'
    art_id = 'payload_forge'
    broker.register_artifact_state(run_id, art_id, ReleaseState.BLINDED)
    res = broker.transition_to_verified(
        run_id=run_id,
        artifact_id=art_id,
        verdict_or_assessment=Verdict.VALID,
        token=red_token,
    )
    assert res.success is False
    assert res.reason_code == 'UNAUTHORIZED_TRANSITION_CALLER'
    assert broker.get_artifact_release_state(run_id, art_id) == ReleaseState.BLINDED

def test_symlink_escape_rejection(broker_setup, tmp_path):
    broker: PolicyBroker = broker_setup['broker']
    storage: MultiTenantStorage = broker_setup['storage']
    red_vault = storage.get_vault(TenantId.RED)
    external_secret = tmp_path / 'external_secret.txt'
    external_secret.write_text('HOST_SECRET_TOKEN', encoding='utf-8')
    symlink_target = red_vault.vault_root / 'evil_symlink.txt'
    try:
        symlink_target.symlink_to(external_secret)
        created_real_symlink = True
    except (OSError, NotImplementedError):
        created_real_symlink = False
        symlink_target.write_text('dummy', encoding='utf-8')
    if created_real_symlink:
        with pytest.raises(PermissionError, match='Symlink traversal detected'):
            red_vault.read_artifact('evil_symlink.txt')
    else:
        with patch.object(Path, 'is_symlink', return_value=True):
            with pytest.raises(PermissionError, match='Symlink traversal detected'):
                red_vault.read_artifact('evil_symlink.txt')

def test_symlink_traversal_detection_guaranteed_across_all_platforms(broker_setup):
    storage: MultiTenantStorage = broker_setup['storage']
    red_vault = storage.get_vault(TenantId.RED)
    test_file = red_vault.vault_root / 'link_probe.txt'
    test_file.write_text('probe', encoding='utf-8')
    with patch.object(Path, 'is_symlink', return_value=True):
        with pytest.raises(PermissionError, match='Symlink traversal detected'):
            red_vault.read_artifact('link_probe.txt')

def test_caller_created_fake_valid_object_rejected(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    evaluator_token = broker_setup['evaluator_token']
    run_id = 'run-fake-obj-01'
    art_id = 'target_payload'
    broker.register_artifact_state(run_id, art_id, ReleaseState.BLINDED)
    fake_obj = type('FakeAssessment', (), {'verdict': Verdict.VALID, 'is_valid': True})()
    res = broker.transition_to_verified(run_id=run_id, artifact_id=art_id, evidence=fake_obj, token=evaluator_token)
    assert res.success is False
    assert res.reason_code == 'UNTRUSTED_CALLER_OBJECT_REJECTED'
    assert broker.get_artifact_release_state(run_id, art_id) == ReleaseState.REJECTED

def test_capsule_run_id_mismatch_rejected(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    evaluator_token = broker_setup['evaluator_token']
    signer = Ed25519Signer.generate()
    broker.trusted_evaluator_public_key = signer.public_key_hex
    capsule_a = create_valid_capsule_for_run('run-AAA', signer)
    res = broker.transition_to_verified(run_id='run-BBB', artifact_id='art-01', evidence=capsule_a, token=evaluator_token)
    assert res.success is False
    assert res.reason_code == 'RUN_ID_MISMATCH'
    assert broker.get_artifact_release_state('run-BBB', 'art-01') == ReleaseState.REJECTED

def test_capsule_manifest_digest_mismatch_rejected(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    evaluator_token = broker_setup['evaluator_token']
    signer = Ed25519Signer.generate()
    broker.trusted_evaluator_public_key = signer.public_key_hex
    run_id = 'run-mismatch-manifest'
    capsule = create_valid_capsule_for_run(run_id, signer)
    capsule.checkpoint.manifest_digest = 'sha256:' + '0' * 64
    res = broker.transition_to_verified(run_id=run_id, artifact_id='art-01', evidence=capsule, token=evaluator_token)
    assert res.success is False
    assert res.reason_code == 'MANIFEST_DIGEST_MISMATCH'
    assert broker.get_artifact_release_state(run_id, 'art-01') == ReleaseState.REJECTED

def test_capsule_untrusted_evaluator_key_rejected(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    evaluator_token = broker_setup['evaluator_token']
    trusted_signer = Ed25519Signer.generate()
    rogue_signer = Ed25519Signer.generate()
    broker.trusted_evaluator_public_key = trusted_signer.public_key_hex
    run_id = 'run-rogue-key'
    capsule = create_valid_capsule_for_run(run_id, rogue_signer)
    res = broker.transition_to_verified(run_id=run_id, artifact_id='art-01', evidence=capsule, token=evaluator_token)
    assert res.success is False
    assert res.reason_code == 'UNTRUSTED_EVALUATOR_KEY'
    assert broker.get_artifact_release_state(run_id, 'art-01') == ReleaseState.REJECTED

def test_path_replacement_race_toctou_defense(broker_setup, tmp_path):
    storage: MultiTenantStorage = broker_setup['storage']
    red_vault = storage.get_vault(TenantId.RED)
    test_file = red_vault.vault_root / 'race_test.txt'
    test_file.write_text('data', encoding='utf-8')
    with patch.object(Path, 'resolve', return_value=tmp_path / 'escaped_outside.txt'):
        with pytest.raises(PermissionError, match='Path (traversal attempt|replacement race detected)'):
            red_vault.read_artifact('race_test.txt')

def test_authorization_strictly_precedes_filesystem_access(broker_setup):
    broker: PolicyBroker = broker_setup['broker']
    storage: MultiTenantStorage = broker_setup['storage']
    red_vault = storage.get_vault(TenantId.RED)
    with patch.object(red_vault, 'read_artifact') as mock_read:
        res1 = broker.read_artifact('invalid-token', 'run-1', TenantId.RED, 'test.txt')
        assert res1.success is False
        assert mock_read.call_count == 0
        blue_token = broker_setup['blue_token']
        broker.register_artifact_state('run-1', 'unreleased_red', ReleaseState.BLINDED)
        res2 = broker.read_artifact(blue_token, 'run-1', TenantId.RED, 'unreleased_red.txt')
        assert res2.success is False
        assert mock_read.call_count == 0
