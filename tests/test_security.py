from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from bayora.broker.broker import PolicyBroker, ReleaseState
from bayora.core.crypto import Ed25519Signer
from bayora.ui.app import app, set_dashboard_broker
from bayora.vaults.vault import MultiTenantStorage, TenantId
from bayora.core.utils import create_sample_capsule

@pytest.fixture
def ui_security_setup(tmp_path: Path):
    storage = MultiTenantStorage(tmp_path / 'ui_vaults')
    broker = PolicyBroker(storage, broker_secret='test-ui-secret-9999')
    set_dashboard_broker(broker)
    red_token = broker.issue_token('red_hacker', TenantId.RED, ['red_attacker'])
    blue_token = broker.issue_token('blue_guard', TenantId.BLUE, ['blue_defender'])
    evaluator_token = broker.issue_token('eval_judge', TenantId.SYSTEM, ['evaluator'])
    client = TestClient(app)
    return {
        'client': client,
        'broker': broker,
        'storage': storage,
        'red_token': red_token,
        'blue_token': blue_token,
        'evaluator_token': evaluator_token,
    }

def test_ui_unauthenticated_artifact_access_rejected(ui_security_setup):
    client: TestClient = ui_security_setup['client']
    res = client.get('/api/vault/artifact', params={'run_id': 'run-ui-01', 'tenant': 'red', 'path': 'test.txt'})
    assert res.status_code == 401
    assert 'UNAUTHENTICATED' in res.json()['detail']

def test_ui_forged_token_artifact_access_rejected(ui_security_setup):
    client: TestClient = ui_security_setup['client']
    res = client.get(
        '/api/vault/artifact',
        params={'run_id': 'run-ui-01', 'tenant': 'red', 'path': 'test.txt'},
        headers={'X-Capability-Token': 'forged_actor:red:role:9999:sig_fake'},
    )
    assert res.status_code == 403
    assert 'ACCESS_DENIED' in res.json()['detail']

def test_ui_cross_tenant_red_cannot_read_blue_defense(ui_security_setup):
    client: TestClient = ui_security_setup['client']
    broker: PolicyBroker = ui_security_setup['broker']
    red_token = ui_security_setup['red_token']
    blue_token = ui_security_setup['blue_token']
    broker.write_artifact(blue_token, 'run-ui-02', TenantId.BLUE, 'defense_rules', 'SECRET_BLUE_LOGIC', 'rules.py')
    res = client.get(
        '/api/vault/artifact',
        params={'run_id': 'run-ui-02', 'tenant': 'blue', 'path': 'rules.py', 'artifact_id': 'defense_rules'},
        headers={'X-Capability-Token': red_token},
    )
    assert res.status_code == 403
    assert 'BLUE_DEFENSE_CONFIDENTIAL' in res.json()['detail']

def test_ui_blue_cannot_read_unreleased_red_payload(ui_security_setup):
    client: TestClient = ui_security_setup['client']
    broker: PolicyBroker = ui_security_setup['broker']
    red_token = ui_security_setup['red_token']
    blue_token = ui_security_setup['blue_token']
    run_id = 'run-ui-03'
    art_id = 'zero_day_payload'
    broker.write_artifact(red_token, run_id, TenantId.RED, art_id, 'TOP_SECRET_PROMPT_INJECTION', 'exploit.txt')
    res = client.get(
        '/api/vault/artifact',
        params={'run_id': run_id, 'tenant': 'red', 'path': 'exploit.txt', 'artifact_id': art_id},
        headers={'X-Capability-Token': blue_token},
    )
    assert res.status_code == 403
    assert 'RED_PAYLOAD_UNRELEASED' in res.json()['detail']
    assert 'TOP_SECRET_PROMPT_INJECTION' not in res.text

def test_ui_path_traversal_via_api_blocked(ui_security_setup):
    client: TestClient = ui_security_setup['client']
    red_token = ui_security_setup['red_token']
    res = client.get(
        '/api/vault/artifact',
        params={'run_id': 'run-ui-04', 'tenant': 'red', 'path': '../../system/secret.txt'},
        headers={'X-Capability-Token': red_token},
    )
    assert res.status_code == 403
    assert 'PATH_TRAVERSAL_BLOCKED' in res.json()['detail']

def test_ui_release_request_without_evaluator_token_rejected(ui_security_setup):
    client: TestClient = ui_security_setup['client']
    broker: PolicyBroker = ui_security_setup['broker']
    red_token = ui_security_setup['red_token']
    run_id = 'run-ui-05'
    art_id = 'payload_release_test'
    broker.register_artifact_state(run_id, art_id, ReleaseState.BLINDED)
    res = client.post('/api/release/request', json={'token': red_token, 'run_id': run_id, 'artifact_id': art_id})
    assert res.status_code == 403
    assert 'RELEASE_DENIED' in res.json()['detail']

def test_ui_release_request_on_invalidated_run_permanently_rejected(ui_security_setup):
    client: TestClient = ui_security_setup['client']
    broker: PolicyBroker = ui_security_setup['broker']
    evaluator_token = ui_security_setup['evaluator_token']
    run_id = 'run-ui-06'
    art_id = 'poisoned_test'
    broker.register_artifact_state(run_id, art_id, ReleaseState.REJECTED)
    res = client.post('/api/release/request', json={'token': evaluator_token, 'run_id': run_id, 'artifact_id': art_id})
    assert res.status_code == 403
    assert 'INVALIDATED_RUN_RELEASE_FORBIDDEN' in res.json()['detail']

def test_ui_authorized_release_and_subsequent_read(ui_security_setup):
    client: TestClient = ui_security_setup['client']
    broker: PolicyBroker = ui_security_setup['broker']
    evaluator_token = ui_security_setup['evaluator_token']
    red_token = ui_security_setup['red_token']
    blue_token = ui_security_setup['blue_token']
    run_id = 'run-ui-07'
    art_id = 'legitimate_payload'
    secret_text = 'ADVERSARIAL_BENCHMARK_PROMPT_ALPHA'
    broker.write_artifact(red_token, run_id, TenantId.RED, art_id, secret_text, 'alpha.txt')
    capsule, signer = create_sample_capsule(run_id=run_id)
    broker.trusted_evaluator_public_key = signer.public_key_hex
    broker.transition_to_verified(run_id, art_id, evidence=capsule, token=evaluator_token)
    rel_res = client.post('/api/release/request', json={'token': evaluator_token, 'run_id': run_id, 'artifact_id': art_id})
    assert rel_res.status_code == 200
    assert rel_res.json()['release_state'] == 'RELEASED'
    read_res = client.get(
        '/api/vault/artifact',
        params={'run_id': run_id, 'tenant': 'red', 'path': 'alpha.txt', 'artifact_id': art_id},
        headers={'X-Capability-Token': blue_token},
    )
    assert read_res.status_code == 200
    assert read_res.json()['content'] == secret_text

def test_ui_api_scenarios_does_not_expose_raw_secrets(ui_security_setup):
    client: TestClient = ui_security_setup['client']
    res = client.get('/api/scenarios')
    assert res.status_code == 200
    text = res.text
    assert 'DROP ALL DEFENSES' not in text
    assert 'IGNORE ALL PREVIOUS INSTRUCTIONS' not in text
