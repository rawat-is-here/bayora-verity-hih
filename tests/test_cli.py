import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from bayora.cli import main
from bayora.core.utils import create_sample_capsule
from bayora.ui.app import app

@pytest.fixture
def client():
    return TestClient(app)

def test_ui_dashboard_html_endpoint(client):
    res = client.get('/')
    assert res.status_code == 200
    assert 'text/html' in res.headers['content-type']
    assert 'Bayora V.E.R.I.T.Y' in res.text
    assert 'Validation of Evidence, Results, Isolation, Trust and Yield' in res.text

def test_ui_api_scenarios_endpoint(client):
    res = client.get('/api/scenarios')
    assert res.status_code == 200
    data = res.json()
    assert 'scenario_1_clean' in data
    assert 'scenario_2_contaminated' in data
    assert data['scenario_1_clean']['verdict'] == 'VALID'
    assert data['scenario_2_contaminated']['verdict'] == 'INVALIDATED'

def test_ui_api_benchmark_endpoint(client):
    res = client.get('/api/benchmark')
    assert res.status_code == 200
    data = res.json()
    assert data['total_scenarios'] == 9
    assert data['blindseal_false_acceptance'] == 0
    assert data['blindseal_tamper_detection_rate'] == '100.0%'

def test_cli_verify_command(tmp_path: Path, monkeypatch):
    capsule, _ = create_sample_capsule()
    file_path = tmp_path / 'cli_test_capsule.json'
    file_path.write_text(json.dumps(capsule.model_dump()), encoding='utf-8')
    monkeypatch.setattr('sys.argv', ['bayora', 'verify', '--file', str(file_path)])
    exit_code = main()
    assert exit_code == 0
