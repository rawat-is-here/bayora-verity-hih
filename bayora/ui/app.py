from __future__ import annotations
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from bayora.benchmark.compare import BenchmarkComparator
from bayora.broker.broker import PolicyBroker, ReleaseState
from bayora.core.models import EvidenceCapsule
from bayora.demo.scenarios import run_all_scenarios
from bayora.vaults.vault import MultiTenantStorage, TenantId
from bayora.verifier.verify import verify_capsule

app = FastAPI(title='Bayora V.E.R.I.T.Y Operator Console', version='0.2.0')
_default_storage_dir = Path.home() / '.bayora' / 'dashboard_storage'
_default_storage_dir.mkdir(parents=True, exist_ok=True)
_default_storage = MultiTenantStorage(_default_storage_dir)
_dashboard_broker = PolicyBroker(_default_storage, broker_secret='bayora-ui-broker-secret-2026')

def get_broker() -> PolicyBroker:
    return _dashboard_broker

def set_dashboard_broker(broker: PolicyBroker) -> None:
    global _dashboard_broker
    _dashboard_broker = broker

class ReleaseRequestModel(BaseModel):
    token: str
    run_id: str
    artifact_id: str

class VerifyRequestModel(BaseModel):
    capsule: Dict[str, Any]
    trusted_public_key: Optional[str] = None

_CACHED_SCENARIOS: Dict[str, Any] = {}
_CACHED_BENCHMARK: Dict[str, Any] = {}

def get_or_run_scenarios(force_refresh: bool=False) -> Dict[str, Any]:
    global _CACHED_SCENARIOS
    if not _CACHED_SCENARIOS or force_refresh:
        with TemporaryDirectory() as tmp_dir:
            raw_res = run_all_scenarios(tmp_dir)
            _CACHED_SCENARIOS = {}
            for k, v in raw_res.items():
                _CACHED_SCENARIOS[k] = {
                    'run_id': v.run_id,
                    'verdict': v.verdict.value,
                    'is_valid': v.is_valid,
                    'reason_code': v.reason_code,
                    'diagnostic_message': v.diagnostic_message,
                    'finding_outcome': v.finding_outcome.value,
                    'disclosure_permitted': v.disclosure_permitted,
                    'final_release_state': v.final_release_state.value,
                    'total_tests': v.total_tests_executed,
                    'manifest_digest': v.capsule.manifest.compute_digest(),
                    'checkpoint_sig': v.capsule.checkpoint.signature_hex,
                    'signer_key': v.capsule.checkpoint.signer_public_key_hex,
                    'events_count': len(v.capsule.events),
                    'capsule': v.capsule.model_dump(),
                    'events': [
                        {
                            'seq': e.sequence_number,
                            'type': e.event_type.value,
                            'subject': e.subject_id,
                            'hash': e.event_hash,
                            'prev_hash': e.previous_event_hash,
                            'payload_digest': e.payload_digest,
                            'metadata': e.metadata,
                        }
                        for e in v.capsule.events
                    ],
                }
    return _CACHED_SCENARIOS

def get_or_run_benchmark(force_refresh: bool=False) -> Dict[str, Any]:
    global _CACHED_BENCHMARK
    if not _CACHED_BENCHMARK or force_refresh:
        with TemporaryDirectory() as tmp_dir:
            comp = BenchmarkComparator(tmp_dir)
            summary = comp.run_benchmark()
            _CACHED_BENCHMARK = {
                'total_scenarios': summary.total_scenarios_evaluated,
                'naive_false_acceptance': summary.naive_false_acceptance_count,
                'blindseal_false_acceptance': summary.blindseal_false_acceptance_count,
                'naive_tamper_detection_rate': f'{summary.naive_tamper_detection_rate:.1f}%',
                'blindseal_tamper_detection_rate': f'{summary.blindseal_tamper_detection_rate:.1f}%',
                'median_overhead_ms': f'{summary.median_overhead_ms}ms',
                'p95_overhead_ms': f'{summary.p95_overhead_ms}ms',
                'max_overhead_ms': f'{summary.max_overhead_ms}ms',
                'scope_note': summary.methodology_note,
                'comparisons': [
                    {
                        'scenario_id': c.scenario_id,
                        'desc': c.description,
                        'naive_verdict': c.naive_verdict,
                        'naive_accepted': c.naive_accepted_as_valid,
                        'blindseal_verdict': c.blindseal_verdict,
                        'blindseal_valid': c.blindseal_validity,
                        'blindseal_reason': c.blindseal_reason,
                        'tamper_detected': c.tamper_detected,
                    }
                    for c in summary.comparisons
                ],
            }
    return _CACHED_BENCHMARK

@app.get('/api/scenarios')
def api_scenarios() -> JSONResponse:
    return JSONResponse(get_or_run_scenarios())

@app.get('/api/scenarios/{scenario_id}/capsule')
def api_scenario_capsule(scenario_id: str) -> JSONResponse:
    scenarios = get_or_run_scenarios()
    if scenario_id not in scenarios or 'capsule' not in scenarios[scenario_id]:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found")
    return JSONResponse(scenarios[scenario_id]['capsule'])

@app.get('/api/benchmark')
def api_benchmark() -> JSONResponse:
    return JSONResponse(get_or_run_benchmark())

@app.post('/api/verify/capsule')
def api_verify_capsule(payload: VerifyRequestModel) -> JSONResponse:
    try:
        capsule = EvidenceCapsule.model_validate(payload.capsule)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'Invalid capsule format: {str(e)}')
    res = verify_capsule(capsule, trusted_evaluator_public_key=payload.trusted_public_key)
    return JSONResponse({
        'is_valid': res.is_valid,
        'verdict': res.verdict.value,
        'reason_code': res.reason_code,
        'diagnostic_message': res.diagnostic_message,
        'event_count_checked': res.event_count_checked,
    })

@app.get('/api/vault/artifact')
def api_read_vault_artifact(
    run_id: str = Query(...),
    tenant: str = Query(...),
    path: str = Query(...),
    artifact_id: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
    x_capability_token: Optional[str] = Header(None, alias='X-Capability-Token'),
) -> JSONResponse:
    effective_token = x_capability_token or token
    if not effective_token:
        raise HTTPException(status_code=401, detail='UNAUTHENTICATED: Valid capability token required')
    try:
        t_id = TenantId(tenant.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid tenant: '{tenant}'")
    broker = get_broker()
    resp = broker.read_artifact(token=effective_token, run_id=run_id, target_tenant=t_id, relative_path=path, artifact_id=artifact_id)
    if not resp.success:
        raise HTTPException(status_code=403, detail=f'ACCESS_DENIED: {resp.reason_code}')
    return JSONResponse({
        'success': True,
        'artifact_id': artifact_id or path,
        'digest': resp.digest,
        'content': resp.content.decode('utf-8', errors='replace') if resp.content else None,
    })

@app.post('/api/release/request')
def api_request_artifact_release(payload: ReleaseRequestModel) -> JSONResponse:
    if not payload.token:
        raise HTTPException(status_code=401, detail='UNAUTHENTICATED: Capability token required')
    broker = get_broker()
    resp = broker.request_release(token=payload.token, run_id=payload.run_id, artifact_id=payload.artifact_id)
    if not resp.success:
        raise HTTPException(status_code=403, detail=f'RELEASE_DENIED: {resp.reason_code}')
    return JSONResponse({
        'success': True,
        'reason_code': resp.reason_code,
        'release_state': broker.get_artifact_release_state(payload.run_id, payload.artifact_id).value,
    })

@app.get('/', response_class=HTMLResponse)
def dashboard_html() -> HTMLResponse:
    html = """<!DOCTYPE html>
<html lang="en" class="h-full bg-black text-slate-100 dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bayora V.E.R.I.T.Y - Validation of Evidence, Results, Isolation, Trust and Yield</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          fontFamily: {
            mono: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
            sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
          },
          colors: {
            brandRed: '#ff1138',
            brandRedDark: '#99001a',
            brandRedGlow: 'rgba(255, 17, 56, 0.45)',
            statusValid: '#00e599',
            statusInvalid: '#ff173d',
            statusBlinded: '#f59e0b',
            statusNeutral: '#64748b',
            obsidianBg: '#050204',
            panelBg: '#0a0408',
            cardBg: '#0f050c',
            cardHover: '#160812',
          }
        }
      }
    }
  </script>
  <style>
    :root {
      --bg-page: #030103;
      --bg-panel: #090307;
      --bg-card: #0f050c;
      --bg-card-hover: #160812;
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-red: rgba(255, 20, 50, 0.22);
      --border-red-bright: rgba(255, 25, 55, 0.55);
      --red-primary: #ff1138;
      --red-hover: #ff2e52;
      --emerald: #00e599;
      --cyan: #00d2ff;
      --mono: 'Inter', system-ui, -apple-system, sans-serif;
      --sans: 'Inter', system-ui, -apple-system, sans-serif;
    }
    body {
      background: #000000;
      color: #f1f5f9;
      font-family: var(--sans);
      overflow-x: hidden;
      margin: 0;
      padding: 0;
      -webkit-font-smoothing: antialiased;
      cursor: default;
    }
    ::selection {
      background: #ff1138;
      color: #ffffff;
    }
    .brand-header {
      background: rgba(4, 2, 4, 0.88);
      border-bottom: 1px solid var(--border-red);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
    }
    .hero-container {
      position: relative;
      background: transparent;
      overflow: hidden;
    }
    #crimsonVortex {
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      pointer-events: none;
      z-index: 0;
    }
    main, .tab-view {
      position: relative;
      z-index: 1;
    }
    .hero-glow-overlay {
      position: absolute;
      top: 0;
      right: 0;
      width: 65%;
      height: 100%;
      background: radial-gradient(ellipse at 78% 28%, rgba(255, 17, 56, 0.38) 0%, rgba(160, 0, 25, 0.16) 45%, rgba(0, 0, 0, 0.88) 75%, transparent 100%);
      pointer-events: none;
      z-index: 2;
    }
    .hud-vector-overlay {
      position: absolute;
      top: 0;
      right: 0;
      width: 55%;
      height: 100%;
      pointer-events: none;
      z-index: 3;
    }
    @media (max-width: 1024px) {
      .hud-vector-overlay { display: none; }
      .hero-glow-overlay { width: 100%; }
    }
    .btn-brand-primary {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      height: 44px;
      padding: 0 24px;
      background: #ff1138;
      color: #ffffff;
      border: 1px solid #ff1138;
      font-size: 14px;
      font-weight: 600;
      border-radius: 9999px;
      box-shadow: 0 0 22px rgba(255, 17, 56, 0.4);
      transition: all 0.15s ease-out;
      text-decoration: none;
      cursor: pointer;
    }
    .btn-brand-primary:hover {
      background: #ff2e52;
      box-shadow: 0 0 32px rgba(255, 17, 56, 0.65);
      transform: translateY(-1px);
    }
    .btn-brand-primary:focus-visible {
      outline: 2px solid #ffffff;
      outline-offset: 2px;
    }
    .btn-brand-secondary {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      height: 44px;
      padding: 0 22px;
      background: rgba(15, 5, 11, 0.85);
      color: #ffffff;
      border: 1px solid var(--border-red);
      font-size: 14px;
      font-weight: 500;
      border-radius: 9999px;
      transition: all 0.15s ease-out;
      cursor: pointer;
    }
    .btn-brand-secondary:hover {
      border-color: #ff1138;
      background: rgba(255, 17, 56, 0.12);
      box-shadow: 0 0 20px rgba(255, 17, 56, 0.25);
    }
    .btn-brand-secondary:focus-visible {
      outline: 2px solid #ff1138;
      outline-offset: 2px;
    }
    .btn-brand-ghost {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      color: #cbd5e1;
      font-size: 14px;
      font-weight: 500;
      transition: color 0.15s ease;
      background: none;
      border: none;
      cursor: pointer;
    }
    .btn-brand-ghost:hover {
      color: #ff1138;
    }
    .precision-frame {
      position: relative;
      background: var(--bg-card);
      border: 1px solid var(--border-red);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.7);
      padding: 32px 28px;
      border-radius: 8px;
      transition: border-color 0.2s, box-shadow 0.2s, background-color 0.2s;
    }
    .precision-frame:hover {
      border-color: var(--border-red-bright);
      box-shadow: 0 10px 40px rgba(255, 17, 56, 0.16);
      background: var(--bg-card-hover);
    }
    .precision-frame::before {
      content: '+';
      position: absolute;
      top: -10px;
      left: -10px;
      width: 20px;
      height: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ff1138;
      font-family: var(--mono);
      font-size: 14px;
      font-weight: bold;
    }
    .precision-frame::after {
      content: '+';
      position: absolute;
      bottom: -10px;
      right: -10px;
      width: 20px;
      height: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ff1138;
      font-family: var(--mono);
      font-size: 14px;
      font-weight: bold;
    }
    .wf-icon-box {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 38px;
      height: 38px;
      border-radius: 6px;
      background: rgba(255, 17, 56, 0.12);
      border: 1px solid rgba(255, 17, 56, 0.35);
      color: #ff1138;
      flex-shrink: 0;
      transition: all 0.2s;
    }
    .wf-row:hover .wf-icon-box {
      background: #ff1138;
      color: #000000;
      box-shadow: 0 0 20px rgba(255, 17, 56, 0.6);
    }
    .architecture-ribbon {
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 14px;
      max-width: 1280px;
      margin: 0 auto;
    }
    @media (max-width: 980px) {
      .architecture-ribbon { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 640px) {
      .architecture-ribbon { grid-template-columns: 1fr; }
    }
    .arch-tile {
      background: var(--bg-card);
      border: 1px solid var(--border-red);
      display: flex;
      flex-direction: column;
      align-items: center;
      text-align: center;
      padding: 24px 16px;
      border-radius: 8px;
      transition: all 0.2s ease;
      cursor: pointer;
    }
    .arch-tile:hover {
      border-color: #ff1138;
      transform: translateY(-2px);
      box-shadow: 0 6px 24px rgba(255, 17, 56, 0.22);
    }
    .ticker-bar {
      overflow: hidden;
      white-space: nowrap;
      position: relative;
    }
    .ticker-track {
      display: flex;
      gap: 28px;
      width: max-content;
      animation: 36s linear infinite ticker-scroll;
    }
    @keyframes ticker-scroll {
      to { transform: translateX(calc(-50% - 14px)); }
    }
    .tab-view {
      display: none;
      animation: fadeIn 0.2s ease-in-out;
    }
    .tab-view.active {
      display: block;
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(4px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .nav-tab-btn {
      position: relative;
      transition: color 0.15s ease;
      background: none;
      border: none;
      cursor: pointer;
    }
    .nav-tab-btn.active {
      color: #ff1138 !important;
    }
    .nav-tab-btn.active::after {
      content: '';
      position: absolute;
      bottom: -22px;
      left: 0;
      right: 0;
      height: 2px;
      background: #ff1138;
      box-shadow: 0 0 10px #ff1138;
      border-radius: 2px;
    }
    .spec-item {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 16px;
      border-radius: 6px;
      background: rgba(15, 5, 11, 0.7);
      border: 1px solid rgba(255, 20, 50, 0.18);
      font-family: var(--mono);
      font-size: 11px;
      color: #cbd5e1;
    }
  </style>
</head>
<body class="min-h-full flex flex-col relative bg-black">

  <canvas id="crimsonVortex"></canvas>

  <header class="brand-header sticky top-0 z-50">
    <div class="w-full h-20 flex items-center justify-between px-6 lg:px-10">
      
      <div class="flex items-center space-x-6">
        <button onclick="switchView('overview')" class="flex items-center space-x-3 text-left focus:outline-none">
          <svg class="w-8 h-8 text-[#ff1138]" viewBox="0 0 32 32" fill="none">
            <path d="M16 2L6 8L16 14L26 8L16 2Z" fill="#ff1138" />
            <path d="M6 12L16 18L26 12" stroke="#ff1138" stroke-width="2" stroke-linecap="round" />
            <path d="M6 18L16 24L26 18" stroke="#ff1138" stroke-width="2" stroke-linecap="round" />
            <path d="M6 24L16 30L26 24" stroke="#ff1138" stroke-width="2" stroke-linecap="round" />
          </svg>
          <div class="flex flex-col">
            <span class="text-xl font-extrabold tracking-wider uppercase text-white font-sans">Bayora V.E.R.I.T.Y</span>
            <span class="text-[9px] text-[#ff1138] font-mono tracking-wider -mt-1 font-bold uppercase">Validation of Evidence, Results, Isolation, Trust and Yield</span>
          </div>
        </button>
      </div>

      <nav class="hidden md:flex items-center space-x-8 text-xs font-semibold font-mono tracking-wider text-slate-300 uppercase">
        <button onclick="switchView('overview')" id="nav-overview" class="nav-tab-btn active hover:text-[#ff1138]">Overview</button>
        <button onclick="switchView('evaluator')" id="nav-evaluator" class="nav-tab-btn hover:text-[#ff1138]">Live Evaluator</button>
        <button onclick="switchView('ledger')" id="nav-ledger" class="nav-tab-btn hover:text-[#ff1138]">Evidence Ledger</button>
        <button onclick="switchView('benchmark')" id="nav-benchmark" class="nav-tab-btn hover:text-[#ff1138]">Benchmark</button>
        <button onclick="switchView('architecture')" id="nav-architecture" class="nav-tab-btn hover:text-[#ff1138]">Architecture</button>
      </nav>

      <div class="flex items-center space-x-4">
        <button onclick="switchView('evaluator')" class="btn-brand-primary text-xs !h-9 !px-4">
          Run Scenario Audit
        </button>
      </div>

    </div>
  </header>

  <main class="flex-1">

    <div id="view-overview" class="tab-view active">

      <section class="hero-container pt-20 pb-24 border-b border-[rgba(255,20,50,0.2)]">
        <div class="hero-glow-overlay"></div>

        <svg class="hud-vector-overlay" viewBox="0 0 700 600" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="230" cy="180" r="54" stroke="rgba(255,255,255,0.4)" stroke-width="1.5" />
          <circle cx="230" cy="180" r="4" fill="#ff1138" />
          <circle cx="200" cy="420" r="68" stroke="rgba(255,255,255,0.4)" stroke-width="1.5" />
          <circle cx="200" cy="420" r="4" fill="#ff1138" />
          <rect x="420" y="230" width="150" height="150" stroke="rgba(255,255,255,0.6)" stroke-width="1.5" />
          <polygon points="495,230 570,305 495,380 420,305" stroke="rgba(255,255,255,0.85)" stroke-width="1.5" />
          <line x1="230" y1="180" x2="495" y2="305" stroke="rgba(255,255,255,0.35)" stroke-width="1.2" stroke-dasharray="5 5" />
          <line x1="200" y1="420" x2="495" y2="305" stroke="rgba(255,255,255,0.35)" stroke-width="1.2" stroke-dasharray="5 5" />
          <line x1="495" y1="230" x2="495" y2="90" stroke="rgba(255,255,255,0.35)" stroke-width="1.2" stroke-dasharray="5 5" />
          <line x1="570" y1="305" x2="680" y2="305" stroke="rgba(255,255,255,0.35)" stroke-width="1.2" stroke-dasharray="5 5" />
          <line x1="495" y1="380" x2="495" y2="510" stroke="rgba(255,255,255,0.35)" stroke-width="1.2" stroke-dasharray="5 5" />
          <line x1="420" y1="305" x2="310" y2="305" stroke="rgba(255,255,255,0.35)" stroke-width="1.2" stroke-dasharray="5 5" />
          <circle cx="495" cy="305" r="5" fill="#ffffff" />
          <circle cx="495" cy="305" r="16" stroke="rgba(255,17,56,0.8)" stroke-width="1.5" stroke-dasharray="3 3" />
          <text x="430" y="215" fill="rgba(255,255,255,0.8)" font-family="Inter, sans-serif" font-size="10" letter-spacing="0.5">PRE-RUN LOCK: RFC 8785</text>
          <text x="240" y="150" fill="#ff1138" font-family="Inter, sans-serif" font-size="10" letter-spacing="0.5">LEAK CHECK: MONITORED</text>
          <text x="160" y="490" fill="#00e599" font-family="Inter, sans-serif" font-size="10" letter-spacing="0.5">SIGNED RECORD: ED25519</text>
        </svg>

        <div class="max-w-[1280px] mx-auto px-6 relative z-10">
          <div class="max-w-2xl">
            <div class="inline-flex items-center space-x-2 px-3 py-1 rounded bg-[#ff1138]/15 border border-[#ff1138]/40 text-[#ff1138] text-xs font-mono font-bold uppercase tracking-widest mb-6">
              <span class="w-2 h-2 rounded-full bg-[#ff1138] animate-pulse"></span>
              <span>BAYORA V.E.R.I.T.Y</span>
            </div>

            <h1 class="text-5xl sm:text-6xl lg:text-7xl font-extrabold font-sans tracking-tight text-white leading-[1.04]">
              Clear Proof for<br>
              AI Safety<br>
              <span class="text-transparent bg-clip-text bg-gradient-to-r from-white via-red-100 to-red-500">Evaluations</span>
            </h1>

            <div class="mt-6 space-y-4">
              <p class="text-base sm:text-lg text-slate-300 leading-relaxed font-sans">
                <strong class="text-white font-semibold">Bayora V.E.R.I.T.Y</strong> verifies whether your testing environment stayed fair, clean, and uncorrupted while evaluating AI models.
              </p>
              <p class="text-xs sm:text-sm text-slate-400 leading-relaxed font-sans">
                We track memory leaks between test runs, verify server health, seal audit records with digital signatures, and hold test attacks in private storage until results are confirmed.
              </p>
            </div>

            <div class="mt-8 flex flex-wrap items-center gap-4">
              <button onclick="switchView('evaluator')" class="btn-brand-primary">
                Launch Live Evaluator
              </button>
              <button onclick="switchView('ledger')" class="btn-brand-ghost">
                <span>Explore Evidence Ledger</span>
                <span class="text-lg">→</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      <section class="py-20 border-b border-[rgba(255,20,50,0.18)] bg-[#050204]/70 backdrop-blur-sm">
        <div class="max-w-[1280px] mx-auto px-6">
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            
            <div class="precision-frame">
              <h2 class="text-2xl font-bold font-sans text-white mb-8 tracking-tight">Why Evaluation Integrity, Why Now?</h2>
              
              <div class="space-y-6">
                <div class="wf-row flex gap-4 items-start">
                  <span class="wf-icon-box">
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                  </span>
                  <div>
                    <div class="text-base font-bold text-white font-sans">Memory Bleeds Across Tests</div>
                    <p class="text-xs text-slate-400 mt-1 leading-relaxed">Leftover conversation history from earlier tests can cause a model to remember answers and bypass safety filters without any real exploit.</p>
                  </div>
                </div>

                <div class="wf-row flex gap-4 items-start">
                  <span class="wf-icon-box">
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="m9 12 2 2 4-4"/></svg>
                  </span>
                  <div>
                    <div class="text-base font-bold text-white font-sans">Server Freezes Look Like Passes</div>
                    <p class="text-xs text-slate-400 mt-1 leading-relaxed">If a safety filter times out or the computer runs out of memory, typical test runners mark it as PASS simply because no reply came back.</p>
                  </div>
                </div>

                <div class="wf-row flex gap-4 items-start">
                  <span class="wf-icon-box">
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                  </span>
                  <div>
                    <div class="text-base font-bold text-white font-sans">Test Attacks Leak Too Early</div>
                    <p class="text-xs text-slate-400 mt-1 leading-relaxed">Storing attack prompts in shared folders lets defense teams see them before tests run, invalidating the evaluation results.</p>
                  </div>
                </div>

                <div class="wf-row flex gap-4 items-start">
                  <span class="wf-icon-box">
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="m14 2 6 6"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                  </span>
                  <div>
                    <div class="text-base font-bold text-white font-sans">Log Files Can Be Quietly Edited</div>
                    <p class="text-xs text-slate-400 mt-1 leading-relaxed">Plain text log files can easily be changed after a run to erase failed tests and fake high scores.</p>
                  </div>
                </div>
              </div>
            </div>

            <div class="precision-frame">
              <h2 class="text-2xl font-bold font-sans text-white mb-8 tracking-tight">How Bayora Fixes This</h2>

              <div class="space-y-6">
                <div class="wf-row flex gap-4 items-start">
                  <span class="wf-icon-box">
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                  </span>
                  <div>
                    <div class="text-base font-bold text-white font-sans">Clear 4-State Health Check</div>
                    <p class="text-xs text-slate-400 mt-1 leading-relaxed">Clearly marks tests VALID, INVALIDATED, INCONCLUSIVE, or NOT EVALUATED so computer issues are never confused with model scores.</p>
                  </div>
                </div>

                <div class="wf-row flex gap-4 items-start">
                  <span class="wf-icon-box">
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/></svg>
                  </span>
                  <div>
                    <div class="text-base font-bold text-white font-sans">Hidden Canary Checks</div>
                    <p class="text-xs text-slate-400 mt-1 leading-relaxed">Injects unique hidden marker tokens into prompts to instantly catch if a model is remembering data across test runs.</p>
                  </div>
                </div>

                <div class="wf-row flex gap-4 items-start">
                  <span class="wf-icon-box">
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                  </span>
                  <div>
                    <div class="text-base font-bold text-white font-sans">Protected Test Privacy</div>
                    <p class="text-xs text-slate-400 mt-1 leading-relaxed">Keeps test attack prompts locked away until the run is cryptographically verified as clean and fair.</p>
                  </div>
                </div>

                <div class="wf-row flex gap-4 items-start">
                  <span class="wf-icon-box">
                    <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>
                  </span>
                  <div>
                    <div class="text-base font-bold text-white font-sans">Tamper-Proof Digital Signatures</div>
                    <p class="text-xs text-slate-400 mt-1 leading-relaxed">Exports audit files with digital signatures that any third party can verify without needing our server.</p>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </div>
      </section>

      <section class="py-20 text-center">
        <div class="max-w-[1280px] mx-auto px-6 space-y-6">
          <h2 class="text-3xl font-extrabold font-sans text-white">Ready to verify evaluation integrity?</h2>
          <p class="text-sm text-slate-400 max-w-lg mx-auto font-sans">Launch the live evaluator to audit live scenarios, inspect cryptographic ledgers, or compare benchmarks.</p>
          <div class="flex justify-center gap-4 pt-2">
            <button onclick="switchView('evaluator')" class="btn-brand-primary">Launch Live Evaluator</button>
            <button onclick="switchView('ledger')" class="btn-brand-secondary">Explore Evidence Ledger</button>
          </div>
        </div>
      </section>

    </div>

    <div id="view-evaluator" class="tab-view">
      <div class="max-w-[1280px] mx-auto px-6 py-12 space-y-8">
        
        <div class="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-4 border-b border-[rgba(255,20,50,0.18)]">
          <div>
            <h1 class="text-3xl font-extrabold font-sans text-white tracking-tight">LIVE VALIDATOR</h1>
            <p class="text-xs text-slate-400 mt-1">Select a test scenario to inspect its environment health and report release status.</p>
          </div>

          <div class="flex items-center space-x-3 font-sans text-xs">
            <button onclick="refreshAllData()" class="btn-brand-secondary !h-9 text-xs !px-4">Refresh Data</button>
            <button onclick="switchView('ledger')" class="btn-brand-secondary !h-9 text-xs !px-4">View Records →</button>
          </div>
        </div>

        <div class="precision-frame !p-5">
          <div class="text-xs font-sans font-semibold text-slate-300 mb-3">Evaluation Scenarios</div>
          <div id="scenario-selector-grid" class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3">
          </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
          
          <div class="precision-frame">
            <div class="flex items-center justify-between pb-4 border-b border-white/10 mb-6">
              <h2 class="text-xl font-bold font-sans text-white tracking-tight">Environment Health</h2>
              <span id="badge-verdict" class="px-3 py-1 text-xs font-semibold rounded bg-white/10 text-white border border-white/15">--</span>
            </div>

            <div class="space-y-5 text-sm font-sans">
              <div class="flex justify-between items-center py-2 border-b border-white/5">
                <span class="text-slate-400">Run ID</span>
                <span id="text-run-id" class="text-white font-medium select-all">--</span>
              </div>
              <div class="flex justify-between items-center py-2 border-b border-white/5">
                <span class="text-slate-400">Reason Code</span>
                <span id="text-reason-code" class="text-white font-medium">--</span>
              </div>
              <div class="flex justify-between items-center py-2 border-b border-white/5">
                <span class="text-slate-400">Model Safety Finding</span>
                <span id="text-finding-outcome" class="text-white font-medium">--</span>
              </div>
              <div class="pt-2">
                <span class="text-slate-400 block mb-2 font-medium">Diagnostic Details</span>
                <div id="text-diagnostic" class="p-4 bg-white/[0.03] rounded-md border border-white/10 text-slate-200 text-xs leading-relaxed">--</div>
              </div>
            </div>
          </div>

          <div class="precision-frame">
            <div class="flex items-center justify-between pb-4 border-b border-white/10 mb-6">
              <h2 class="text-xl font-bold font-sans text-white tracking-tight">Attack Prompt Privacy</h2>
              <span id="badge-release-state" class="px-3 py-1 text-xs font-semibold rounded bg-white/10 text-white border border-white/15">--</span>
            </div>

            <p class="text-sm text-slate-300 leading-relaxed font-sans mb-6">
              Test prompts remain private until the test environment is verified as clean and uncorrupted. Any session leak or missing monitor keeps them locked.
            </p>

            <div class="flex flex-wrap gap-3 pt-2">
              <button onclick="auditCapsuleWithVerifier()" class="btn-brand-primary text-xs !h-9 !px-4">
                Audit with Independent Verifier
              </button>
              <button onclick="exportCapsuleJson()" class="btn-brand-secondary text-xs !h-9 !px-4">
                Export Capsule JSON
              </button>
            </div>

            <div id="verifier-output-box" class="hidden mt-4 p-4 rounded-md border border-white/10 text-xs font-sans"></div>
          </div>

        </div>

      </div>
    </div>

    <div id="view-ledger" class="tab-view">
      <div class="max-w-[1280px] mx-auto px-6 py-12 space-y-8">
        
        <div class="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-4 border-b border-[rgba(255,20,50,0.18)]">
          <div>
            <div class="inline-flex items-center space-x-2 px-3 py-0.5 rounded bg-[#00d2ff]/15 text-[#00d2ff] font-mono text-xs font-bold uppercase mb-2">
              <span>MERKLE EVIDENCE LEDGER</span>
            </div>
            <h1 class="text-3xl font-extrabold font-sans text-white tracking-tight">RFC 8785 Hash-Chained Audit Trail</h1>
            <p class="text-xs text-slate-400 mt-1">Every evaluation lifecycle event is hashed sequentially and anchored by an Ed25519 signature checkpoint.</p>
          </div>

          <div class="flex items-center space-x-3 font-mono text-xs">
            <input id="ledger-search" oninput="filterLedgerEvents()" type="text" placeholder="Filter ledger events..." class="px-3 py-1.5 text-xs font-mono bg-[#0f0408] border border-[rgba(255,20,50,0.25)] rounded text-slate-200 placeholder-slate-500 focus:outline-none focus:border-[#ff1138]">
            <button onclick="switchView('evaluator')" class="btn-brand-secondary !h-9 text-xs !px-4">← Back to Evaluator</button>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
          <div class="precision-frame !p-4 space-y-1">
            <div class="flex justify-between text-[11px] text-slate-400">
              <span>Manifest Digest:</span>
              <button onclick="copyToClipboard('text-manifest-digest')" class="text-slate-500 hover:text-[#ff1138]">copy</button>
            </div>
            <div id="text-manifest-digest" class="truncate text-slate-300 text-[11px] select-all font-bold">--</div>
          </div>

          <div class="precision-frame !p-4 space-y-1">
            <div class="flex justify-between text-[11px] text-slate-400">
              <span>Ed25519 Checkpoint Sig:</span>
              <button onclick="copyToClipboard('text-checkpoint-sig')" class="text-slate-500 hover:text-[#ff1138]">copy</button>
            </div>
            <div id="text-checkpoint-sig" class="truncate text-slate-300 text-[11px] select-all font-bold">--</div>
          </div>

          <div class="precision-frame !p-4 space-y-1">
            <div class="flex justify-between text-[11px] text-slate-400">
              <span>Evaluator Public Key:</span>
              <button onclick="copyToClipboard('text-signer-key')" class="text-slate-500 hover:text-[#ff1138]">copy</button>
            </div>
            <div id="text-signer-key" class="truncate text-slate-300 text-[11px] select-all font-bold">--</div>
          </div>
        </div>

        <div class="precision-frame !p-0 overflow-hidden">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs font-mono">
              <thead class="text-slate-400 border-b border-[rgba(255,20,50,0.18)] bg-[#050204]">
                <tr>
                  <th class="py-3 px-4 w-12">#</th>
                  <th class="py-3 px-4">Event Type</th>
                  <th class="py-3 px-4">Principal</th>
                  <th class="py-3 px-4">SHA-256 Link</th>
                  <th class="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody id="ledger-tbody" class="divide-y divide-white/5 text-slate-300">
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>

    <div id="view-benchmark" class="tab-view">
      <div class="max-w-[1280px] mx-auto px-6 py-12 space-y-8">
        
        <div class="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-4 border-b border-[rgba(255,20,50,0.18)]">
          <div>
            <div class="inline-flex items-center space-x-2 px-3 py-0.5 rounded bg-[#ff1138]/15 text-[#ff1138] font-mono text-xs font-bold uppercase mb-2">
              <span>SIDE-BY-SIDE TEST</span>
            </div>
            <h1 class="text-3xl font-extrabold font-sans text-white tracking-tight">Test Comparison: V.E.R.I.T.Y vs. Basic Runner</h1>
            <p class="text-xs text-slate-400 mt-1">9 identical test and tampering scenarios evaluated side-by-side.</p>
          </div>

          <button onclick="switchView('evaluator')" class="btn-brand-secondary !h-9 text-xs !px-4 font-mono">
            Launch Evaluator →
          </button>
        </div>

        <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
          <div class="precision-frame !p-5 border-l-4 border-l-[#ff1138]">
            <span class="text-[10px] text-slate-400 uppercase">Basic Runner Missed Failures</span>
            <div id="bm-stat-naive-fa" class="text-[#ff1138] font-bold text-lg mt-1">8 of 8 (FAIL)</div>
          </div>
          <div class="precision-frame !p-5 border-l-4 border-l-emerald-400">
            <span class="text-[10px] text-slate-400 uppercase">V.E.R.I.T.Y Missed Failures</span>
            <div id="bm-stat-bs-fa" class="text-emerald-400 font-bold text-lg mt-1">0 of 8 (PASS)</div>
          </div>
          <div class="precision-frame !p-5 border-l-4 border-l-[#00d2ff]">
            <span class="text-[10px] text-slate-400 uppercase">Tamper Detection Rate</span>
            <div class="text-[#00d2ff] font-bold text-lg mt-1">100.0%</div>
          </div>
          <div class="precision-frame !p-5 border-l-4 border-l-purple-400">
            <span class="text-[10px] text-slate-400 uppercase">Security Check Delay</span>
            <div id="bm-stat-overhead" class="text-purple-300 font-bold text-lg mt-1">--</div>
          </div>
        </div>

        <div class="precision-frame !p-0 overflow-hidden">
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs font-mono">
              <thead class="text-slate-400 border-b border-[rgba(255,20,50,0.18)] bg-[#050204]">
                <tr>
                  <th class="py-3.5 px-4">Test Condition</th>
                  <th class="py-3.5 px-4">Basic Runner</th>
                  <th class="py-3.5 px-4">V.E.R.I.T.Y Health</th>
                  <th class="py-3.5 px-4">Diagnostics</th>
                  <th class="py-3.5 px-4 text-right">Tampering Caught?</th>
                </tr>
              </thead>
              <tbody id="benchmark-tbody" class="divide-y divide-white/5 text-slate-300">
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>

    <div id="view-architecture" class="tab-view">
      <div class="max-w-[1280px] mx-auto px-6 py-12 space-y-8">
        
        <div class="pb-4 border-b border-[rgba(255,20,50,0.18)]">
          <div class="inline-flex items-center space-x-2 px-3 py-0.5 rounded bg-emerald-500/15 text-emerald-400 font-mono text-xs font-bold uppercase mb-2">
            <span>SECURITY BOUNDARIES</span>
          </div>
          <h1 class="text-3xl font-extrabold font-sans text-white tracking-tight">Security Boundaries & System Guarantees</h1>
          <p class="text-xs text-slate-400 mt-1">Clear breakdown of what our server enforces, what we cryptographically verify, and what we monitor.</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-8 font-mono text-xs">
          
          <div class="precision-frame space-y-3 border-t-4 !border-t-emerald-400">
            <span class="font-bold text-emerald-400 text-sm uppercase block">1. Server-Enforced Controls</span>
            <p class="text-slate-300 font-sans leading-relaxed text-xs">
              Separate storage folders for each team, folder path checks that block directory traversal, short-lived signed access tokens, and a central rule broker that locks test prompts until checks pass.
            </p>
          </div>

          <div class="precision-frame space-y-3 border-t-4 !border-t-[#00d2ff]">
            <span class="font-bold text-[#00d2ff] text-sm uppercase block">2. Tested Verifications</span>
            <p class="text-slate-300 font-sans leading-relaxed text-xs">
              Exact RFC 8785 JSON formatting, tamper-evident SHA-256 hash chains, Ed25519 digital signature validation against verified keys, and strict 4-state test health checks.
            </p>
          </div>

          <div class="precision-frame space-y-3 border-t-4 !border-t-amber-400">
            <span class="font-bold text-amber-400 text-sm uppercase block">3. Monitored Activity</span>
            <p class="text-slate-300 font-sans leading-relaxed text-xs">
              Monitors CPU load, memory usage, and response times against declared limits to flag slowed or starved tests. Does <strong>not</strong> enforce kernel cgroups v2 hard limits.
            </p>
          </div>

          <div class="precision-frame space-y-3 border-t-4 !border-t-[#ff1138]">
            <span class="font-bold text-[#ff1138] text-sm uppercase block">4. Production Prerequisites</span>
            <p class="text-slate-300 font-sans leading-relaxed text-xs">
              Physical LLM memory isolation requires dedicated worker container recycling or hardware TEEs (AMD SEV-SNP). Immutable public log transparency requires Sigstore Rekor anchoring.
            </p>
          </div>

        </div>

      </div>
    </div>

  </main>

  <div id="meta-modal" class="hidden fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4">
    <div class="precision-frame max-w-2xl w-full !p-6 space-y-4 font-mono text-xs">
      <div class="flex justify-between items-center border-b border-[rgba(255,20,50,0.18)] pb-3">
        <span id="modal-title" class="font-bold text-white text-sm">Event Metadata Details</span>
        <button onclick="closeModal()" class="text-slate-400 hover:text-white px-2 py-1 rounded">&times; Close</button>
      </div>
      <div class="space-y-1 text-slate-400 text-[11px]">
        <div>Event Hash: <span id="modal-hash" class="text-white select-all font-bold"></span></div>
        <div>Payload Digest: <span id="modal-digest" class="text-white select-all font-bold"></span></div>
      </div>
      <div class="relative">
        <pre id="modal-json" class="p-4 bg-[#000000] rounded border border-[rgba(255,20,50,0.2)] text-slate-300 max-h-72 overflow-y-auto overflow-x-auto text-[11px]"></pre>
        <button onclick="copyModalJson()" class="absolute top-2 right-2 px-2.5 py-1 bg-white/10 hover:bg-white/20 rounded text-[10px] text-white">copy</button>
      </div>
    </div>
  </div>

  <div id="toast-copied" class="hidden fixed bottom-6 right-6 bg-[#ff1138] text-white font-bold font-mono text-xs px-4 py-2 rounded shadow-[0_0_20px_rgba(255,17,56,0.6)] z-50">
    Copied to clipboard!
  </div>

  <script>
    let mouseCanvasX = -9999;
    let mouseCanvasY = -9999;

    function initCrimsonVortexCanvas() {
      const canvas = document.getElementById("crimsonVortex");
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      let w = 0, h = 0;
      let time = 0;

      const particleCount = 120;
      let particles = [];

      function initParticles() {
        particles = [];
        const pw = w || window.innerWidth || 1600;
        const ph = h || window.innerHeight || 900;
        for (let i = 0; i < particleCount; i++) {
          const ox = Math.random() * pw;
          const oy = Math.random() * ph;
          particles.push({
            ox: ox,
            oy: oy,
            x: ox,
            y: oy,
            vx: 0,
            vy: 0,
            radius: Math.random() * 2.0 + 0.8,
            alpha: Math.random() * 0.45 + 0.25
          });
        }
      }

      function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
        initParticles();
      }
      window.addEventListener("resize", resize);
      resize();

      window.addEventListener("mousemove", (e) => {
        mouseCanvasX = e.clientX;
        mouseCanvasY = e.clientY;
      });

      window.addEventListener("mouseleave", () => {
        mouseCanvasX = -9999;
        mouseCanvasY = -9999;
      });

      function draw() {
        time += 0.007;
        ctx.fillStyle = "#000000";
        ctx.fillRect(0, 0, w, h);

        const cx = w * 0.72;
        const cy = h * 0.38;
        const radGrad = ctx.createRadialGradient(cx, cy, 20, cx, cy, Math.max(w, 1200) * 0.6);
        radGrad.addColorStop(0, "rgba(235, 10, 45, 0.48)");
        radGrad.addColorStop(0.35, "rgba(170, 0, 30, 0.28)");
        radGrad.addColorStop(0.7, "rgba(35, 0, 8, 0.88)");
        radGrad.addColorStop(1, "rgba(0, 0, 0, 0)");
        ctx.fillStyle = radGrad;
        ctx.fillRect(0, 0, w, h);

        const repulsionRadius = 200;
        const repulsionStrength = 95;

        ctx.lineWidth = 2.2;
        for (let i = 0; i < 28; i++) {
          ctx.beginPath();
          const p = i / 28;
          const alpha = 0.16 + Math.sin(time + i * 0.3) * 0.07;
          ctx.strokeStyle = `rgba(${230 + Math.min(25, i)}, ${10 + i * 2}, ${35 + i * 2}, ${alpha})`;

          const startX = 0;
          const endX = w + 40;
          const stepX = 14;

          for (let x = startX; x <= endX; x += stepX) {
            const nx = x / (w || 1);
            let baseY = cy + Math.sin(nx * 3.6 - time * 1.3 + i * 0.35) * (70 + i * 7) +
                             Math.cos(nx * 2.1 + time * 0.9 + i * 0.2) * (45 + i * 4) +
                             (nx * 110) - (p * 130);
            let drawX = x;
            let drawY = baseY;

            const dx = drawX - mouseCanvasX;
            const dy = drawY - mouseCanvasY;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < repulsionRadius && dist > 0) {
              const force = Math.pow(1 - dist / repulsionRadius, 2) * repulsionStrength;
              drawX += (dx / dist) * force;
              drawY += (dy / dist) * force;
            }

            if (x === startX) ctx.moveTo(drawX, drawY);
            else ctx.lineTo(drawX, drawY);
          }
          ctx.stroke();
        }

        for (let i = 0; i < particles.length; i++) {
          const pt = particles[i];
          const dx = pt.x - mouseCanvasX;
          const dy = pt.y - mouseCanvasY;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < repulsionRadius && dist > 0) {
            const force = (1 - dist / repulsionRadius) * 6.5;
            pt.vx += (dx / dist) * force;
            pt.vy += (dy / dist) * force;
          }

          pt.vx += (pt.ox - pt.x) * 0.06;
          pt.vy += (pt.oy - pt.y) * 0.06;
          pt.vx *= 0.85;
          pt.vy *= 0.85;
          pt.x += pt.vx;
          pt.y += pt.vy;

          ctx.fillStyle = `rgba(255, 30, 60, ${pt.alpha})`;
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, pt.radius, 0, Math.PI * 2);
          ctx.fill();

          for (let j = i + 1; j < particles.length; j++) {
            const p2 = particles[j];
            const pdist = Math.hypot(pt.x - p2.x, pt.y - p2.y);
            if (pdist < 90) {
              ctx.strokeStyle = `rgba(255, 20, 50, ${(1 - pdist / 90) * 0.18})`;
              ctx.lineWidth = 0.8;
              ctx.beginPath();
              ctx.moveTo(pt.x, pt.y);
              ctx.lineTo(p2.x, p2.y);
              ctx.stroke();
            }
          }
        }

        requestAnimationFrame(draw);
      }
      requestAnimationFrame(draw);
    }

    let scenariosData = {};
    let benchmarkData = {};
    let activeKey = "scenario_1_clean";
    let activeEvents = [];

    const views = ["overview", "evaluator", "ledger", "benchmark", "architecture"];

    function switchView(target) {
      views.forEach(v => {
        const vEl = document.getElementById("view-" + v);
        const navEl = document.getElementById("nav-" + v);
        if (vEl) vEl.classList.toggle("active", v === target);
        if (navEl) navEl.classList.toggle("active", v === target);
      });
      window.location.hash = target;
      window.scrollTo({ top: 0, behavior: "smooth" });
    }

    async function loadData() {
      try {
        const [scResp, bmResp] = await Promise.all([
          fetch("/api/scenarios"),
          fetch("/api/benchmark"),
        ]);
        scenariosData = await scResp.json();
        benchmarkData = await bmResp.json();

        renderScenarioSelectors();
        renderActiveScenario();
        renderBenchmark();
      } catch (err) {
        console.error("Telemetry failed:", err);
      }
    }

    async function refreshAllData() {
      await loadData();
    }

    function renderScenarioSelectors() {
      const grid = document.getElementById("scenario-selector-grid");
      if (!grid) return;
      grid.innerHTML = "";

      const names = {
        "scenario_1_clean": "1. Clean Run",
        "scenario_2_contaminated": "2. Contaminated",
        "scenario_3_resource_violation": "3. Throttled",
        "scenario_3_resource_exhausted": "3. Throttled",
        "scenario_4_telemetry_offline": "4. Monitor Offline",
        "scenario_5_tampered_evidence": "5. Tampered Ledger",
        "scenario_5_tampered_ledger": "5. Tampered Ledger",
      };

      Object.keys(scenariosData).forEach(key => {
        const sc = scenariosData[key];
        const btn = document.createElement("button");
        const isActive = key === activeKey;
        const isPass = sc.verdict === "VALID";

        const label = names[key] || key.replace(/_/g, " ");

        btn.className = `p-3.5 text-left rounded-md border transition-all text-xs font-sans flex flex-col justify-between h-20 ${
          isActive
            ? "border-white/40 bg-white/10 text-white"
            : "border-white/10 bg-white/[0.02] text-slate-300 hover:border-white/25 hover:bg-white/[0.05]"
        }`;

        btn.innerHTML = `
          <div class="font-semibold text-white truncate">${label}</div>
          <div class="flex items-center justify-between mt-2">
            <span class="text-[11px] px-2 py-0.5 rounded font-medium ${isPass ? 'bg-white/15 text-white border border-white/20' : 'bg-white/10 text-slate-300 border border-white/15'}">${sc.verdict}</span>
            <span class="text-[11px] text-slate-400">${sc.events_count} events</span>
          </div>
        `;

        btn.onclick = () => {
          activeKey = key;
          renderScenarioSelectors();
          renderActiveScenario();
        };

        grid.appendChild(btn);
      });
    }

    function renderActiveScenario() {
      const data = scenariosData[activeKey];
      if (!data) return;

      const vBadge = document.getElementById("badge-verdict");
      vBadge.innerText = (data.verdict || "").replace(/_/g, " ");
      if (data.verdict === "VALID") {
        vBadge.className = "px-3 py-1 text-xs font-sans font-semibold rounded bg-white/15 text-white border border-white/20";
      } else {
        vBadge.className = "px-3 py-1 text-xs font-sans font-semibold rounded bg-white/10 text-slate-200 border border-white/15";
      }

      document.getElementById("text-run-id").innerText = (data.run_id || "").replace(/_/g, " ");
      document.getElementById("text-reason-code").innerText = (data.reason_code || "").replace(/_/g, " ");
      document.getElementById("text-finding-outcome").innerText = (data.finding_outcome || "").replace(/_/g, " ");
      document.getElementById("text-diagnostic").innerText = data.diagnostic_message;

      const rBadge = document.getElementById("badge-release-state");
      rBadge.innerText = (data.final_release_state || "").replace(/_/g, " ");
      if (data.final_release_state === "RELEASED") {
        rBadge.className = "px-3 py-1 text-xs font-sans font-semibold rounded bg-white/15 text-white border border-white/20";
      } else if (data.final_release_state === "BLINDED") {
        rBadge.className = "px-3 py-1 text-xs font-sans font-semibold rounded bg-white/10 text-slate-300 border border-white/15";
      } else {
        rBadge.className = "px-3 py-1 text-xs font-sans font-semibold rounded bg-white/10 text-slate-300 border border-white/15";
      }

      document.getElementById("text-manifest-digest").innerText = data.manifest_digest;
      document.getElementById("text-checkpoint-sig").innerText = data.checkpoint_sig;
      document.getElementById("text-signer-key").innerText = data.signer_key;

      const outBox = document.getElementById("verifier-output-box");
      outBox.className = "hidden";
      outBox.innerText = "";

      activeEvents = data.events || [];
      renderLedgerEvents(activeEvents);
    }

    function renderLedgerEvents(events) {
      const tbody = document.getElementById("ledger-tbody");
      if (!tbody) return;
      tbody.innerHTML = "";

      events.forEach(ev => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-[#ff1138]/5 transition-colors";
        const displayType = (ev.type || "").replace(/_/g, " ");
        tr.innerHTML = `
          <td class="py-3 px-4 font-mono text-slate-500 font-bold">${ev.seq}</td>
          <td class="py-3 px-4 font-mono font-semibold text-white">
            <span class="px-2 py-0.5 rounded bg-[#0f0408] border border-[rgba(255,20,50,0.2)]">${displayType}</span>
          </td>
          <td class="py-3 px-4 font-mono text-slate-400">${(ev.subject || "").replace(/_/g, " ")}</td>
          <td class="py-3 px-4 font-mono text-slate-400 select-all truncate max-w-[140px]">${ev.hash.substring(0, 16)}...</td>
          <td class="py-3 px-4 text-right font-mono">
            <button class="px-2.5 py-1 rounded bg-[#0f0408] hover:bg-[#ff1138] hover:text-white border border-[rgba(255,20,50,0.3)] transition-colors text-slate-300 text-[11px]" onclick='openModal(${JSON.stringify(ev)})'>
              Inspect
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    function filterLedgerEvents() {
      const term = (document.getElementById("ledger-search").value || "").toLowerCase();
      const filtered = activeEvents.filter(e =>
        e.type.toLowerCase().includes(term) ||
        (e.type || "").replace(/_/g, " ").toLowerCase().includes(term) ||
        e.subject.toLowerCase().includes(term) ||
        (e.subject || "").replace(/_/g, " ").toLowerCase().includes(term) ||
        e.hash.toLowerCase().includes(term) ||
        JSON.stringify(e.metadata).toLowerCase().includes(term)
      );
      renderLedgerEvents(filtered);
    }

    function renderBenchmark() {
      if (!benchmarkData || !benchmarkData.comparisons) return;

      document.getElementById("bm-stat-naive-fa").innerText = `${benchmarkData.naive_false_acceptance} of ${benchmarkData.total_scenarios - 1} (FAIL)`;
      document.getElementById("bm-stat-bs-fa").innerText = `${benchmarkData.blindseal_false_acceptance} of ${benchmarkData.total_scenarios - 1} (PASS)`;
      document.getElementById("bm-stat-overhead").innerText = `~${benchmarkData.median_overhead_ms}`;

      const tbody = document.getElementById("benchmark-tbody");
      if (!tbody) return;
      tbody.innerHTML = "";

      benchmarkData.comparisons.forEach(c => {
        const tr = document.createElement("tr");
        tr.className = "hover:bg-[#ff1138]/5 transition-colors";
        const naiveColor = c.naive_accepted ? "text-amber-400" : "text-emerald-400";
        const bsColor = c.blindseal_valid ? "text-emerald-400" : "text-[#ff1138]";

        const displayId = (c.scenario_id || "").replace(/_/g, " ").toUpperCase();
        const displayReason = (c.blindseal_reason || "").replace(/_/g, " ");
        tr.innerHTML = `
          <td class="py-3.5 px-4 font-mono">
            <div class="font-bold text-white text-xs">${displayId}</div>
            <div class="text-[11px] text-slate-400 mt-0.5 font-sans">${c.desc}</div>
          </td>
          <td class="py-3.5 px-4 font-bold ${naiveColor}">
            <span class="px-2 py-0.5 rounded ${c.naive_accepted ? 'bg-amber-400/10' : 'bg-emerald-400/10'}">${(c.naive_verdict || "").replace(/_/g, " ")}</span>
          </td>
          <td class="py-3.5 px-4 font-bold ${bsColor}">
            <span class="px-2 py-0.5 rounded ${c.blindseal_valid ? 'bg-emerald-400/10' : 'bg-[#ff1138]/10'}">${(c.blindseal_verdict || "").replace(/_/g, " ")}</span>
          </td>
          <td class="py-3.5 px-4 text-[11px] text-slate-300 max-w-xs font-sans">${displayReason}</td>
          <td class="py-3.5 px-4 text-right font-bold ${c.tamper_detected ? 'text-emerald-400' : 'text-slate-600'}">
            ${c.tamper_detected ? '<span class="px-2 py-0.5 rounded bg-emerald-400/15 text-emerald-400">YES (100%)</span>' : 'N/A'}
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    async function auditCapsuleWithVerifier() {
      const data = scenariosData[activeKey];
      if (!data || !data.capsule) return;

      const outBox = document.getElementById("verifier-output-box");
      outBox.className = "p-4 rounded-md border text-xs font-sans bg-white/[0.03] border-white/10 text-slate-300 block";
      outBox.innerText = "Running independent deterministic validity audit...";

      try {
        const resp = await fetch("/api/verify/capsule", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            capsule: data.capsule,
            trusted_public_key: data.signer_key,
          }),
        });
        const res = await resp.json();

        if (res.is_valid) {
          outBox.className = "p-4 rounded-md border text-xs font-sans bg-white/[0.05] border-white/20 text-white block";
          outBox.innerText = `[OK] VALIDITY AUDIT PASSED: All ${res.event_count_checked} events, manifest digest, hash chain, and Ed25519 signature verified.`;
        } else {
          outBox.className = "p-4 rounded-md border text-xs font-sans bg-white/[0.05] border-white/20 text-white block";
          const displayReason = (res.reason_code || "").replace(/_/g, " ");
          const displayVerdict = (res.verdict || "").replace(/_/g, " ");
          outBox.innerText = `[FAIL] VERDICT ${displayVerdict} (${displayReason}): ${res.diagnostic_message}`;
        }
      } catch (err) {
        outBox.className = "p-4 rounded-md border text-xs font-sans bg-white/[0.05] border-white/20 text-white block";
        outBox.innerText = "Verification request failed: " + err.message;
      }
    }

    function exportCapsuleJson() {
      const data = scenariosData[activeKey];
      if (!data || !data.capsule) return;
      const jsonStr = JSON.stringify(data.capsule, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${data.run_id}_capsule.json`;
      a.click();
    }

    function openModal(ev) {
      const displayType = (ev.type || "").replace(/_/g, " ");
      document.getElementById("modal-title").innerText = `Event #${ev.seq} [${displayType}]`;
      document.getElementById("modal-hash").innerText = ev.hash;
      document.getElementById("modal-digest").innerText = ev.payload_digest;
      document.getElementById("modal-json").innerText = JSON.stringify(ev.metadata, null, 2);
      document.getElementById("meta-modal").className = "fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4";
    }

    function closeModal() {
      document.getElementById("meta-modal").className = "hidden";
    }

    function copyModalJson() {
      const text = document.getElementById("modal-json").innerText;
      navigator.clipboard.writeText(text);
      showToast();
    }

    function copyToClipboard(elementId) {
      const text = document.getElementById(elementId).innerText;
      navigator.clipboard.writeText(text);
      showToast();
    }

    function showToast() {
      const toast = document.getElementById("toast-copied");
      toast.className = "fixed bottom-6 right-6 bg-[#ff1138] text-white font-bold font-mono text-xs px-4 py-2 rounded shadow-[0_0_20px_rgba(255,17,56,0.6)] z-50 block";
      setTimeout(() => {
        toast.className = "hidden";
      }, 2000);
    }

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeModal();
    });

    document.getElementById("meta-modal").addEventListener("click", (e) => {
      if (e.target.id === "meta-modal") closeModal();
    });

    window.addEventListener("hashchange", () => {
      const h = window.location.hash.replace("#", "");
      if (views.includes(h)) switchView(h);
    });

    const initHash = window.location.hash.replace("#", "");
    if (views.includes(initHash)) switchView(initHash);

    initCrimsonVortexCanvas();
    loadData();
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html)
