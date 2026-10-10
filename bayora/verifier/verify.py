from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict
from bayora.core.models import EvidenceCapsule, LifecycleState, Verdict
from bayora.core.engine import EvaluationAssessment, ValidityEngine

def verify_capsule(capsule: EvidenceCapsule, telemetry_online: bool = True, trusted_evaluator_public_key: str | None = None) -> EvaluationAssessment:
    return ValidityEngine.evaluate(
        lifecycle=LifecycleState.COMPLETED,
        manifest=capsule.manifest,
        events=capsule.events,
        checkpoint=capsule.checkpoint,
        telemetry_online=telemetry_online,
        trusted_evaluator_public_key=trusted_evaluator_public_key,
    )

def verify_capsule_from_file(file_path: str | Path, telemetry_online: bool = True, trusted_evaluator_public_key: str | None = None) -> EvaluationAssessment:
    path = Path(file_path)
    if not path.exists():
        return EvaluationAssessment(
            verdict=Verdict.INCONCLUSIVE,
            reason_code='FILE_NOT_FOUND',
            is_valid=False,
            diagnostic_message=f"Evidence capsule file not found at '{path}'.",
        )
    try:
        content = path.read_text(encoding='utf-8')
        data = json.loads(content)
        capsule = EvidenceCapsule.model_validate(data)
        return verify_capsule(capsule, telemetry_online=telemetry_online, trusted_evaluator_public_key=trusted_evaluator_public_key)
    except Exception as exc:
        return EvaluationAssessment(
            verdict=Verdict.INVALIDATED,
            reason_code='MALFORMED_CAPSULE_JSON',
            is_valid=False,
            diagnostic_message=f'Failed to parse evidence capsule: {exc}',
        )

def format_report_dict(assessment: EvaluationAssessment, capsule: EvidenceCapsule | None = None) -> Dict[str, Any]:
    report = {
        'verdict': assessment.verdict.value,
        'is_valid': assessment.is_valid,
        'reason_code': assessment.reason_code,
        'diagnostic_message': assessment.diagnostic_message,
        'failed_sequence_number': assessment.failed_sequence_number,
        'events_checked': assessment.event_count_checked,
    }
    if capsule:
        report['run_id'] = capsule.manifest.run_id
        report['finding_outcome'] = capsule.finding_outcome.value
        report['declared_scope'] = capsule.declared_scope
        report['manifest_digest'] = capsule.manifest.compute_digest()
        report['checkpoint_signer'] = capsule.checkpoint.signer_public_key_hex[:16] + '...'
    return report

def main() -> int:
    parser = argparse.ArgumentParser(description='Bayora V.E.R.I.T.Y - Independent Evidence Capsule Verifier')
    parser.add_argument('--file', '-f', required=True, help='Path to evidence capsule JSON file')
    parser.add_argument('--json', '-j', action='store_true', help='Output result as JSON')
    parser.add_argument('--trusted-key', '-k', default=None, help='Hex-encoded trusted evaluator Ed25519 public key (detects key substitution)')
    args = parser.parse_args()
    assessment = verify_capsule_from_file(args.file, trusted_evaluator_public_key=args.trusted_key)
    if args.json:
        report = format_report_dict(assessment)
        print(json.dumps(report, indent=2))
    else:
        status_symbol = '[OK]' if assessment.is_valid else '[FAIL]'
        print('=' * 60)
        print('  BAYORA V.E.R.I.T.Y INDEPENDENT EVIDENCE VERIFICATION')
        print('=' * 60)
        print(f'Status:             {status_symbol} {assessment.verdict.value}')
        print(f'Reason Code:        {assessment.reason_code}')
        print(f'Diagnostic:         {assessment.diagnostic_message}')
        print(f'Events Audited:     {assessment.event_count_checked}')
        if assessment.failed_sequence_number is not None:
            print(f'Failure Sequence #: {assessment.failed_sequence_number}')
        print('=' * 60)
    if assessment.verdict == Verdict.VALID:
        return 0
    elif assessment.verdict == Verdict.INVALIDATED:
        return 1
    elif assessment.verdict == Verdict.INCONCLUSIVE:
        return 2
    else:
        return 3

if __name__ == '__main__':
    sys.exit(main())
