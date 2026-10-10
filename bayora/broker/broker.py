from __future__ import annotations
import hmac
import hashlib
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import time
from bayora.core.canonical import canonical_json_bytes
from bayora.core.crypto import sha256_hex
from bayora.core.models import AuditEvent, EventType, Verdict, EvidenceCapsule, LifecycleState
from bayora.vaults.vault import MultiTenantStorage, TenantId, StoredArtifact

class ReleaseState(str, Enum):
    SEALED = 'SEALED'
    BLINDED = 'BLINDED'
    VERIFIED = 'VERIFIED'
    RELEASED = 'RELEASED'
    REJECTED = 'REJECTED'

class Actor:

    def __init__(self, actor_id: str, tenant: TenantId, roles: List[str], token: str, expires_at: float = float('inf'), bound_run_id: str = '*') -> None:
        self.actor_id = actor_id
        self.tenant = tenant
        self.roles = roles
        self.token = token
        self.expires_at = expires_at
        self.bound_run_id = bound_run_id

class BrokerResponse:

    def __init__(self, success: bool, reason_code: str, content: Optional[bytes] = None, digest: Optional[str] = None) -> None:
        self.success = success
        self.reason_code = reason_code
        self.content = content if success else None
        self.digest = digest

class PolicyBroker:

    def __init__(self, storage: MultiTenantStorage, broker_secret: str = 'bayora-broker-secret-key-v1', trusted_evaluator_public_key: Optional[str] = None) -> None:
        self.storage = storage
        self.broker_secret = broker_secret.encode('utf-8')
        self.trusted_evaluator_public_key = trusted_evaluator_public_key
        self._release_states: Dict[tuple[str, str], ReleaseState] = {}
        self._events: List[AuditEvent] = []
        self._prev_hash = '0' * 64

    def issue_token(self, actor_id: str, tenant: TenantId, roles: List[str], expires_in_seconds: Optional[float] = 3600.0, bound_run_id: Optional[str] = None) -> str:
        roles_str = ','.join(sorted(roles))
        now = time.time()
        exp_val = now + expires_in_seconds if expires_in_seconds is not None else 9999999999.0
        exp_str = f'{exp_val:.1f}'
        run_str = bound_run_id or '*'
        payload = f'{actor_id}:{tenant.value}:{roles_str}:{exp_str}:{run_str}'
        sig = hmac.new(self.broker_secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
        return f'{payload}:{sig}'

    def authenticate_token(self, token: str, target_run_id: Optional[str] = None) -> tuple[Optional[Actor], str]:
        try:
            parts = token.split(':')
            if len(parts) != 6:
                return (None, 'MALFORMED_TOKEN')
            actor_id, tenant_str, roles_str, exp_str, run_str, sig = parts
            payload = f'{actor_id}:{tenant_str}:{roles_str}:{exp_str}:{run_str}'
            target_sig = hmac.new(self.broker_secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, target_sig):
                return (None, 'INVALID_TOKEN_SIGNATURE')
            expires_at = float(exp_str)
            if time.time() > expires_at:
                return (None, 'TOKEN_EXPIRED')
            if target_run_id and run_str != '*' and (run_str != target_run_id):
                return (None, 'CROSS_RUN_TOKEN_SUBSTITUTION')
            try:
                tenant = TenantId(tenant_str)
            except ValueError:
                return (None, 'INVALID_TENANT_IN_TOKEN')
            roles = [r for r in roles_str.split(',') if r]
            actor = Actor(actor_id=actor_id, tenant=tenant, roles=roles, token=token, expires_at=expires_at, bound_run_id=run_str)
            return (actor, 'OK')
        except (ValueError, TypeError):
            return (None, 'AUTHENTICATION_EXCEPTION')

    def _record_event(self, run_id: str, event_type: EventType, subject_id: str, payload_digest: str, metadata: Dict[str, Any]) -> AuditEvent:
        now_iso = datetime.now(timezone.utc).isoformat()
        seq = len(self._events)
        evt_dict = {
            'run_id': run_id,
            'sequence_number': seq,
            'event_type': event_type,
            'timestamp': now_iso,
            'subject_id': subject_id,
            'payload_digest': payload_digest,
            'metadata': metadata,
            'previous_event_hash': self._prev_hash,
        }
        raw = canonical_json_bytes(evt_dict)
        h = sha256_hex(raw + self._prev_hash.encode('utf-8'))
        evt = AuditEvent(
            run_id=run_id,
            sequence_number=seq,
            event_type=event_type,
            timestamp=now_iso,
            subject_id=subject_id,
            payload_digest=payload_digest,
            metadata=metadata,
            previous_event_hash=self._prev_hash,
            event_hash=h,
        )
        self._events.append(evt)
        self._prev_hash = h
        return evt

    @property
    def audited_events(self) -> List[AuditEvent]:
        return list(self._events)

    def register_artifact_state(self, run_id: str, artifact_id: str, state: ReleaseState) -> None:
        self._release_states[run_id, artifact_id] = state

    def get_artifact_release_state(self, run_id: str, artifact_id: str) -> ReleaseState:
        return self._release_states.get((run_id, artifact_id), ReleaseState.BLINDED)

    def transition_to_verified(
        self,
        run_id: str,
        artifact_id: str,
        evidence: Any = None,
        token: Optional[str] = None,
        trusted_evaluator_public_key: Optional[str] = None,
        verdict_or_assessment: Any = None,
        telemetry_online: bool = True,
    ) -> BrokerResponse:
        if evidence is None and verdict_or_assessment is not None:
            evidence = verdict_or_assessment
        if evidence in (Verdict.INVALIDATED, Verdict.INCONCLUSIVE, Verdict.NOT_EVALUATED, ReleaseState.REJECTED):
            self._release_states[run_id, artifact_id] = ReleaseState.REJECTED
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id='evaluator',
                payload_digest='sha256:empty',
                metadata={'action': 'TRANSITION_VERIFIED', 'decision': 'REJECTED', 'reason': 'EXPLICIT_INVALIDATION_SIGNAL'},
            )
            return BrokerResponse(success=True, reason_code='STATE_TRANSITIONED_REJECTED')
        if token is None:
            reason = 'MISSING_AUTHENTICATION_TOKEN'
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id='unauthenticated',
                payload_digest='sha256:empty',
                metadata={'action': 'TRANSITION_VERIFIED', 'decision': 'DENIED', 'reason': reason},
            )
            return BrokerResponse(success=False, reason_code=reason)
        actor, auth_err = self.authenticate_token(token, target_run_id=run_id)
        if not actor or not any((r in actor.roles for r in ('evaluator', 'system'))):
            reason = auth_err if not actor else 'UNAUTHORIZED_TRANSITION_CALLER'
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id if actor else 'unauthenticated',
                payload_digest='sha256:empty',
                metadata={'action': 'TRANSITION_VERIFIED', 'decision': 'DENIED', 'reason': reason},
            )
            return BrokerResponse(success=False, reason_code=reason)
        capsule: Optional[EvidenceCapsule] = None
        if isinstance(evidence, EvidenceCapsule):
            capsule = evidence
        elif isinstance(evidence, dict) and 'manifest' in evidence and ('checkpoint' in evidence):
            try:
                capsule = EvidenceCapsule(**evidence)
            except Exception:
                capsule = None
        if capsule is None:
            self._release_states[run_id, artifact_id] = ReleaseState.REJECTED
            reason = 'UNTRUSTED_CALLER_OBJECT_REJECTED'
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'action': 'TRANSITION_VERIFIED', 'decision': 'DENIED', 'reason': reason},
            )
            return BrokerResponse(success=False, reason_code=reason)
        if capsule.manifest.run_id != run_id or (capsule.checkpoint and capsule.checkpoint.run_id != run_id):
            self._release_states[run_id, artifact_id] = ReleaseState.REJECTED
            reason = 'RUN_ID_MISMATCH'
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'action': 'TRANSITION_VERIFIED', 'decision': 'DENIED', 'reason': reason},
            )
            return BrokerResponse(success=False, reason_code=reason)
        if not capsule.checkpoint:
            self._release_states[run_id, artifact_id] = ReleaseState.REJECTED
            reason = 'MISSING_SIGNED_CHECKPOINT'
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'action': 'TRANSITION_VERIFIED', 'decision': 'DENIED', 'reason': reason},
            )
            return BrokerResponse(success=False, reason_code=reason)
        digest = capsule.manifest.compute_digest()
        if capsule.checkpoint.manifest_digest != digest:
            self._release_states[run_id, artifact_id] = ReleaseState.REJECTED
            reason = 'MANIFEST_DIGEST_MISMATCH'
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'action': 'TRANSITION_VERIFIED', 'decision': 'DENIED', 'reason': reason},
            )
            return BrokerResponse(success=False, reason_code=reason)
        trusted_key = trusted_evaluator_public_key or self.trusted_evaluator_public_key
        if trusted_key and capsule.checkpoint.signer_public_key_hex != trusted_key:
            self._release_states[run_id, artifact_id] = ReleaseState.REJECTED
            reason = 'UNTRUSTED_EVALUATOR_KEY'
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'action': 'TRANSITION_VERIFIED', 'decision': 'DENIED', 'reason': reason},
            )
            return BrokerResponse(success=False, reason_code=reason)
        from bayora.core.engine import ValidityEngine
        assessment = ValidityEngine.evaluate(
            lifecycle=LifecycleState.COMPLETED,
            manifest=capsule.manifest,
            events=capsule.events,
            checkpoint=capsule.checkpoint,
            telemetry_online=telemetry_online,
            trusted_evaluator_public_key=trusted_key or capsule.checkpoint.signer_public_key_hex,
        )
        if assessment.is_valid and assessment.verdict == Verdict.VALID:
            self._release_states[run_id, artifact_id] = ReleaseState.VERIFIED
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'action': 'TRANSITION_VERIFIED', 'decision': 'ALLOWED', 'reason': 'EVIDENCE_CRYPTOGRAPHICALLY_VERIFIED'},
            )
            return BrokerResponse(success=True, reason_code='STATE_TRANSITIONED_VERIFIED')
        else:
            self._release_states[run_id, artifact_id] = ReleaseState.REJECTED
            reason = f'EVIDENCE_INVALIDATED:{assessment.reason_code}'
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'action': 'TRANSITION_VERIFIED', 'decision': 'DENIED', 'reason': reason},
            )
            return BrokerResponse(success=False, reason_code=reason)

    def write_artifact(self, token: str, run_id: str, target_tenant: TenantId, artifact_id: str, content: bytes | str, relative_path: Optional[str] = None) -> BrokerResponse:
        actor, auth_err = self.authenticate_token(token, target_run_id=run_id)
        if not actor:
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id='unknown_principal',
                payload_digest='sha256:empty',
                metadata={'action': 'WRITE', 'decision': 'DENIED', 'reason': auth_err},
            )
            return BrokerResponse(success=False, reason_code=auth_err)
        if actor.tenant != target_tenant and actor.tenant != TenantId.SYSTEM:
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'actor_tenant': actor.tenant.value, 'target_tenant': target_tenant.value, 'action': 'WRITE', 'decision': 'DENIED', 'reason': 'CROSS_TENANT_WRITE_FORBIDDEN'},
            )
            return BrokerResponse(success=False, reason_code='CROSS_TENANT_WRITE_FORBIDDEN')
        try:
            vault = self.storage.get_vault(target_tenant)
            stored = vault.store_artifact(artifact_id, content, relative_path=relative_path)
            if target_tenant == TenantId.RED:
                self.register_artifact_state(run_id, artifact_id, ReleaseState.SEALED)
            self._record_event(
                run_id=run_id,
                event_type=EventType.SUITE_SEALED if target_tenant == TenantId.RED else EventType.DEFENSE_SEALED,
                subject_id=actor.actor_id,
                payload_digest=stored.digest,
                metadata={'target_tenant': target_tenant.value, 'artifact_id': artifact_id, 'decision': 'ALLOWED', 'reason': 'ARTIFACT_STORED'},
            )
            return BrokerResponse(success=True, reason_code='ARTIFACT_STORED', digest=stored.digest)
        except PermissionError:
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'action': 'WRITE', 'decision': 'DENIED', 'reason': 'PATH_TRAVERSAL_BLOCKED'},
            )
            return BrokerResponse(success=False, reason_code='PATH_TRAVERSAL_BLOCKED')

    def read_artifact(self, token: str, run_id: str, target_tenant: TenantId, relative_path: str, artifact_id: Optional[str] = None) -> BrokerResponse:
        actor, auth_err = self.authenticate_token(token, target_run_id=run_id)
        if not actor:
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id='unknown_principal',
                payload_digest='sha256:empty',
                metadata={'action': 'READ', 'decision': 'DENIED', 'reason': auth_err},
            )
            return BrokerResponse(success=False, reason_code=auth_err)
        art_id = artifact_id or Path(relative_path).stem
        if actor.tenant == target_tenant or actor.tenant == TenantId.SYSTEM:
            try:
                vault = self.storage.get_vault(target_tenant)
                content = vault.read_artifact(relative_path)
                digest = 'sha256:' + sha256_hex(content)
                self._record_event(
                    run_id=run_id,
                    event_type=EventType.TEST_DISPATCHED,
                    subject_id=actor.actor_id,
                    payload_digest=digest,
                    metadata={'action': 'READ_OWN', 'decision': 'ALLOWED', 'target_tenant': target_tenant.value},
                )
                return BrokerResponse(success=True, reason_code='READ_ALLOWED', content=content, digest=digest)
            except PermissionError:
                self._record_event(
                    run_id=run_id,
                    event_type=EventType.TEST_DISPATCHED,
                    subject_id=actor.actor_id,
                    payload_digest='sha256:empty',
                    metadata={'action': 'READ', 'decision': 'DENIED', 'reason': 'PATH_TRAVERSAL_BLOCKED'},
                )
                return BrokerResponse(success=False, reason_code='PATH_TRAVERSAL_BLOCKED')
            except FileNotFoundError:
                return BrokerResponse(success=False, reason_code='ARTIFACT_NOT_FOUND')
        if actor.tenant == TenantId.RED and target_tenant == TenantId.BLUE:
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'actor_tenant': actor.tenant.value, 'target_tenant': target_tenant.value, 'action': 'READ', 'decision': 'DENIED', 'reason': 'BLUE_DEFENSE_CONFIDENTIAL'},
            )
            return BrokerResponse(success=False, reason_code='BLUE_DEFENSE_CONFIDENTIAL')
        if actor.tenant == TenantId.BLUE and target_tenant == TenantId.RED:
            rel_state = self.get_artifact_release_state(run_id, art_id)
            if rel_state != ReleaseState.RELEASED:
                self._record_event(
                    run_id=run_id,
                    event_type=EventType.TEST_DISPATCHED,
                    subject_id=actor.actor_id,
                    payload_digest='sha256:empty',
                    metadata={'actor_tenant': actor.tenant.value, 'target_tenant': target_tenant.value, 'artifact_id': art_id, 'release_state': rel_state.value, 'action': 'READ', 'decision': 'DENIED', 'reason': 'RED_PAYLOAD_UNRELEASED'},
                )
                return BrokerResponse(success=False, reason_code='RED_PAYLOAD_UNRELEASED')
            try:
                vault = self.storage.get_vault(target_tenant)
                content = vault.read_artifact(relative_path)
                digest = 'sha256:' + sha256_hex(content)
                self._record_event(
                    run_id=run_id,
                    event_type=EventType.TEST_DISPATCHED,
                    subject_id=actor.actor_id,
                    payload_digest=digest,
                    metadata={'actor_tenant': actor.tenant.value, 'target_tenant': target_tenant.value, 'artifact_id': art_id, 'action': 'READ_RELEASED', 'decision': 'ALLOWED', 'reason': 'POST_VERIFICATION_RELEASE'},
                )
                return BrokerResponse(success=True, reason_code='RELEASED_ACCESS_GRANTED', content=content, digest=digest)
            except Exception:
                return BrokerResponse(success=False, reason_code='ARTIFACT_NOT_FOUND')
        return BrokerResponse(success=False, reason_code='DENIED_BY_DEFAULT')

    def request_release(self, token: str, run_id: str, artifact_id: str) -> BrokerResponse:
        actor, auth_err = self.authenticate_token(token, target_run_id=run_id)
        if not actor or 'evaluator' not in actor.roles:
            reason = auth_err if not actor else 'UNAUTHORIZED_RELEASE_REQUEST'
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id if actor else 'unknown',
                payload_digest='sha256:empty',
                metadata={'action': 'REQUEST_RELEASE', 'decision': 'DENIED', 'reason': reason},
            )
            return BrokerResponse(success=False, reason_code=reason)
        cur_state = self.get_artifact_release_state(run_id, artifact_id)
        if cur_state == ReleaseState.BLINDED or cur_state == ReleaseState.SEALED:
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'action': 'REQUEST_RELEASE', 'decision': 'DENIED', 'reason': 'PREMATURE_RELEASE_ATTEMPT'},
            )
            return BrokerResponse(success=False, reason_code='PREMATURE_RELEASE_ATTEMPT')
        if cur_state == ReleaseState.REJECTED:
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'action': 'REQUEST_RELEASE', 'decision': 'DENIED', 'reason': 'INVALIDATED_RUN_RELEASE_FORBIDDEN'},
            )
            return BrokerResponse(success=False, reason_code='INVALIDATED_RUN_RELEASE_FORBIDDEN')
        if cur_state == ReleaseState.RELEASED:
            return BrokerResponse(success=True, reason_code='ALREADY_RELEASED')
        if cur_state == ReleaseState.VERIFIED:
            self._release_states[run_id, artifact_id] = ReleaseState.RELEASED
            self._record_event(
                run_id=run_id,
                event_type=EventType.TEST_DISPATCHED,
                subject_id=actor.actor_id,
                payload_digest='sha256:empty',
                metadata={'artifact_id': artifact_id, 'action': 'REQUEST_RELEASE', 'decision': 'ALLOWED', 'reason': 'ARTIFACT_RELEASED'},
            )
            return BrokerResponse(success=True, reason_code='ARTIFACT_RELEASED')
        return BrokerResponse(success=False, reason_code='UNKNOWN_RELEASE_STATE')
