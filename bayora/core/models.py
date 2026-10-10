from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from bayora.core.canonical import canonical_json_bytes
from bayora.core.crypto import sha256_canonical, sha256_hex

class LifecycleState(str, Enum):
    CREATED = 'CREATED'
    SEALED = 'SEALED'
    EXECUTING = 'EXECUTING'
    COMPLETED = 'COMPLETED'
    ABORTED = 'ABORTED'

class Verdict(str, Enum):
    VALID = 'VALID'
    INVALIDATED = 'INVALIDATED'
    INCONCLUSIVE = 'INCONCLUSIVE'
    NOT_EVALUATED = 'NOT_EVALUATED'

class FindingOutcome(str, Enum):
    FINDING = 'FINDING'
    NO_FINDING_IN_TESTED_SCOPE = 'NO_FINDING_IN_TESTED_SCOPE'
    AMBIGUOUS_OR_UNRESOLVED = 'AMBIGUOUS_OR_UNRESOLVED'
    NOT_APPLICABLE = 'NOT_APPLICABLE'

class EventType(str, Enum):
    RUN_INITIALIZED = 'RUN_INITIALIZED'
    SUITE_SEALED = 'SUITE_SEALED'
    DEFENSE_SEALED = 'DEFENSE_SEALED'
    EXECUTION_STARTED = 'EXECUTION_STARTED'
    TEST_DISPATCHED = 'TEST_DISPATCHED'
    TEST_COMPLETED = 'TEST_COMPLETED'
    CANARY_PROBE = 'CANARY_PROBE'
    RESOURCE_CHECK = 'RESOURCE_CHECK'
    EXECUTION_COMPLETED = 'EXECUTION_COMPLETED'
    CHECKPOINT_CREATED = 'CHECKPOINT_CREATED'

class RunManifest(BaseModel):
    run_id: str
    protocol_version: str = '1.0'
    test_suite_digest: str
    defense_digest: str
    model_digest: str
    policy_digest: str
    resource_profile: str = 'standard-profile'
    created_at: str

    def compute_digest(self) -> str:
        return sha256_canonical(self.model_dump())

class AuditEvent(BaseModel):
    run_id: str
    sequence_number: int
    event_type: EventType
    timestamp: str
    subject_id: str
    payload_digest: str = Field(default='sha256:empty')
    metadata: Dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: str
    event_hash: str

    def compute_expected_hash(self) -> str:
        event_dict = self.model_dump(exclude={'event_hash'})
        canonical_bytes = canonical_json_bytes(event_dict)
        return sha256_hex(canonical_bytes + self.previous_event_hash.encode('utf-8'))

class RunCheckpoint(BaseModel):
    run_id: str
    manifest_digest: str
    event_count: int
    final_sequence_number: int
    final_event_hash: str
    created_at: str
    signature_hex: str
    signer_public_key_hex: str

    def canonical_signing_bytes(self) -> bytes:
        data = {'run_id': self.run_id, 'manifest_digest': self.manifest_digest, 'event_count': self.event_count, 'final_sequence_number': self.final_sequence_number, 'final_event_hash': self.final_event_hash, 'created_at': self.created_at}
        return canonical_json_bytes(data)

class EvidenceCapsule(BaseModel):
    manifest: RunManifest
    events: List[AuditEvent]
    checkpoint: RunCheckpoint
    finding_outcome: FindingOutcome = FindingOutcome.NOT_APPLICABLE
    declared_scope: str = 'Adversarial Prompt Injection Scope v1'
