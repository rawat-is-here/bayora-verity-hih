from __future__ import annotations
import os
from enum import Enum
from pathlib import Path
from typing import Optional
from bayora.core.crypto import sha256_hex

class TenantId(str, Enum):
    RED = 'red'
    BLUE = 'blue'
    MODEL = 'model'
    SYSTEM = 'system'

class StoredArtifact:

    def __init__(self, artifact_id: str, tenant_id: TenantId, digest: str, content_bytes: bytes, relative_path: str) -> None:
        self.artifact_id = artifact_id
        self.tenant_id = tenant_id
        self.digest = digest
        self.content_bytes = content_bytes
        self.relative_path = relative_path

class TenantVault:

    def __init__(self, tenant_id: TenantId, base_dir: Path | str) -> None:
        self.tenant_id = tenant_id
        self.vault_root = (Path(base_dir) / tenant_id.value).resolve()
        self.vault_root.mkdir(parents=True, exist_ok=True)

    def _resolve_safe_path(self, relative_path: str) -> Path:
        if '..' in relative_path or relative_path.startswith(('/', '\\')):
            raise PermissionError(f"Path traversal detected in '{relative_path}'")
        raw_path = self.vault_root / relative_path
        curr = raw_path
        while curr != self.vault_root and curr != curr.parent:
            if curr.is_symlink():
                raise PermissionError(f"Symlink traversal detected in '{relative_path}'")
            curr = curr.parent
        target_path = raw_path.resolve()
        try:
            target_path.relative_to(self.vault_root)
        except ValueError:
            raise PermissionError(f"Path traversal attempt outside vault root: '{relative_path}'")
        return target_path

    def store_artifact(self, artifact_id: str, content: bytes | str, relative_path: Optional[str] = None) -> StoredArtifact:
        raw = content.encode('utf-8') if isinstance(content, str) else content
        path = relative_path or f'{artifact_id}.bin'
        target = self._resolve_safe_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.parent.resolve().relative_to(self.vault_root)
        except ValueError:
            raise PermissionError(f"Parent directory replacement race detected: '{path}'")
        target.write_bytes(raw)
        digest = 'sha256:' + sha256_hex(raw)
        return StoredArtifact(artifact_id=artifact_id, tenant_id=self.tenant_id, digest=digest, content_bytes=raw, relative_path=path)

    def read_artifact(self, relative_path: str) -> bytes:
        target = self._resolve_safe_path(relative_path)
        if not target.exists() or not target.is_file():
            raise FileNotFoundError(f"Artifact not found: '{relative_path}'")
        real_path = target.resolve()
        try:
            real_path.relative_to(self.vault_root)
        except ValueError:
            raise PermissionError(f"Path replacement race detected outside vault root: '{relative_path}'")
        if real_path.is_symlink():
            raise PermissionError(f"Symlink race detected in '{relative_path}'")
        return target.read_bytes()

    def has_artifact(self, relative_path: str) -> bool:
        try:
            target = self._resolve_safe_path(relative_path)
            return target.exists() and target.is_file()
        except PermissionError:
            return False

class MultiTenantStorage:

    def __init__(self, storage_root: Path | str) -> None:
        self.storage_root = Path(storage_root).resolve()
        self.storage_root.mkdir(parents=True, exist_ok=True)
        self.vaults: dict[TenantId, TenantVault] = {t: TenantVault(t, self.storage_root) for t in TenantId}

    def get_vault(self, tenant_id: TenantId) -> TenantVault:
        return self.vaults[tenant_id]
