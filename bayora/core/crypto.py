from __future__ import annotations
import hashlib
from typing import Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from bayora.core.canonical import canonical_json_bytes

def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def sha256_canonical(obj: Any) -> str:
    return sha256_hex(canonical_json_bytes(obj))

class Ed25519Signer:

    def __init__(self, private_key: ed25519.Ed25519PrivateKey | None=None) -> None:
        self._private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

    @classmethod
    def generate(cls) -> Ed25519Signer:
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw_bytes: bytes) -> Ed25519Signer:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)
        return cls(private_key)

    @property
    def private_bytes(self) -> bytes:
        return self._private_key.private_bytes_raw()

    @property
    def public_bytes(self) -> bytes:
        return self._public_key.public_bytes_raw()

    @property
    def public_key_hex(self) -> str:
        return self.public_bytes.hex()

    def sign(self, message: bytes) -> str:
        sig = self._private_key.sign(message)
        return sig.hex()

def verify_ed25519_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        public_key.verify(sig_bytes, message)
        return True
    except (InvalidSignature, ValueError):
        return False
