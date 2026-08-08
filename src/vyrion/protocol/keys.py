"""Signing and verification keys with an explicit trust boundary.

The broker holds an Ed25519Signer (private key). The runtime holds only a KeyRing
of public verifiers keyed by key_id, and can revoke a key_id. The runtime cannot
issue events. Falls back to a pure-python Ed25519 only if cryptography is absent,
but the default is the vetted library.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False


class Ed25519Signer:
    """Private signing capability. Lives in the broker only."""

    def __init__(self, key_id: str = "key-1", _priv=None):
        if not _HAVE_CRYPTO:
            raise RuntimeError("cryptography library required for signing")
        self.key_id = key_id
        self._priv = _priv or Ed25519PrivateKey.generate()

    def sign(self, payload: bytes) -> str:
        return self._priv.sign(payload).hex()

    def verifier(self) -> "Ed25519Verifier":
        return Ed25519Verifier(self.key_id, self._priv.public_key())

    def public_pem(self) -> bytes:
        return self._priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def private_pem(self) -> bytes:
        return self._priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())

    @staticmethod
    def from_private_pem(key_id: str, pem: bytes) -> "Ed25519Signer":
        priv = serialization.load_pem_private_key(pem, password=None)
        return Ed25519Signer(key_id=key_id, _priv=priv)


class Ed25519Verifier:
    """Public verification only. Safe to hold in the runtime guard."""

    def __init__(self, key_id: str, pub: "Ed25519PublicKey"):
        self.key_id = key_id
        self._pub = pub

    def verify(self, payload: bytes, signature_hex: str) -> bool:
        try:
            self._pub.verify(bytes.fromhex(signature_hex), payload)
            return True
        except (InvalidSignature, ValueError):
            return False

    @staticmethod
    def from_pem(key_id: str, pem: bytes) -> "Ed25519Verifier":
        pub = serialization.load_pem_public_key(pem)
        return Ed25519Verifier(key_id, pub)


@dataclass
class KeyRing:
    """The runtime's set of trusted public keys, with revocation."""
    verifiers: dict = field(default_factory=dict)
    revoked: set = field(default_factory=set)

    def trust(self, verifier: Ed25519Verifier) -> None:
        self.verifiers[verifier.key_id] = verifier

    def revoke(self, key_id: str) -> None:
        self.revoked.add(key_id)

    def get(self, key_id: str) -> Optional[Ed25519Verifier]:
        if key_id in self.revoked:
            return None
        return self.verifiers.get(key_id)


def new_keypair(key_id: str = "key-1") -> Ed25519Signer:
    return Ed25519Signer(key_id=key_id)
