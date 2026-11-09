"""Ed25519 (RFC 8032) and ML-DSA-65 (FIPS 204) signatures, and the hybrid pair.

Domain separation: every signature covers ``label || message``; for ML-DSA the label is also
the FIPS 204 context string. A label from :mod:`pqchat.crypto.labels` is mandatory, so a
signature made for one purpose can never be replayed for another.
"""

from __future__ import annotations

from dataclasses import dataclass

import oqs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from pqchat.crypto.errors import CryptoError
from pqchat.crypto.labels import ALL as _LABELS

MLDSA_ALG = "ML-DSA-65"
ED_PUBLIC_LEN = 32
ED_PRIVATE_LEN = 32
ED_SIG_LEN = 64
MLDSA_PUBLIC_LEN = 1952
MLDSA_SECRET_LEN = 4032
MLDSA_SIG_LEN = 3309


def _check_label(label: bytes) -> None:
    if label not in _LABELS:
        raise CryptoError("unknown signature label")


def _check_len(data: bytes, expected: int, name: str) -> None:
    if len(data) != expected:
        raise CryptoError(f"{name} must be {expected} bytes")


# ----------------------------------------------------------------------------- Ed25519
def ed25519_verify(public_key: bytes, signature: bytes, label: bytes, message: bytes) -> bool:
    _check_label(label)
    if len(public_key) != ED_PUBLIC_LEN or len(signature) != ED_SIG_LEN:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(
            bytes(signature), label + bytes(message)
        )
    except (InvalidSignature, ValueError):
        return False
    return True


# ----------------------------------------------------------------------------- ML-DSA-65
def mldsa_verify(public_key: bytes, signature: bytes, label: bytes, message: bytes) -> bool:
    _check_label(label)
    if len(public_key) != MLDSA_PUBLIC_LEN or len(signature) != MLDSA_SIG_LEN:
        return False
    with oqs.Signature(MLDSA_ALG) as verifier:
        return bool(
            verifier.verify_with_ctx_str(
                label + bytes(message), bytes(signature), label, bytes(public_key)
            )
        )


# ----------------------------------------------------------------------------- hybrid
@dataclass(frozen=True)
class HybridSignature:
    ed25519: bytes
    mldsa65: bytes


@dataclass(frozen=True)
class HybridPublicKey:
    ed25519: bytes
    mldsa65: bytes

    def __post_init__(self) -> None:
        _check_len(self.ed25519, ED_PUBLIC_LEN, "Ed25519 public key")
        _check_len(self.mldsa65, MLDSA_PUBLIC_LEN, "ML-DSA-65 public key")


class HybridSigningKey:
    """Ed25519 + ML-DSA-65 identity signing keys (IKsig-ed, IKsig-pq)."""

    __slots__ = ("_ed", "_pq_secret", "public")

    def __init__(self, ed_private: bytes, pq_public: bytes, pq_secret: bytes) -> None:
        _check_len(ed_private, ED_PRIVATE_LEN, "Ed25519 private key")
        _check_len(pq_secret, MLDSA_SECRET_LEN, "ML-DSA-65 secret key")
        self._ed = Ed25519PrivateKey.from_private_bytes(bytes(ed_private))
        self._pq_secret = bytearray(pq_secret)
        self.public = HybridPublicKey(
            self._ed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), bytes(pq_public)
        )

    @classmethod
    def generate(cls) -> HybridSigningKey:
        ed = Ed25519PrivateKey.generate().private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        with oqs.Signature(MLDSA_ALG) as signer:
            pq_public = signer.generate_keypair()
            pq_secret = signer.export_secret_key()
        return cls(ed, pq_public, pq_secret)

    def private_parts(self) -> tuple[bytearray, bytearray]:
        """(Ed25519 private key, ML-DSA-65 secret key), for the encrypted key store."""
        ed = self._ed.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return bytearray(ed), bytearray(self._pq_secret)

    def sign_ed25519(self, label: bytes, message: bytes) -> bytes:
        _check_label(label)
        return self._ed.sign(label + bytes(message))

    def sign_mldsa(self, label: bytes, message: bytes) -> bytes:
        _check_label(label)
        with oqs.Signature(MLDSA_ALG, bytes(self._pq_secret)) as signer:
            return bytes(signer.sign_with_ctx_str(label + bytes(message), label))

    def sign(self, label: bytes, message: bytes) -> HybridSignature:
        return HybridSignature(self.sign_ed25519(label, message), self.sign_mldsa(label, message))


def verify_hybrid(
    public: HybridPublicKey, signature: HybridSignature, label: bytes, message: bytes
) -> bool:
    """True only if **both** signatures verify (SR-5). Both are always evaluated."""
    ed_ok = ed25519_verify(public.ed25519, signature.ed25519, label, message)
    pq_ok = mldsa_verify(public.mldsa65, signature.mldsa65, label, message)
    return ed_ok and pq_ok
