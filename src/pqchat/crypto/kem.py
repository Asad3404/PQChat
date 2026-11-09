"""ML-KEM-768 (FIPS 203) via liboqs-python."""

from __future__ import annotations

import oqs

from pqchat.crypto.errors import CryptoError

ALG = "ML-KEM-768"
PUBLIC_KEY_LEN = 1184
SECRET_KEY_LEN = 2400
CIPHERTEXT_LEN = 1088
SHARED_SECRET_LEN = 32
SEED_LEN = 64


def _check_len(data: bytes, expected: int, name: str) -> None:
    if len(data) != expected:
        raise CryptoError(f"{name} must be {expected} bytes")


class MLKEMKeyPair:
    """Decapsulation key plus its public encapsulation key."""

    __slots__ = ("_secret", "public")

    def __init__(self, public: bytes, secret: bytes) -> None:
        _check_len(public, PUBLIC_KEY_LEN, "ML-KEM public key")
        _check_len(secret, SECRET_KEY_LEN, "ML-KEM secret key")
        self.public = bytes(public)
        self._secret = bytearray(secret)

    @classmethod
    def generate(cls) -> MLKEMKeyPair:
        with oqs.KeyEncapsulation(ALG) as kem:
            public = kem.generate_keypair()
            return cls(public, kem.export_secret_key())

    @classmethod
    def from_seed(cls, seed: bytes) -> MLKEMKeyPair:
        """Deterministic key generation from the 64-byte seed d || z (FIPS 203 §7.1)."""
        _check_len(seed, SEED_LEN, "ML-KEM seed")
        with oqs.KeyEncapsulation(ALG) as kem:
            public = kem.generate_keypair_seed(bytes(seed))
            return cls(public, kem.export_secret_key())

    def secret_bytes(self) -> bytearray:
        return bytearray(self._secret)

    def decapsulate(self, ciphertext: bytes) -> bytearray:
        """Return the shared secret. A tampered ciphertext gives a *different* secret
        (implicit rejection); it never raises, so callers must authenticate the result."""
        _check_len(ciphertext, CIPHERTEXT_LEN, "ML-KEM ciphertext")
        with oqs.KeyEncapsulation(ALG, bytes(self._secret)) as kem:
            return bytearray(kem.decap_secret(bytes(ciphertext)))

    def wipe(self) -> None:
        self._secret[:] = bytes(len(self._secret))


def encapsulate(public_key: bytes) -> tuple[bytes, bytearray]:
    """Return (ciphertext, shared_secret) for the given public key."""
    _check_len(public_key, PUBLIC_KEY_LEN, "ML-KEM public key")
    with oqs.KeyEncapsulation(ALG) as kem:
        try:
            ciphertext, shared = kem.encap_secret(bytes(public_key))
        except RuntimeError as exc:  # FIPS 203 encapsulation-key check failed
            raise CryptoError("invalid ML-KEM public key") from exc
    return bytes(ciphertext), bytearray(shared)
