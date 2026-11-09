"""Behaviour of each wrapper in pqchat.crypto, including every rejection path."""

from __future__ import annotations

import os

import pytest

from pqchat.crypto import aead, kdf, kem, labels, sig
from pqchat.crypto.dh import X25519KeyPair
from pqchat.crypto.errors import CryptoError
from pqchat.crypto.zeroize import wipe


# ------------------------------------------------------------------ X25519
def test_x25519_roundtrip_and_private_export() -> None:
    a, b = X25519KeyPair.generate(), X25519KeyPair.generate()
    assert a.dh(b.public) == b.dh(a.public)
    again = X25519KeyPair.from_private_bytes(bytes(a.private_bytes()))
    assert again.public == a.public


@pytest.mark.parametrize("n", [0, 31, 33])
def test_x25519_rejects_wrong_lengths(n: int) -> None:
    with pytest.raises(CryptoError):
        X25519KeyPair.generate().dh(b"\x01" * n)
    with pytest.raises(CryptoError):
        X25519KeyPair.from_private_bytes(b"\x01" * n)


def test_x25519_rejects_low_order_point() -> None:
    """u = 0 is a low-order point: the shared secret would be all zeros."""
    with pytest.raises(CryptoError):
        X25519KeyPair.generate().dh(bytes(32))


# ------------------------------------------------------------------ ML-KEM-768
def test_mlkem_roundtrip_and_wipe() -> None:
    kp = kem.MLKEMKeyPair.generate()
    ct, ss = kem.encapsulate(kp.public)
    assert kp.decapsulate(ct) == ss
    kp.wipe()
    assert kp.secret_bytes() == bytes(kem.SECRET_KEY_LEN)


def test_mlkem_length_checks() -> None:
    kp = kem.MLKEMKeyPair.generate()
    with pytest.raises(CryptoError):
        kem.encapsulate(kp.public[:-1])
    with pytest.raises(CryptoError):
        kp.decapsulate(b"\x00" * (kem.CIPHERTEXT_LEN + 1))
    with pytest.raises(CryptoError):
        kem.MLKEMKeyPair.from_seed(b"\x00" * 63)
    with pytest.raises(CryptoError):
        kem.MLKEMKeyPair(kp.public, b"\x00" * 10)


# ------------------------------------------------------------------ signatures
@pytest.fixture(scope="module")
def signer() -> sig.HybridSigningKey:
    return sig.HybridSigningKey.generate()


def test_hybrid_sign_verify(signer: sig.HybridSigningKey) -> None:
    s = signer.sign(labels.SIG_PREKEY, b"prekey bytes")
    assert len(s.ed25519) == sig.ED_SIG_LEN and len(s.mldsa65) == sig.MLDSA_SIG_LEN
    assert sig.verify_hybrid(signer.public, s, labels.SIG_PREKEY, b"prekey bytes")


def test_hybrid_rejects_if_either_signature_is_bad(signer: sig.HybridSigningKey) -> None:
    good = signer.sign(labels.SIG_PREKEY, b"m")
    bad_ed = sig.HybridSignature(bytes(64), good.mldsa65)
    bad_pq = sig.HybridSignature(good.ed25519, bytes(sig.MLDSA_SIG_LEN))
    assert not sig.verify_hybrid(signer.public, bad_ed, labels.SIG_PREKEY, b"m")
    assert not sig.verify_hybrid(signer.public, bad_pq, labels.SIG_PREKEY, b"m")


def test_signatures_are_bound_to_their_label(signer: sig.HybridSigningKey) -> None:
    """A prekey signature cannot be reused as, e.g., a relay-auth signature."""
    s = signer.sign(labels.SIG_PREKEY, b"m")
    assert not sig.verify_hybrid(signer.public, s, labels.SIG_RELAY_AUTH, b"m")


def test_signature_wrong_lengths_and_unknown_label(signer: sig.HybridSigningKey) -> None:
    s = signer.sign(labels.SIG_PREKEY, b"m")
    assert not sig.ed25519_verify(signer.public.ed25519[:31], s.ed25519, labels.SIG_PREKEY, b"m")
    assert not sig.mldsa_verify(signer.public.mldsa65, s.mldsa65[:-1], labels.SIG_PREKEY, b"m")
    assert not sig.ed25519_verify(bytes(32), s.ed25519, labels.SIG_PREKEY, b"m")
    with pytest.raises(CryptoError):
        signer.sign(b"not a registered label", b"m")
    with pytest.raises(CryptoError):
        sig.HybridPublicKey(b"\x00" * 31, signer.public.mldsa65)


def test_signing_key_export_reimport(signer: sig.HybridSigningKey) -> None:
    ed, pq = signer.private_parts()
    again = sig.HybridSigningKey(bytes(ed), signer.public.mldsa65, bytes(pq))
    assert again.public == signer.public
    s = again.sign(labels.SIG_PREKEY, b"x")
    assert sig.verify_hybrid(signer.public, s, labels.SIG_PREKEY, b"x")


# ------------------------------------------------------------------ KDF / HMAC
def test_hkdf_rejects_bad_length() -> None:
    for n in (0, kdf.MAX_OKM + 1):
        with pytest.raises(CryptoError):
            kdf.hkdf(b"k", b"", labels.HANDSHAKE_SPLIT, n)


def test_verify_hmac_rejects_wrong_tag() -> None:
    tag = kdf.hmac_sha256(b"key", b"data")
    assert kdf.verify_hmac(b"key", b"data", bytes(tag))
    bad = bytearray(tag)
    bad[0] ^= 1
    assert not kdf.verify_hmac(b"key", b"data", bytes(bad))


# ------------------------------------------------------------------ AEAD
def test_aead_detects_any_tampering() -> None:
    key, nonce = os.urandom(32), os.urandom(12)
    ct = aead.seal(key, nonce, b"hello", b"ad")
    for mutated in (ct[:-1] + bytes([ct[-1] ^ 1]), bytes([ct[0] ^ 1]) + ct[1:]):
        with pytest.raises(CryptoError):
            aead.open_(key, nonce, mutated, b"ad")
    with pytest.raises(CryptoError):
        aead.open_(key, nonce, ct, b"other ad")
    with pytest.raises(CryptoError):
        aead.open_(key, nonce, ct[:15], b"ad")


def test_aead_rejects_bad_key_or_nonce_length() -> None:
    with pytest.raises(CryptoError):
        aead.seal(b"k" * 16, b"n" * 12, b"", b"")
    with pytest.raises(CryptoError):
        aead.seal(b"k" * 32, b"n" * 8, b"", b"")


# ------------------------------------------------------------------ zeroize
def test_wipe_zeroes_buffers_and_ignores_none() -> None:
    a, b = bytearray(b"secret"), bytearray(b"other")
    wipe(a, None, b)
    assert a == bytes(6) and b == bytes(5)
