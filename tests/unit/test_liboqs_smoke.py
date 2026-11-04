"""Milestone 0 smoke tests: is liboqs installed correctly and does it behave as FIPS 203/204 say?

These are *installation* tests, not the full vector suite (that is Milestone 2).
"""

from __future__ import annotations

import hmac

import oqs
import pytest

from pqchat import selftest

# Sizes in bytes from FIPS 203 Table 3 (ML-KEM-768) and FIPS 204 Table 2 (ML-DSA-65).
MLKEM768_EK = 1184
MLKEM768_DK = 2400
MLKEM768_CT = 1088
MLKEM768_SS = 32
MLDSA65_PK = 1952
MLDSA65_SK = 4032
MLDSA65_SIG = 3309


def test_liboqs_version_is_pinned() -> None:
    assert oqs.oqs_version() == selftest.EXPECTED_LIBOQS_VERSION


def test_only_required_algorithms_are_enabled() -> None:
    """The minimal build (ADR-001) must contain exactly the two algorithms we use."""
    assert oqs.get_enabled_kem_mechanisms() == ("ML-KEM-768",)
    assert oqs.get_enabled_sig_mechanisms() == ("ML-DSA-65",)


def test_mlkem768_roundtrip() -> None:
    with oqs.KeyEncapsulation("ML-KEM-768") as bob:
        ek = bob.generate_keypair()
        dk = bob.export_secret_key()
        with oqs.KeyEncapsulation("ML-KEM-768") as alice:
            ct, ss_alice = alice.encap_secret(ek)
        ss_bob = bob.decap_secret(ct)

    assert len(ek) == MLKEM768_EK
    assert len(dk) == MLKEM768_DK
    assert len(ct) == MLKEM768_CT
    assert len(ss_alice) == MLKEM768_SS
    assert hmac.compare_digest(ss_alice, ss_bob)


def test_mlkem768_encapsulation_is_randomised() -> None:
    """Two encapsulations to the same key must give different ciphertexts and secrets."""
    with oqs.KeyEncapsulation("ML-KEM-768") as bob:
        ek = bob.generate_keypair()
    with oqs.KeyEncapsulation("ML-KEM-768") as alice:
        ct1, ss1 = alice.encap_secret(ek)
        ct2, ss2 = alice.encap_secret(ek)
    assert ct1 != ct2
    assert ss1 != ss2


def test_mlkem768_implicit_rejection_on_tampered_ciphertext() -> None:
    """ML-KEM never raises on a bad ciphertext: it returns a pseudo-random secret.

    So a tampered CT is only detected later, when the AEAD tag fails. The handshake
    (Milestone 3) must therefore always authenticate CT through the AEAD.
    """
    with oqs.KeyEncapsulation("ML-KEM-768") as bob:
        ek = bob.generate_keypair()
        with oqs.KeyEncapsulation("ML-KEM-768") as alice:
            ct, ss_alice = alice.encap_secret(ek)
        tampered = bytearray(ct)
        tampered[0] ^= 0x01
        ss_bob = bob.decap_secret(bytes(tampered))
    assert len(ss_bob) == MLKEM768_SS
    assert not hmac.compare_digest(ss_alice, ss_bob)


def test_mlkem768_rejects_wrong_length_public_key() -> None:
    with oqs.KeyEncapsulation("ML-KEM-768") as alice, pytest.raises(Exception):  # noqa: B017
        alice.encap_secret(b"\x00" * (MLKEM768_EK - 1))


def test_mldsa65_sign_verify() -> None:
    msg = b"bundle bytes"
    with oqs.Signature("ML-DSA-65") as signer:
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
        sig = signer.sign(msg)
    assert (len(pk), len(sk), len(sig)) == (MLDSA65_PK, MLDSA65_SK, MLDSA65_SIG)

    with oqs.Signature("ML-DSA-65") as verifier:
        assert verifier.verify(msg, sig, pk)
        assert not verifier.verify(msg + b"x", sig, pk)
        bad_sig = bytearray(sig)
        bad_sig[10] ^= 0x80
        assert not verifier.verify(msg, bytes(bad_sig), pk)


def test_selftest_passes_and_prints_no_secrets(capsys: pytest.CaptureFixture[str]) -> None:
    assert selftest.main() == 0
    out = capsys.readouterr().out
    assert "ML-KEM-768 OK" in out
    assert "ML-DSA-65 OK" in out
    # Output is a single short status line: no key or secret material can hide in it.
    assert len(out.strip().splitlines()) == 1
    assert len(out) < 120
