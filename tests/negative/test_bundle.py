"""SR-5 (both signatures required) and SR-18 (prekey expiry)."""

from __future__ import annotations

import dataclasses

import pytest

from pqchat.crypto.sig import HybridSignature
from pqchat.protocol import handshake
from pqchat.protocol.bundle import (
    DAY,
    IdentityKeys,
    IdentityPublic,
    PrekeyBundle,
    PrekeyKind,
    PrekeyStore,
    SignedPrekey,
    sign_prekey,
)
from pqchat.protocol.encoding import ALG_X25519
from pqchat.protocol.errors import ProtocolError, VerificationError
from pqchat.protocol.modes import Mode, Policy
from tests.conftest import NOW, make_store


def _break(sig: HybridSignature, which: str) -> HybridSignature:
    if which == "ed25519":
        return HybridSignature(bytes([sig.ed25519[0] ^ 1]) + sig.ed25519[1:], sig.mldsa65)
    return HybridSignature(sig.ed25519, sig.mldsa65[:-1] + bytes([sig.mldsa65[-1] ^ 1]))


@pytest.mark.parametrize("which", ["ed25519", "mldsa65"])
def test_identity_signature_each_invalid(bob: PrekeyStore, which: str) -> None:
    b = bob.bundle()
    bad_ident = dataclasses.replace(b.identity, dh_signature=_break(b.identity.dh_signature, which))
    with pytest.raises(VerificationError):
        dataclasses.replace(b, identity=bad_ident).verify(Mode.HYBRID, NOW, Policy())


@pytest.mark.parametrize("which", ["ed25519", "mldsa65"])
@pytest.mark.parametrize("field", ["spk", "pqspk", "opk", "pqopk"])
def test_prekey_signature_each_invalid(bob: PrekeyStore, which: str, field: str) -> None:
    b = bob.bundle()
    pk: SignedPrekey = getattr(b, field)
    bad = dataclasses.replace(pk, signature=_break(pk.signature, which))
    with pytest.raises(VerificationError):
        dataclasses.replace(b, **{field: bad}).verify(Mode.HYBRID, NOW, Policy())


def test_classical_mode_checks_only_ed25519(bob: PrekeyStore) -> None:
    """Documents mode semantics: classical ignores ML-DSA, which is why it is not default."""
    b = bob.bundle()
    spk = dataclasses.replace(b.spk, signature=_break(b.spk.signature, "mldsa65"))
    dataclasses.replace(b, spk=spk).verify(Mode.CLASSICAL, NOW, Policy(allow_classical=True))


def test_swapped_prekey_value_is_rejected(bob: PrekeyStore) -> None:
    """Attacker replaces the key inside a signed prekey but keeps the signature."""
    b = bob.bundle()
    mallory_spk = make_store().bundle().spk
    forged = dataclasses.replace(b.spk, public=mallory_spk.public)
    with pytest.raises(VerificationError):
        dataclasses.replace(b, spk=forged).verify(Mode.HYBRID, NOW, Policy())


def test_prekey_signed_by_someone_else(bob: PrekeyStore) -> None:
    mallory = make_store()
    b = dataclasses.replace(bob.bundle(), spk=mallory.bundle().spk)
    with pytest.raises(VerificationError):
        b.verify(Mode.HYBRID, NOW, Policy())


def _bundle_with_spk(store: PrekeyStore, created: int, lifetime: int) -> PrekeyBundle:
    spk = sign_prekey(
        store.identity,
        PrekeyKind.SIGNED,
        7,
        ALG_X25519,
        store.bundle().spk.public,
        created,
        lifetime,
    )
    return dataclasses.replace(store.bundle(), spk=spk)


@pytest.mark.parametrize(
    ("created", "lifetime"),
    [
        (NOW - 8 * DAY, 7 * DAY),  # expired
        (NOW - 7 * DAY, 7 * DAY),  # expires exactly now
        (NOW + 3600, 7 * DAY),  # created in the future beyond skew
        (NOW, 31 * DAY),  # lifetime longer than allowed
        (NOW, 0),  # zero lifetime
    ],
    ids=["expired", "expires-now", "future", "too-long", "zero-life"],
)
def test_prekey_time_checks(bob: PrekeyStore, created: int, lifetime: int) -> None:
    with pytest.raises(VerificationError):
        _bundle_with_spk(bob, created, lifetime).verify(Mode.HYBRID, NOW, Policy())


def test_prekey_within_skew_is_accepted(bob: PrekeyStore) -> None:
    _bundle_with_spk(bob, NOW + 200, 7 * DAY).verify(Mode.HYBRID, NOW, Policy())


def test_initiate_refuses_bad_bundle(alice_identity: IdentityKeys, bob: PrekeyStore) -> None:
    b = bob.bundle()
    bad = dataclasses.replace(b, pqspk=dataclasses.replace(b.pqspk, public=b"\x00" * 1184))  # type: ignore[arg-type]
    with pytest.raises(ProtocolError):
        handshake.initiate(alice_identity, bad, b"x", now=NOW)


def test_responder_rejects_expired_signed_prekey(alice_identity: IdentityKeys) -> None:
    bob = make_store()
    msg, _ = handshake.initiate(alice_identity, bob.bundle(), b"x", now=NOW)
    with pytest.raises(VerificationError):
        handshake.respond(bob, msg, now=NOW + 8 * DAY)


def test_bundle_roundtrip_and_identity_decode(bob: PrekeyStore) -> None:
    b = bob.bundle()
    assert PrekeyBundle.decode(b.encode()) == b
    assert IdentityPublic.decode(b.identity.encode()) == b.identity
    no_ot = bob.bundle(with_one_time=False)
    assert PrekeyBundle.decode(no_ot.encode()) == no_ot


def test_drop_expired_prekeys() -> None:
    store = make_store()
    store.drop_expired(NOW + 61 * DAY)
    assert not store.signed_dh and not store.one_time_dh and not store.one_time_kem


def test_unknown_signed_prekey_ids(bob: PrekeyStore) -> None:
    with pytest.raises(VerificationError):
        bob.signed_dh_key(0xDEAD)
    with pytest.raises(VerificationError):
        bob.kem_key(0xDEAD, one_time=False)
