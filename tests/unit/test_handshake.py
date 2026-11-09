"""M3 "done when": Alice and Bob derive the same key, in every mode (SR-4)."""

from __future__ import annotations

import pytest

from pqchat.crypto.kem import MLKEMKeyPair, encapsulate
from pqchat.protocol import handshake
from pqchat.protocol.bundle import IdentityKeys, PrekeyStore
from pqchat.protocol.modes import Mode, Policy
from tests.conftest import NOW, make_store

ALL_MODES = Policy(allow_classical=True, allow_pq_only=True)


@pytest.mark.parametrize("mode", list(Mode))
@pytest.mark.parametrize("one_time", [True, False], ids=["with-OPK", "last-resort"])
def test_both_sides_derive_same_keys(
    alice_identity: IdentityKeys, mode: Mode, one_time: bool
) -> None:
    bob = make_store()
    bundle = bob.bundle(with_one_time=one_time)
    msg, a = handshake.initiate(
        alice_identity, bundle, b"hi Bob", mode=mode, policy=ALL_MODES, now=NOW
    )
    b = handshake.respond(bob, msg, policy=ALL_MODES, now=NOW)
    assert b.plaintext == b"hi Bob"
    assert a.root_key == b.root_key and len(a.root_key) == 32
    assert a.associated_data == b.associated_data
    assert a.mode == b.mode == mode
    assert b.peer == alice_identity.public and a.peer == bob.identity.public
    assert a.peer_ratchet_public == b.own_ratchet_keypair.public  # type: ignore[union-attr]


def test_hybrid_is_default(alice_identity: IdentityKeys, bob: PrekeyStore) -> None:
    msg, a = handshake.initiate(alice_identity, bob.bundle(), b"x", now=NOW)
    assert a.mode is Mode.HYBRID and msg[1] == Mode.HYBRID


def test_one_time_prekeys_are_deleted_after_use(
    alice_identity: IdentityKeys, bob: PrekeyStore
) -> None:
    bundle = bob.bundle()
    assert bundle.opk and bundle.pqopk
    msg, _ = handshake.initiate(alice_identity, bundle, b"x", now=NOW)
    handshake.respond(bob, msg, now=NOW)
    assert bundle.opk.key_id not in bob.one_time_dh
    assert bundle.pqopk.key_id not in bob.one_time_kem
    assert bundle.spk.key_id in bob.signed_dh  # signed prekeys stay


def test_sk_depends_on_every_input() -> None:
    """SR-4: changing any single DH output or the KEM secret changes both derived keys."""
    base = [bytearray(bytes([i]) * 32) for i in range(1, 5)]
    ss = bytearray(b"\x09" * 32)

    def derive(dhs: list[bytearray], s: bytearray | None) -> bytes:
        k, rk = handshake._derive(
            Mode.HYBRID, [bytearray(d) for d in dhs], bytearray(s) if s else None
        )
        return bytes(k + rk)

    reference = derive(base, ss)
    for i in range(4):
        changed = [bytearray(d) for d in base]
        changed[i][0] ^= 1
        assert derive(changed, ss) != reference
    assert derive(base, bytearray(b"\x0a" * 32)) != reference
    assert derive(base, None) != reference  # dropping the KEM secret changes the key


def test_modes_use_distinct_kdf_labels() -> None:
    dhs = [bytearray(32)] * 3
    keys = {bytes(handshake._derive(m, [bytearray(d) for d in dhs], None)[1]) for m in Mode}
    assert len(keys) == 3


def test_derive_wipes_intermediate_secrets() -> None:
    """SR-15: DH outputs and the KEM secret are zeroed once the keys exist."""
    dhs = [bytearray(b"\x01" * 32), bytearray(b"\x02" * 32)]
    ss = bytearray(b"\x03" * 32)
    handshake._derive(Mode.HYBRID, dhs, ss)
    assert all(d == bytes(32) for d in dhs) and ss == bytes(32)


def test_replay_cache_purges_old_entries() -> None:
    cache = handshake.ReplayCache()
    d = cache.check(b"header")
    cache.add(d, NOW)
    cache.purge(NOW + 31 * 86400)
    assert not cache.seen


def test_first_message_size_limit(alice_identity: IdentityKeys, bob: PrekeyStore) -> None:
    with pytest.raises(ValueError):
        handshake.initiate(
            alice_identity, bob.bundle(), b"x" * (handshake.MAX_FIRST_PLAINTEXT + 1), now=NOW
        )


def test_initial_message_sizes(alice_identity: IdentityKeys) -> None:
    """Record sizes for the protocol spec and M11 benchmarks (empty plaintext)."""
    sizes = {}
    for mode in Mode:
        msg, _ = handshake.initiate(
            alice_identity, make_store().bundle(), b"", mode=mode, policy=ALL_MODES, now=NOW
        )
        sizes[mode.name] = len(msg)
    assert sizes["CLASSICAL"] < sizes["HYBRID"]
    assert sizes["HYBRID"] == sizes["CLASSICAL"] + 4 + 1088 + 0  # pq_id + CT
    kp = MLKEMKeyPair.generate()
    assert len(encapsulate(kp.public)[0]) == 1088
