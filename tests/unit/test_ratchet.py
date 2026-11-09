"""Double ratchet with ML-KEM re-keying: basic behaviour and PQ-step frequency."""

from __future__ import annotations

import pytest

from pqchat.crypto.kem import MLKEMKeyPair
from pqchat.protocol.errors import ParseError, ProtocolError
from pqchat.protocol.pq_ratchet import KemRatchet
from pqchat.protocol.ratchet import Header, Ratchet, parse_message
from tests.conftest import make_pair


def test_long_conversation_roundtrip() -> None:
    alice, bob = make_pair()
    for turn in range(20):
        sender, receiver = (alice, bob) if turn % 2 == 0 else (bob, alice)
        for i in range(3):
            text = f"turn {turn} msg {i}".encode()
            assert receiver.decrypt(sender.encrypt(text)) == text


def test_both_sides_agree_on_safety_number() -> None:
    alice, bob = make_pair()
    assert alice.safety_number() == bob.safety_number()


def test_bob_can_reply_right_after_the_handshake() -> None:
    """Alice's first message carries her first ratchet message, so Bob has a sending chain
    immediately: no second handshake in the other direction (found via the M6 UI run)."""
    from pqchat.protocol.bundle import IdentityKeys
    from pqchat.protocol.session import Session
    from tests.conftest import NOW, make_store

    store = make_store()
    alice, first = Session.initiate(IdentityKeys.generate(), store.bundle(), b"x", now=NOW)
    bob, pt = Session.accept(store, first, now=NOW)
    assert pt == b"x"
    assert alice.decrypt(bob.encrypt(b"immediate reply")) == b"immediate reply"


def test_responder_ratchet_cannot_send_before_receiving() -> None:
    from pqchat.crypto.dh import X25519KeyPair

    bob = Ratchet.init_bob(bytearray(32), b"ad", X25519KeyPair.generate())
    with pytest.raises(ProtocolError):
        bob.encrypt(b"too early")


def _headers(messages: list[bytes]) -> list[Header]:
    return [parse_message(m)[0] for m in messages]


def test_pq_step_every_k_dh_steps() -> None:
    """K = 4: each party re-keys on every 2nd of its own sending chains."""
    alice, bob = make_pair(interval=4)
    ct_chains = {"alice": 0, "bob": 0}
    for turn in range(16):
        sender, receiver, name = (alice, bob, "alice") if turn % 2 == 0 else (bob, alice, "bob")
        msgs = [sender.encrypt(b"m"), sender.encrypt(b"m")]
        hs = _headers(msgs)
        assert hs[0].kem_ct == hs[1].kem_ct  # every message of a re-key chain repeats the CT
        if hs[0].kem_ct:
            ct_chains[name] += 1
        for m in msgs:
            receiver.decrypt(m)
    # 8 chains each; first chain of a party cannot re-key (no peer key yet / count 1).
    assert ct_chains["alice"] >= 3 and ct_chains["bob"] >= 3


def test_kem_announcement_stops_after_ack() -> None:
    alice, bob = make_pair()
    first = _headers([alice.encrypt(b"a")])[0]
    assert first.kem_pub is not None  # Alice announces her ML-KEM ratchet key
    bob.decrypt(alice.encrypt(b"b"))
    reply = bob.encrypt(b"c")
    assert _headers([reply])[0].kem_ack == first.kem_pub[0]
    alice.decrypt(reply)
    assert alice.ratchet.state.kem.announce is False


def test_header_sizes() -> None:
    dh = bytes(32)
    assert len(Header(dh, 0, 0).encode()) == 47
    with_ct = Header(dh, 0, 0, kem_ct=(1, bytes(1088)))
    assert len(with_ct.encode()) == 47 + 4 + 1088
    full = Header(dh, 0, 0, kem_ct=(1, bytes(1088)), kem_pub=(2, bytes(1184)))
    assert len(full.encode()) == 47 + 4 + 1088 + 4 + 1 + 1184


def test_header_parsing_rejects_bad_input() -> None:
    alice, _ = make_pair()
    msg = alice.encrypt(b"x")
    for bad in (b"\x02" + msg[1:], msg[:1] + b"\x80" + msg[2:], msg[:-1], msg + b"\x00"):
        with pytest.raises(ParseError):
            parse_message(bad)


def test_invalid_interval_and_long_message() -> None:
    with pytest.raises(ValueError):
        KemRatchet.create(3)
    with pytest.raises(ValueError):
        KemRatchet.create(0)
    alice, _ = make_pair()
    with pytest.raises(ValueError):
        alice.encrypt(b"x" * (64 * 1024 + 1))


def test_unknown_kem_target_is_rejected() -> None:
    kem = KemRatchet.create(4)
    from pqchat.protocol.errors import VerificationError

    with pytest.raises(VerificationError):
        kem.decapsulate(12345, bytes(1088))


def test_kem_keys_rotate_and_old_ones_are_pruned() -> None:
    kem = KemRatchet.create(4, MLKEMKeyPair.generate)
    from pqchat.crypto.kem import encapsulate

    first = kem.current_id
    for _ in range(3):
        ct, _ = encapsulate(kem.own[kem.current_id].public)
        kem.decapsulate(kem.current_id, ct)
    assert first not in kem.own
    assert len(kem.own) == 2  # current + previous
    assert isinstance(Ratchet, type)
