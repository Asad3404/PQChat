"""SR-37 and T-09: the session key is bound to the exact prekeys used."""

from __future__ import annotations

import struct

import pytest

from pqchat.protocol import handshake
from pqchat.protocol.bundle import IdentityKeys, PrekeyStore
from pqchat.protocol.errors import ProtocolError, VerificationError
from tests.conftest import NOW, make_store


def test_binding_changes_with_each_prekey(bob: PrekeyStore) -> None:
    b = bob.bundle()
    other = make_store().bundle()
    ref = handshake.prekey_binding(3, b.spk, b.opk, b.pqopk)
    assert handshake.prekey_binding(3, other.spk, b.opk, b.pqopk) != ref
    assert handshake.prekey_binding(3, b.spk, other.opk, b.pqopk) != ref
    assert handshake.prekey_binding(3, b.spk, b.opk, other.pqopk) != ref
    assert handshake.prekey_binding(2, b.spk, None, b.pqopk) != ref


def test_redirect_to_another_valid_kem_prekey(alice_identity: IdentityKeys) -> None:
    """Attacker rewrites the PQ prekey id to another of Bob's real keys: must fail."""
    bob = make_store(one_time=3)
    bundle = bob.bundle()
    msg, _ = handshake.initiate(alice_identity, bundle, b"x", now=NOW)
    header, _, _ = handshake.parse_initial(msg)
    other_id = next(k for k in bob.one_time_kem if k != header.pq_id)
    old, new = struct.pack(">I", header.pq_id), struct.pack(">I", other_id)  # type: ignore[arg-type]
    assert msg.count(old) == 1
    with pytest.raises(ProtocolError):
        handshake.respond(bob, msg.replace(old, new), now=NOW)


def test_forged_message_does_not_burn_one_time_prekeys(
    alice_identity: IdentityKeys, bob: PrekeyStore
) -> None:
    bundle = bob.bundle()
    msg, _ = handshake.initiate(alice_identity, bundle, b"x", now=NOW)
    forged = msg[:-1] + bytes([msg[-1] ^ 1])
    with pytest.raises(VerificationError):
        handshake.respond(bob, forged, now=NOW)
    assert bundle.opk.key_id in bob.one_time_dh  # type: ignore[union-attr]
    assert handshake.respond(bob, msg, now=NOW).plaintext == b"x"
