"""SR-14 post-compromise security, against a classical and against a quantum attacker.

The attacker copies Bob's whole state at time t (A3) and then sees every message (A1). It keeps
a *shadow* ratchet that processes the same messages as Bob and tries to decrypt Alice's messages.

* Classical attacker: cannot learn Bob's new DH private keys -> loses access after one round trip.
* Quantum attacker (A4): learns every new X25519 private key from its public key (modelled by
  handing the shadow Bob's actual future DH key pairs), but cannot break ML-KEM -> keeps access
  across DH steps, and loses it only once a fresh ML-KEM secret enters the root chain.
"""

from __future__ import annotations

import pytest

from pqchat.crypto.dh import X25519KeyPair
from pqchat.protocol.errors import ProtocolError
from pqchat.protocol.ratchet import Ratchet
from pqchat.protocol.session import Session
from tests.conftest import make_pair


def _can_read(shadow: Ratchet, message: bytes) -> bool:
    try:
        shadow.decrypt(message)
    except ProtocolError:
        return False
    return True


def _exchange(alice: Session, bob: Session, shadow: Ratchet, rounds: int) -> list[bool]:
    """Each round: Alice sends 1 message (shadow tries it), Bob replies."""
    readable = []
    for r in range(rounds):
        m = alice.encrypt(f"secret {r}".encode())
        bob.decrypt(m)
        readable.append(_can_read(shadow, m))
        alice.decrypt(bob.encrypt(b"ack"))
    return readable


def test_classical_attacker_loses_access_after_one_round_trip() -> None:
    alice, bob = make_pair()
    bob.decrypt(alice.encrypt(b"before"))
    shadow = Ratchet(bob.ratchet.state.clone())
    readable = _exchange(alice, bob, shadow, rounds=4)
    # Round 0: same chain as before the theft.
    # Round 1: still readable, because Bob generated his next sending key DHs_B1 while
    #          processing "before", i.e. *before* the theft, so the stolen state contains it.
    # Round 2+: Bob has now sent with a key created after the theft and Alice answered:
    #          the attacker cannot compute that DH output, so the session has healed.
    assert readable == [True, True, False, False]


def _quantum_shadow_run(interval: int, rounds: int) -> list[bool]:
    generated: list[X25519KeyPair] = []

    def recording_factory() -> X25519KeyPair:
        kp = X25519KeyPair.generate()
        generated.append(kp)
        return kp

    alice, bob = make_pair(interval=interval, dh_factory=recording_factory)
    bob.decrypt(alice.encrypt(b"before"))
    cursor = len(generated)

    def quantum_factory() -> X25519KeyPair:
        # The quantum attacker recovers each new DH private key from its public key.
        nonlocal cursor
        kp = generated[cursor]
        cursor += 1
        return kp

    state = bob.ratchet.state.clone()
    state.dh_factory = quantum_factory
    return _exchange(alice, bob, Ratchet(state), rounds)


@pytest.mark.parametrize("interval", [4, 8, 12])
def test_quantum_attacker_keeps_access_until_mlkem_step(interval: int) -> None:
    """Healing against A4 happens only at the ML-KEM step: after K/2 round trips.

    Classical attackers are locked out after 2 rounds whatever K is (test above); a quantum
    attacker stays in for max(2, K/2) rounds. With K = 4 the two coincide, which is why the
    larger K values are what actually separates DH healing from ML-KEM healing.
    """
    readable = _quantum_shadow_run(interval, rounds=10)
    keeps = max(2, interval // 2)
    assert readable == [True] * keeps + [False] * (10 - keeps)
