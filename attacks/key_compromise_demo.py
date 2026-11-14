"""Key-compromise demonstration (A3 + A4): what a thief of Bob's device can and cannot read.

Steps:
1. Alice and Bob chat. Messages 0-2 are delivered.
2. At time t the attacker copies Bob's complete session state (as if from a stolen, unlocked
   device) and from then on records all traffic. Variant "quantum": the attacker also learns every
   new X25519 private key from its public key.
3. The attacker tries to read (a) the messages delivered before t (forward secrecy) and
   (b) every later message (post-compromise security).
Writes evidence/m8/key-compromise.json and prints a table.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from tests.conftest import make_pair  # noqa: E402

from pqchat.crypto.dh import X25519KeyPair  # noqa: E402
from pqchat.protocol.errors import ProtocolError  # noqa: E402
from pqchat.protocol.padding import unpad  # noqa: E402
from pqchat.protocol.ratchet import Ratchet  # noqa: E402


def try_read(shadow: Ratchet, wire: bytes) -> str | None:
    try:
        return unpad(shadow.decrypt(wire)).decode()
    except ProtocolError:
        return None


def run(quantum: bool, interval: int = 8, rounds: int = 8) -> dict:  # type: ignore[type-arg]
    log: list[X25519KeyPair] = []

    def rec() -> X25519KeyPair:
        kp = X25519KeyPair.generate()
        log.append(kp)
        return kp

    alice, bob = make_pair(interval=interval, dh_factory=rec)
    past = [alice.encrypt(f"before theft {i}".encode()) for i in range(3)]
    for m in past:
        bob.decrypt(m)
    state = bob.ratchet.state.clone()  # <- theft at time t
    if quantum:
        cursor = len(log)

        def oracle() -> X25519KeyPair:
            nonlocal cursor
            kp = log[cursor]
            cursor += 1
            return kp

        state.dh_factory = oracle
    shadow = Ratchet(state)
    stolen_copy = Ratchet(bob.ratchet.state.clone())
    fs = {
        f"before theft {i}": try_read(Ratchet(stolen_copy.state.clone()), m) is not None
        for i, m in enumerate(past)
    }
    after = []
    for r in range(rounds):
        m = alice.encrypt(f"after theft, round {r}".encode())
        bob.decrypt(m)
        after.append(try_read(shadow, m) is not None)
        alice.decrypt(bob.encrypt(b"ack"))
    return {
        "attacker": "quantum (all X25519 keys)" if quantum else "classical",
        "K": interval,
        "reads_messages_before_theft": fs,
        "reads_round_after_theft": after,
    }


def main() -> None:
    results = [run(False), run(True)]
    for r in results:
        line = "".join("R" if x else "." for x in r["reads_round_after_theft"])
        print(
            f"{r['attacker']:28s} K={r['K']}  past readable: {any(r['reads_messages_before_theft'].values())}  after theft: {line}"
        )
    (ROOT / "evidence" / "m8" / "key-compromise.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
