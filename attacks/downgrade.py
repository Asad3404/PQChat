"""Downgrade attacks (SR-6, T-04). Writes evidence/m8/downgrade-results.json.

1. Malicious relay deletes Bob's ML-KEM prekeys from its database: Alice must refuse to start a
   classical-only session.
2. Network attacker rewrites the mode byte of Alice's initial message from hybrid (2) to
   classical (1), with and without fixing the suite bytes: Bob must reject both, even when Bob's
   policy would allow classical sessions.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from pqchat.protocol import handshake  # noqa: E402
from pqchat.protocol.bundle import IdentityKeys, PrekeyBundle, PrekeyStore  # noqa: E402
from pqchat.protocol.errors import ProtocolError  # noqa: E402
from pqchat.protocol.modes import Mode, Policy  # noqa: E402


def main() -> None:
    now = int(time.time())
    bob = PrekeyStore(IdentityKeys.generate())
    bob.rotate_signed(now)
    bob.add_one_time(2, now)
    alice = IdentityKeys.generate()
    results = {}

    stripped = PrekeyBundle(
        bob.bundle().identity, bob.bundle().spk
    )  # relay dropped every KEM prekey
    try:
        handshake.initiate(alice, stripped, b"x", now=now)
        results["relay_strips_kem_prekeys"] = "ATTACK SUCCEEDED"
    except ProtocolError as e:
        results["relay_strips_kem_prekeys"] = f"blocked: {type(e).__name__}"

    msg, _ = handshake.initiate(alice, bob.bundle(), b"x", now=now)
    lenient = Policy(allow_classical=True)
    for name, tampered in {
        "mode_byte_only": msg[:1] + bytes([Mode.CLASSICAL]) + msg[2:],
        "mode_and_suite": msg[:1] + bytes([Mode.CLASSICAL, 1, 1, 1]) + msg[5:],
    }.items():
        for pol_name, pol in {"default_policy": Policy(), "classical_allowed": lenient}.items():
            try:
                handshake.respond(bob, tampered, policy=pol, now=now)
                results[f"{name}/{pol_name}"] = "ATTACK SUCCEEDED"
            except ProtocolError as e:
                results[f"{name}/{pol_name}"] = f"blocked: {type(e).__name__}"
    results["passed"] = all(str(v).startswith("blocked") for v in results.values())
    print(json.dumps(results))
    (ROOT / "evidence" / "m8" / "downgrade-results.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
