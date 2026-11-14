"""Fuzz every parser that sees attacker-controlled bytes (SR-9, M8).

Atheris has no wheel for Python 3.12 and its source build failed in this environment, so — as
CLAUDE.md §6 allows — fuzzing uses Hypothesis: random bytes plus mutations (bit flips, truncation,
insertion, duplication, splicing) of *valid* messages, so the fuzzer gets past the first checks.

A target passes if every input either parses or raises one of its *expected* error types. Any other
exception (IndexError, struct.error, UnicodeDecodeError, ...) is a finding.

    python attacks/fuzz_parsers.py [--examples 5000]      -> evidence/m8/fuzz-results.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402
from tests.conftest import NOW, make_pair, make_store  # noqa: E402

from pqchat import wire  # noqa: E402
from pqchat.crypto.errors import CryptoError  # noqa: E402
from pqchat.protocol import handshake, ratchet  # noqa: E402
from pqchat.protocol.bundle import IdentityKeys, IdentityPublic, PrekeyBundle, decode_prekey  # noqa: E402
from pqchat.protocol.errors import ProtocolError  # noqa: E402
from pqchat.protocol.padding import pad, unpad  # noqa: E402


def mutations(seed: bytes) -> st.SearchStrategy[bytes]:
    pos = st.integers(0, max(len(seed) - 1, 0))
    flip = st.tuples(pos, st.integers(0, 7)).map(
        lambda t: seed[: t[0]] + bytes([seed[t[0]] ^ (1 << t[1])]) + seed[t[0] + 1 :]
    )
    cut = pos.map(lambda i: seed[:i])
    insert = st.tuples(pos, st.binary(min_size=1, max_size=64)).map(
        lambda t: seed[: t[0]] + t[1] + seed[t[0] :]
    )
    dup = st.tuples(pos, pos).map(lambda t: seed[: max(t)] + seed[min(t) : max(t)] + seed[max(t) :])
    overwrite = st.tuples(pos, st.binary(min_size=1, max_size=8)).map(
        lambda t: seed[: t[0]] + t[1] + seed[t[0] + len(t[1]) :]
    )
    return st.one_of(flip, cut, insert, dup, overwrite, st.binary(max_size=2048))


def build_targets() -> dict[
    str, tuple[bytes, Callable[[bytes], object], tuple[type[BaseException], ...]]
]:
    bob = make_store(one_time=50)
    alice = IdentityKeys.generate()
    bundle = bob.bundle()
    init_msg, _ = handshake.initiate(alice, bundle, b"seed", now=NOW)
    a, b = make_pair()
    ratchet_msg = a.encrypt(b"seed message")
    env = wire.build("send", req=7, to="bob", kind="msg", blob=b"\x01" * 100)
    proto = (ProtocolError,)
    return {
        "wire.parse (relay side)": (
            env.encode(),
            lambda d: wire.parse(d, set(wire.SCHEMAS)),
            (wire.EnvelopeError,),
        ),
        "PrekeyBundle.decode": (bundle.encode(), PrekeyBundle.decode, proto),
        "IdentityPublic.decode": (bundle.identity.encode(), IdentityPublic.decode, proto),
        "decode_prekey": (bundle.pqspk.encode(), decode_prekey, proto),  # type: ignore[union-attr]
        "handshake.parse_initial": (init_msg, handshake.parse_initial, proto),
        "handshake.respond (full)": (init_msg, lambda d: handshake.respond(bob, d, now=NOW), proto),
        "ratchet.parse_message": (ratchet_msg, ratchet.parse_message, proto),
        "Session.decrypt (full)": (ratchet_msg, b.decrypt, proto),
        "padding.unpad": (pad(b"seed"), unpad, proto),
        "keystore header": (
            b"PQKS\x01" + bytes(40),
            lambda d: __import__("pqchat.crypto.keystore_crypto", fromlist=["x"]).decrypt_keystore(
                "pw", d
            ),
            (CryptoError,),
        ),
    }


def fuzz(
    name: str,
    seed: bytes,
    fn: Callable[[bytes], object],
    expected: tuple[type[BaseException], ...],
    n: int,
) -> dict:  # type: ignore[type-arg]
    stats = {"inputs": 0, "accepted": 0, "rejected": 0, "unexpected": []}

    @settings(
        max_examples=n,
        deadline=None,
        database=None,
        derandomize=True,
        suppress_health_check=list(HealthCheck),
    )
    @given(data=mutations(seed))
    def run(data: bytes) -> None:
        stats["inputs"] += 1  # type: ignore[operator]
        try:
            fn(data)
            stats["accepted"] += 1  # type: ignore[operator]
        except expected:
            stats["rejected"] += 1  # type: ignore[operator]
        except Exception as exc:
            if len(stats["unexpected"]) < 5:  # type: ignore[arg-type]
                stats["unexpected"].append(f"{type(exc).__name__}: {exc}")  # type: ignore[union-attr]
            raise

    t0 = time.monotonic()
    try:
        run()
        stats["result"] = "pass"
    except Exception as exc:
        stats["result"] = f"FINDING ({type(exc).__name__})"
    stats["seconds"] = round(time.monotonic() - t0, 1)
    return stats


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--examples", type=int, default=5000)
    ap.add_argument("--out", default=str(ROOT / "evidence" / "m8" / "fuzz-results.json"))
    args = ap.parse_args()
    results = {}
    for name, (seed, fn, expected) in build_targets().items():
        results[name] = fuzz(name, seed, fn, expected, args.examples)
        r = results[name]
        print(
            f"{name:30s} {r['result']:14s} inputs={r['inputs']:6d} rejected={r['rejected']:6d} accepted={r['accepted']:5d} {r['seconds']}s"
        )
    Path(args.out).write_text(json.dumps(results, indent=2))
    sys.exit(0 if all(r["result"] == "pass" for r in results.values()) else 1)


if __name__ == "__main__":
    main()
