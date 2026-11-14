"""Replay attacks by a malicious relay (A2) or network attacker (A1): SR-10, SR-11, SR-12.

The relay re-queues ciphertexts it already delivered. Bob's client must drop every replay (it counts
them in ``dropped``) and show nothing new. Writes evidence/m8/replay-results.json.
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from tests.relay_harness import running_relay  # noqa: E402

from pqchat.client.core import ChatClient  # noqa: E402

PASS = "synthetic attack passphrase"  # noqa: S105


async def run(addr: str, storage, work: Path) -> dict:  # type: ignore[no-untyped-def, type-arg]
    alice, bob = (
        ChatClient(work / "a", f"ws://{addr}/ws"),
        ChatClient(work / "b", f"ws://{addr}/ws"),
    )
    alice.unlock("alice", PASS)
    bob.unlock("bob", PASS)
    await alice.connect()
    await bob.connect()
    # the relay keeps a copy of everything it forwards (A2)
    captured: list[tuple[str, bytes]] = []
    original = storage.enqueue

    def spy(recipient, sender, kind, blob, now):  # type: ignore[no-untyped-def]
        captured.append((kind, blob))
        return original(recipient, sender, kind, blob, now)

    storage.enqueue = spy
    await alice.send_text("bob", "first message (handshake)")
    await alice.send_text("bob", "second message (ratchet)")
    await asyncio.sleep(0.5)
    before = list(bob.state.history["alice"])  # type: ignore[union-attr]
    dropped_before = bob.state.dropped  # type: ignore[union-attr]
    storage.enqueue = original  # stop recording before replaying
    for kind, blob in list(captured):  # replay every message once
        storage.enqueue("bob", "alice", kind, blob, int(time.time()))
    await bob.close()
    bob = ChatClient(work / "b", f"ws://{addr}/ws")
    bob.unlock("bob", PASS)
    await bob.connect()  # replays are delivered on login
    await asyncio.sleep(1.0)
    result = {
        "replayed": [k for k, _ in captured],
        "history_unchanged": bob.state.history["alice"] == before,  # type: ignore[union-attr]
        "dropped_by_bob": bob.state.dropped - dropped_before,  # type: ignore[union-attr]
    }
    await alice.close()
    await bob.close()
    return result


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp, running_relay() as (addr, storage):
        result = asyncio.run(run(addr, storage, Path(tmp)))
    result["passed"] = result["history_unchanged"] and result["dropped_by_bob"] == len(
        result["replayed"]
    )
    print(json.dumps(result))
    (ROOT / "evidence" / "m8" / "replay-results.json").write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
