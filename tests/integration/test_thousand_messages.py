"""Two clients and the relay exchange 1,000 messages, out of order and with loss.

PROJECT-BRIEF.md §8.

Runs against an in-process relay by default, or against a running Docker Compose relay when
PQCHAT_RELAY_URL (and PQCHAT_RELAY_CA for wss://) are set, e.g.:

    PQCHAT_RELAY_URL=wss://localhost:8443/ws PQCHAT_RELAY_CA=ca.crt pytest tests/integration
"""

from __future__ import annotations

import asyncio
import os
import random
import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager

from pqchat.client.relay_client import RelayClient
from pqchat.client.tls import client_context
from pqchat.protocol.bundle import IdentityKeys, PrekeyBundle, PrekeyStore
from pqchat.protocol.session import Session
from pqchat.server.ratelimit import RateLimiter
from tests.relay_harness import running_relay

TOTAL = 1000
BURST = 25
DROP_RATE = 0.05


EXTERNAL = os.environ.get("PQCHAT_RELAY_URL")


@contextmanager
def relay_url() -> Iterator[str]:
    if EXTERNAL:
        yield EXTERNAL
    else:
        # This test sends ~2,000 envelopes in seconds, far above the human-paced limit the
        # relay enforces (SR-22); the in-process relay gets a stress-test limit instead.
        with running_relay(limiter=RateLimiter(rate=1e6, burst=1e6)) as (addr, _):
            yield f"ws://{addr}/ws"


def test_thousand_messages_out_of_order_with_loss() -> None:
    rng = random.Random(20261109)  # noqa: S311 - test scheduling only, never key material
    suffix = secrets.token_hex(3)

    async def scenario(url: str) -> dict[str, int]:
        ca = os.environ.get("PQCHAT_RELAY_CA")
        ctx = client_context(ca) if url.startswith("wss://") else None
        now = int(time.time())
        bob_store = PrekeyStore(IdentityKeys.generate())
        bob_store.rotate_signed(now)
        bob_store.add_one_time(1, now)
        alice_id = IdentityKeys.generate()
        a_name, b_name = f"alice_{suffix}", f"bob_{suffix}"
        alice = RelayClient(url, a_name, alice_id, ctx)
        bob = RelayClient(url, b_name, bob_store.identity, ctx)
        await alice.connect(register=True)
        await bob.connect(register=True)
        spk, pqspk = bob_store.current_signed()
        await bob.upload_prekeys(
            [spk.encode(), pqspk.encode()],
            [pk.encode() for _, pk in bob_store.one_time_dh.values()]
            + [pk.encode() for _, pk in bob_store.one_time_kem.values()],
        )
        bundle = PrekeyBundle.decode(await alice.fetch_bundle(b_name))
        a_sess, first = Session.initiate(alice_id, bundle, b"hello")
        await alice.send(b_name, "init", first)
        d = await asyncio.wait_for(bob.inbox.get(), 10)
        b_sess, pt = Session.accept(bob_store, d.blob)
        assert pt == b"hello"
        await bob.ack(d.id)

        stats = {"sent": 1, "delivered": 1, "dropped": 0}
        sides = [(a_sess, alice, b_sess, bob, b_name), (b_sess, bob, a_sess, alice, a_name)]
        turn = 0
        while stats["sent"] < TOTAL:
            s_sess, s_relay, r_sess, r_relay, r_name = sides[turn % 2]
            n = min(BURST, TOTAL - stats["sent"])
            expected = {}
            for i in range(n):
                text = f"m{stats['sent'] + i}".encode()
                await s_relay.send(r_name, "msg", s_sess.encrypt(text))
            for i in range(n):
                expected[i] = f"m{stats['sent'] + i}".encode()
            stats["sent"] += n
            if EXTERNAL:
                await asyncio.sleep(n / 20)  # stay below the real relay's rate limit
            batch = [await asyncio.wait_for(r_relay.inbox.get(), 10) for _ in range(n)]
            for x in batch:
                await r_relay.ack(x.id)
            keep = [x for x in batch if rng.random() >= DROP_RATE] or batch[:1]
            stats["dropped"] += n - len(keep)
            rng.shuffle(keep)
            got = {r_sess.decrypt(x.blob) for x in keep}
            assert got <= set(expected.values())
            assert len(got) == len(keep)
            stats["delivered"] += len(keep)
            turn += 1
        stats["missing_alice"] = a_sess.missing_messages
        stats["missing_bob"] = b_sess.missing_messages
        await alice.close()
        await bob.close()
        return stats

    with relay_url() as url:
        stats = asyncio.run(scenario(url))
    assert stats["sent"] == TOTAL
    assert stats["delivered"] + stats["dropped"] == TOTAL
    assert stats["dropped"] > 0
    # Every dropped message is still known as "missing" (SR-33), except the last burst's tail
    # that the receiver never learned about through a later message.
    assert stats["missing_alice"] + stats["missing_bob"] <= stats["dropped"]
