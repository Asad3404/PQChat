"""SR-22 rate limiting and T-16 prekey-exhaustion protection."""

from __future__ import annotations

import asyncio
import time

from pqchat.client.relay_client import RelayClient, RelayError
from pqchat.protocol.bundle import IdentityKeys, PrekeyStore
from pqchat.server.ratelimit import RateLimiter
from tests.relay_harness import running_relay


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_token_bucket_burst_and_refill() -> None:
    clock = FakeClock()
    rl = RateLimiter(rate=2, burst=4, clock=clock)
    assert [rl.allow("k") for _ in range(5)] == [True] * 4 + [False]
    clock.t += 1.0  # +2 tokens
    assert [rl.allow("k") for _ in range(3)] == [True, True, False]
    assert rl.allow("other")  # keys are independent


def test_cost_and_memory_bound() -> None:
    clock = FakeClock()
    rl = RateLimiter(rate=1, burst=10, clock=clock, max_keys=3)
    assert rl.allow("a", cost=10) and not rl.allow("a", cost=1)
    for k in "bcde":
        clock.t += 1
        rl.allow(k)
    assert len(rl._buckets) <= 4  # oldest keys evicted


def test_prekey_exhaustion_is_capped() -> None:
    """Several attacker accounts hammering bob's bundle cannot drain all his one-time prekeys."""

    async def scenario(addr: str) -> int:
        now = int(time.time())
        bob_store = PrekeyStore(IdentityKeys.generate())
        bob_store.rotate_signed(now)
        bob_store.add_one_time(25, now)
        bob = RelayClient(f"ws://{addr}/ws", "bob", bob_store.identity)
        await bob.connect(register=True)
        spk, pqspk = bob_store.current_signed()
        ot = [pk.encode() for _, pk in bob_store.one_time_dh.values()]
        ot += [pk.encode() for _, pk in bob_store.one_time_kem.values()]
        await bob.upload_prekeys([spk.encode(), pqspk.encode()], ot[:25])
        await bob.upload_prekeys([], ot[25:])
        limited = 0
        for i in range(3):
            attacker = RelayClient(f"ws://{addr}/ws", f"mallory{i}", IdentityKeys.generate())
            await attacker.connect(register=True)
            for _ in range(10):
                try:
                    await attacker.fetch_bundle("bob")
                except RelayError as e:
                    assert e.code == "rate_limited"
                    limited += 1
            await attacker.close()
        left = await bob.count_prekeys()
        await bob.close()
        assert limited >= 10
        return left

    with running_relay() as (addr, _):
        left = asyncio.run(scenario(addr))
    assert left >= 5  # 25 uploaded, at most 20 handed out in the burst
