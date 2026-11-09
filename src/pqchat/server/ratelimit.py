"""Token-bucket rate limiting (SR-22, M7).

Keys are strings such as ``conn:<id>`` (every envelope on one connection) or
``bundle:<requester>:<target>`` (bundle fetches, which consume one-time prekeys and are therefore
the prekey-exhaustion attack surface, T-16). Fetching a bundle costs more tokens than a message.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class RateLimiter:
    #: Sustained envelopes per second per key, and burst size.
    rate: float = 20.0
    burst: float = 60.0
    #: A bundle fetch costs this many tokens from the requester/target bucket.
    bundle_cost: float = 20.0
    clock: Callable[[], float] = field(default=time.monotonic)
    _buckets: dict[str, tuple[float, float]] = field(default_factory=dict)
    max_keys: int = 100_000

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = self.clock()
        tokens, last = self._buckets.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if tokens < cost:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - cost, now)
        if len(self._buckets) > self.max_keys:  # bound memory under key-spraying
            oldest = min(self._buckets, key=lambda k: self._buckets[k][1])
            del self._buckets[oldest]
        return True
