"""Per-source token-bucket rate limiting.

Each third-party source gets its own bucket: `rate` tokens per second, at most `burst`
stored. Every outgoing request (retries included) spends one token, so a plugin cannot
exceed the pace agreed for its source. Sources with no declared limit fall back to a
conservative default rather than to "unlimited".

Clock and sleep are injectable so tests run instantly and deterministically.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass

MonotonicClock = Callable[[], float]
Sleep = Callable[[float], Awaitable[None]]


@dataclass(frozen=True)
class RateLimit:
    rate: float
    """Tokens added per second."""
    burst: int = 1
    """Bucket capacity: requests allowed back to back after an idle period."""

    def __post_init__(self) -> None:
        if self.rate <= 0:
            raise ValueError("rate must be positive")
        if self.burst < 1:
            raise ValueError("burst must be at least 1")


DEFAULT_LIMIT = RateLimit(rate=1.0, burst=1)


class TokenBucket:
    def __init__(
        self,
        limit: RateLimit,
        clock: MonotonicClock = time.monotonic,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._limit = limit
        self._clock = clock
        self._sleep = sleep
        self._tokens = float(limit.burst)
        self._updated = clock()
        # One waiter at a time: concurrent callers queue instead of sharing a token.
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._updated
        self._tokens = min(self._limit.burst, self._tokens + elapsed * self._limit.rate)
        self._updated = now

    async def acquire(self) -> None:
        """Wait until a token is available, then spend it."""
        async with self._lock:
            self._refill()
            if self._tokens < 1:
                await self._sleep((1 - self._tokens) / self._limit.rate)
                self._refill()
            self._tokens -= 1


class RateLimiter:
    """One token bucket per source name."""

    def __init__(
        self,
        limits: Mapping[str, RateLimit],
        default: RateLimit = DEFAULT_LIMIT,
        clock: MonotonicClock = time.monotonic,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self._limits = dict(limits)
        self._default = default
        self._clock = clock
        self._sleep = sleep
        self._buckets: dict[str, TokenBucket] = {}

    async def acquire(self, source: str) -> None:
        bucket = self._buckets.get(source)
        if bucket is None:
            limit = self._limits.get(source, self._default)
            bucket = self._buckets[source] = TokenBucket(limit, self._clock, self._sleep)
        await bucket.acquire()
