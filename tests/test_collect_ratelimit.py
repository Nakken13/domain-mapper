import asyncio

import pytest

from domain_mapper.collect.ratelimit import RateLimit, RateLimiter, TokenBucket


class FakeTime:
    """Monotonic clock whose sleep advances time instantly (and yields to the loop)."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds
        await asyncio.sleep(0)


@pytest.fixture
def t() -> FakeTime:
    return FakeTime()


def bucket(t: FakeTime, rate: float, burst: int) -> TokenBucket:
    return TokenBucket(RateLimit(rate=rate, burst=burst), clock=t.clock, sleep=t.sleep)


async def test_burst_is_served_without_waiting(t: FakeTime) -> None:
    b = bucket(t, rate=1, burst=3)
    for _ in range(3):
        await b.acquire()
    assert t.now == 0


async def test_waits_for_refill_once_burst_is_spent(t: FakeTime) -> None:
    b = bucket(t, rate=2, burst=1)
    await b.acquire()
    await b.acquire()
    assert t.now == pytest.approx(0.5)


async def test_tokens_refill_with_elapsed_time(t: FakeTime) -> None:
    b = bucket(t, rate=1, burst=2)
    await b.acquire()
    await b.acquire()
    t.now += 10  # idle: refill is capped at burst, not 10 tokens
    for _ in range(3):
        await b.acquire()
    assert t.now == pytest.approx(11)


async def test_concurrent_acquires_are_serialized(t: FakeTime) -> None:
    b = bucket(t, rate=2, burst=1)
    await asyncio.gather(*(b.acquire() for _ in range(4)))
    assert t.now == pytest.approx(1.5)


@pytest.mark.parametrize(("rate", "burst"), [(0, 1), (-1, 1), (1, 0)])
def test_invalid_limits_are_refused(rate: float, burst: int) -> None:
    with pytest.raises(ValueError, match=r"rate|burst"):
        RateLimit(rate=rate, burst=burst)


async def test_limiter_keeps_one_bucket_per_source(t: FakeTime) -> None:
    limiter = RateLimiter(
        {"crtsh": RateLimit(rate=1, burst=1), "wayback": RateLimit(rate=1, burst=1)},
        clock=t.clock,
        sleep=t.sleep,
    )
    await limiter.acquire("crtsh")
    await limiter.acquire("wayback")
    assert t.now == 0
    await limiter.acquire("crtsh")
    assert t.now == pytest.approx(1)


async def test_undeclared_source_gets_the_conservative_default(t: FakeTime) -> None:
    limiter = RateLimiter({}, default=RateLimit(rate=0.5, burst=1), clock=t.clock, sleep=t.sleep)
    await limiter.acquire("unknown")
    await limiter.acquire("unknown")
    assert t.now == pytest.approx(2)
