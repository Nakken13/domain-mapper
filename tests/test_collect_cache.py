from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from domain_mapper.collect.cache import ResponseCache


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def cache(tmp_path: Path, clock: FakeClock) -> Iterator[ResponseCache]:
    with ResponseCache(tmp_path / "cache.sqlite", ttl=timedelta(hours=1), clock=clock) as c:
        yield c


def test_miss_returns_none(cache: ResponseCache) -> None:
    assert cache.get("crtsh", "%.example.com") is None


def test_hit_returns_stored_body(cache: ResponseCache) -> None:
    cache.set("crtsh", "%.example.com", '[{"id": 1}]')
    assert cache.get("crtsh", "%.example.com") == '[{"id": 1}]'


def test_key_is_source_and_query(cache: ResponseCache) -> None:
    cache.set("crtsh", "example.com", "a")
    assert cache.get("wayback", "example.com") is None
    assert cache.get("crtsh", "other.com") is None


def test_key_parts_cannot_collide_by_concatenation(cache: ResponseCache) -> None:
    cache.set("a|b", "c", "first")
    assert cache.get("a", "b|c") is None


def test_set_overwrites(cache: ResponseCache) -> None:
    cache.set("crtsh", "q", "old")
    cache.set("crtsh", "q", "new")
    assert cache.get("crtsh", "q") == "new"


def test_entry_expires_after_ttl(cache: ResponseCache, clock: FakeClock) -> None:
    cache.set("crtsh", "q", "body")
    clock.advance(minutes=59)
    assert cache.get("crtsh", "q") == "body"
    clock.advance(minutes=2)
    assert cache.get("crtsh", "q") is None


def test_purge_expired_removes_only_stale_rows(cache: ResponseCache, clock: FakeClock) -> None:
    cache.set("crtsh", "old", "x")
    clock.advance(hours=2)
    cache.set("crtsh", "fresh", "y")
    assert cache.purge_expired() == 1
    assert cache.get("crtsh", "fresh") == "y"


def test_persists_across_instances(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "sub" / "cache.sqlite"
    with ResponseCache(path, ttl=timedelta(hours=1), clock=clock) as first:
        first.set("crtsh", "q", "body")
    with ResponseCache(path, ttl=timedelta(hours=1), clock=clock) as second:
        assert second.get("crtsh", "q") == "body"


def test_non_positive_ttl_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="ttl"):
        ResponseCache(tmp_path / "c.sqlite", ttl=timedelta(0))


def test_stale_rows_are_purged_on_open(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "cache.sqlite"
    with ResponseCache(path, ttl=timedelta(hours=1), clock=clock) as first:
        first.set("rdap", "example.com", "raw body")
    clock.advance(hours=2)
    with ResponseCache(path, ttl=timedelta(hours=1), clock=clock) as second:
        assert second.purge_expired() == 0  # already removed when the cache was opened
