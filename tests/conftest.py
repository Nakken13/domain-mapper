"""Shared fixtures: a plugin context over a fixed scope, fully offline."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from surfacemap.collect.cache import ResponseCache
from surfacemap.collect.http import HttpClient
from surfacemap.collect.ratelimit import RateLimiter
from surfacemap.config import Settings
from surfacemap.plugins.base import PluginContext, ScopeView
from surfacemap.scope import Scope, ScopeEntry

FIXTURES = Path(__file__).parent / "fixtures"
TODAY = date(2026, 6, 1)


def _load(name: str) -> Any:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    return json.loads(text) if name.endswith(".json") else text


@pytest.fixture
def load_fixture() -> Callable[[str], Any]:
    """Loader of a recorded (or hand-built, synthetic) API response from `tests/fixtures/`."""
    return _load


async def _no_sleep(_: float) -> None:
    return None


@pytest.fixture
def scope_view() -> ScopeView:
    return ScopeView(Scope([ScopeEntry(domain="example.com", authorization="test")]), TODAY)


@pytest.fixture
def plugin_ctx(tmp_path: Path, scope_view: ScopeView) -> Iterator[PluginContext]:
    with ResponseCache(tmp_path / "cache.sqlite", ttl=timedelta(hours=1)) as cache:
        limiter = RateLimiter({}, sleep=_no_sleep)
        yield PluginContext(
            http=HttpClient(limiter, cache, scope_view.is_target_host, sleep=_no_sleep),
            cache=cache,
            limiter=limiter,
            settings=Settings(_env_file=None),
            scope=scope_view,
        )
