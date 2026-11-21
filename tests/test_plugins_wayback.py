from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from surfacemap.collect.cache import ResponseCache
from surfacemap.collect.http import FetchError, HttpClient
from surfacemap.collect.ratelimit import RateLimiter
from surfacemap.config import Settings
from surfacemap.models import ArchivedURL, Domain, IPAddress, RelationType
from surfacemap.plugins.base import Plugin, PluginContext, ScopeView, default_registry
from surfacemap.plugins.wayback import CDX_URL, WaybackPlugin
from surfacemap.scope import Scope, ScopeEntry

ROOT = Domain(fqdn="example.com", in_scope=True)


def mock_cdx(body: object) -> respx.Route:
    return respx.get(CDX_URL, params={"url": "example.com", "matchType": "domain"}).mock(
        return_value=httpx.Response(200, json=body)
    )


def test_declares_a_root_only_enrichment_plugin(scope_view: ScopeView) -> None:
    plugin = WaybackPlugin()
    assert isinstance(plugin, Plugin)
    assert plugin.name == "wayback"
    assert plugin.consumes == frozenset({"domain"})
    assert plugin.runs_out_of_scope is False
    assert plugin.applies_to(ROOT, scope_view)
    assert not plugin.applies_to(Domain(fqdn="www.example.com", in_scope=True), scope_view)
    assert isinstance(default_registry().get("wayback"), WaybackPlugin)


@respx.mock
async def test_emits_archived_paths_without_query_strings(
    plugin_ctx: PluginContext, load_fixture: Callable[[str], Any]
) -> None:
    route = mock_cdx(load_fixture("wayback_example.json"))

    [observation] = await WaybackPlugin().run(ROOT, plugin_ctx)

    sent = route.calls.last.request.url.params
    assert sent["output"] == "json"
    assert sent["fl"] == "timestamp,original"
    assert observation.provenance.query == "example.com/*"
    urls = {e.id: e for e in observation.entities if isinstance(e, ArchivedURL)}
    assert sorted(urls) == [
        "url:example.com/",
        "url:old.example.com/backup.zip",
        "url:www.example.com/login",
    ]
    root_page = urls["url:example.com/"]
    assert root_page.first_seen == datetime(2019, 3, 4, 5, 6, 7, tzinfo=UTC)
    assert root_page.last_seen == datetime(2024, 1, 1, tzinfo=UTC)
    login = urls["url:www.example.com/login"]
    assert (login.first_seen.year, login.last_seen.year) == (2020, 2021)

    hosts = sorted(e.fqdn for e in observation.entities if isinstance(e, Domain))
    assert hosts == ["example.com", "old.example.com", "www.example.com"]
    edges = {(r.source, r.type, r.target) for r in observation.relations}
    assert ("domain:www.example.com", RelationType.ARCHIVED_AT, "url:www.example.com/login") in (
        edges
    )
    assert len(edges) == 3
    # No query string, fragment or email survives anywhere in the observation.
    dumped = observation.model_dump_json()
    for leak in ("utm_source", "next=", "jane.doe", "#reset", "partner.example.net", "bad_host"):
        assert leak not in dumped


@respx.mock
async def test_a_truncated_archive_is_logged(
    plugin_ctx: PluginContext, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("surfacemap.plugins.wayback.CDX_LIMIT", 2)
    mock_cdx(
        [
            ["timestamp", "original"],
            ["20240101000000", "https://example.com/a"],
            ["20240102000000", "https://example.com/b"],
        ]
    )
    with caplog.at_level("WARNING"):
        await WaybackPlugin().run(ROOT, plugin_ctx)
    assert "CDX_LIMIT" in caplog.text or "truncated" in caplog.text


@respx.mock
async def test_empty_archive_means_no_observation(plugin_ctx: PluginContext) -> None:
    mock_cdx([])
    assert await WaybackPlugin().run(ROOT, plugin_ctx) == []


@respx.mock
async def test_header_only_means_no_observation(plugin_ctx: PluginContext) -> None:
    mock_cdx([["timestamp", "original"]])
    assert await WaybackPlugin().run(ROOT, plugin_ctx) == []


@respx.mock
async def test_unexpected_payload_is_a_fetch_error(plugin_ctx: PluginContext) -> None:
    respx.get(CDX_URL).mock(return_value=httpx.Response(200, text="Blocked"))
    with pytest.raises(FetchError, match="wayback: unexpected payload"):
        await WaybackPlugin().run(ROOT, plugin_ctx)


async def test_ignores_entities_that_are_not_domains(plugin_ctx: PluginContext) -> None:
    assert await WaybackPlugin().run(IPAddress(address="192.0.2.1"), plugin_ctx) == []


@respx.mock
async def test_path_parameters_and_encoded_delimiters_are_cut(plugin_ctx: PluginContext) -> None:
    mock_cdx(
        [
            ["timestamp", "original"],
            ["20200101000000", "https://example.com/app;jsessionid=SECRET1"],
            ["20200101000000", "https://example.com/dl%3Ftoken=SECRET2"],
            ["20200101000000", "https://example.com/doc%23SECRET3"],
            ["20200101000000", "https://example.com/;SECRET4"],
            ["20200101000000", "https://example.com/p%3Bsid=SECRET5"],
            ["20200101000000", "https://example.com/q%253Ftoken=SECRET6"],
        ]
    )
    [observation] = await WaybackPlugin().run(ROOT, plugin_ctx)
    paths = sorted(e.path for e in observation.entities if isinstance(e, ArchivedURL))
    assert paths == ["/", "/app", "/dl", "/doc", "/p", "/q"]
    assert "SECRET" not in observation.model_dump_json()


@respx.mock
async def test_out_of_scope_hosts_are_recorded_but_not_enriched(
    tmp_path: Path, scope_view: ScopeView
) -> None:
    view = ScopeView(
        Scope([ScopeEntry(domain="example.com", include_subdomains=False, authorization="t")]),
        scope_view.today,
    )
    mock_cdx(
        [
            ["timestamp", "original"],
            ["20200101000000", "https://example.com/home"],
            ["20200101000000", "https://staging.example.com/admin"],
        ]
    )
    with ResponseCache(tmp_path / "c.sqlite", ttl=timedelta(hours=1)) as cache:
        limiter = RateLimiter({})
        ctx = PluginContext(
            http=HttpClient(limiter, cache, view.is_target_host),
            cache=cache,
            limiter=limiter,
            settings=Settings(_env_file=None),
            scope=view,
        )
        [observation] = await WaybackPlugin().run(ROOT, ctx)

    ids = sorted(e.id for e in observation.entities)
    assert ids == ["domain:example.com", "domain:staging.example.com", "url:example.com/home"]
    staging = next(e for e in observation.entities if e.id == "domain:staging.example.com")
    assert isinstance(staging, Domain)
    assert staging.in_scope is False
    assert [r.target for r in observation.relations] == ["url:example.com/home"]


@respx.mock
async def test_cached_body_holds_only_cut_urls(
    plugin_ctx: PluginContext, load_fixture: Callable[[str], Any]
) -> None:
    mock_cdx(load_fixture("wayback_example.json"))
    await WaybackPlugin().run(ROOT, plugin_ctx)
    bodies = [b for (b,) in plugin_ctx.cache._db.execute("SELECT body FROM responses")]
    assert bodies
    for body in bodies:
        for leak in ("utm_source", "jane.doe", "next=", "reset", "partner.example.net", "mailto"):
            assert leak not in body
        assert "https://www.example.com/login" in body


@respx.mock
async def test_emails_in_paths_never_reach_the_cache(plugin_ctx: PluginContext) -> None:
    mock_cdx(
        [
            ["timestamp", "original"],
            ["20200101000000", "https://example.com/unsubscribe/jane.doe@example.org"],
            ["20200101000000", "https://example.com/u/john.roe%40example.org/profile"],
        ]
    )
    [observation] = await WaybackPlugin().run(ROOT, plugin_ctx)
    for (body,) in plugin_ctx.cache._db.execute("SELECT body FROM responses"):
        assert "jane.doe" not in body
        assert "john.roe" not in body
    assert "jane.doe" not in observation.model_dump_json()


@respx.mock
async def test_obfuscated_emails_in_paths_never_reach_the_cache(plugin_ctx: PluginContext) -> None:
    # Fully percent-encoded, double-encoded and fullwidth at-sign: all decode to an email
    # that the plain scrubber does not see.
    mock_cdx(
        [
            ["timestamp", "original"],
            ["20200101000000", "https://example.com/u/%6A%61ne%2Edoe%40example.org"],
            ["20200101000000", "https://example.com/u/mary.sue%2540example.org"],
            ["20200101000000", "https://example.com/u/john.roe\uff20example.org/profile"],
            ["20200101000000", "https://example.com/n/ann.lee%252525252540example.org"],
            ["20200101000000", "https://example.com/docs/a%20b"],
        ]
    )
    [observation] = await WaybackPlugin().run(ROOT, plugin_ctx)
    leaked = ("jane", "doe", "%6A", "mary.sue", "john.roe", "ann.lee", "example.org", "\uff20")
    cached = [body for (body,) in plugin_ctx.cache._db.execute("SELECT body FROM responses")]
    emitted = observation.model_dump_json()
    for text in (*cached, emitted):
        for needle in leaked:
            assert needle not in text
    assert "/docs/a%20b" in cached[0]  # a harmless encoded path is untouched
