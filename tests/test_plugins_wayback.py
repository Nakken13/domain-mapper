from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx

from surfacemap.collect.http import FetchError
from surfacemap.models import ArchivedURL, Domain, IPAddress, RelationType
from surfacemap.plugins.base import Plugin, PluginContext, ScopeView, default_registry
from surfacemap.plugins.wayback import CDX_URL, WaybackPlugin

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
