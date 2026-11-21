from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from surfacemap.collect.http import FetchError
from surfacemap.models import Domain, IPAddress
from surfacemap.plugins.base import Plugin, PluginContext, ScopeView, default_registry
from surfacemap.plugins.crtsh import CRTSH_URL, CrtshPlugin

ROOT = Domain(fqdn="example.com", in_scope=True)


def mock_crtsh(body: object, status: int = 200) -> respx.Route:
    return respx.get(CRTSH_URL, params={"q": "%.example.com", "output": "json"}).mock(
        return_value=httpx.Response(status, json=body)
    )


def test_declares_a_root_only_enrichment_plugin(scope_view: ScopeView) -> None:
    plugin = CrtshPlugin()
    assert isinstance(plugin, Plugin)
    assert plugin.name == "crtsh"
    assert plugin.consumes == frozenset({"domain"})
    assert plugin.runs_out_of_scope is False
    assert plugin.applies_to(ROOT, scope_view)
    assert not plugin.applies_to(Domain(fqdn="www.example.com", in_scope=True), scope_view)
    assert not plugin.applies_to(Domain(fqdn="cdn.net", in_scope=False), scope_view)
    assert not plugin.applies_to(IPAddress(address="192.0.2.1"), scope_view)


@respx.mock
async def test_emits_subdomains_seen_in_certificates(
    plugin_ctx: PluginContext, load_fixture: Callable[[str], Any]
) -> None:
    route = mock_crtsh(load_fixture("crtsh_example.json"))

    [observation] = await CrtshPlugin().run(ROOT, plugin_ctx)

    assert route.call_count == 1
    assert observation.provenance.source == "crtsh"
    assert observation.provenance.query == "%.example.com"
    fqdns = sorted(e.fqdn for e in observation.entities if isinstance(e, Domain))
    # Wildcard stripped, case/trailing dot normalized, duplicates merged; the email,
    # the invalid `_` label and the co-tenant name outside the root are dropped.
    assert fqdns == ["api.example.com", "dev.example.com", "example.com", "www.example.com"]
    assert all(isinstance(e, Domain) and e.in_scope for e in observation.entities)
    assert observation.relations == ()


@respx.mock
async def test_no_certificate_means_no_observation(plugin_ctx: PluginContext) -> None:
    mock_crtsh([])
    assert await CrtshPlugin().run(ROOT, plugin_ctx) == []


@respx.mock
async def test_ignores_malformed_rows(plugin_ctx: PluginContext) -> None:
    mock_crtsh([{"name_value": 42}, "not-a-row", {"common_name": "ok.example.com"}])
    [observation] = await CrtshPlugin().run(ROOT, plugin_ctx)
    assert [e.id for e in observation.entities] == ["domain:ok.example.com"]


@respx.mock
async def test_non_list_payload_is_a_fetch_error(plugin_ctx: PluginContext) -> None:
    mock_crtsh({"error": "busy"})
    with pytest.raises(FetchError, match="crtsh: unexpected payload"):
        await CrtshPlugin().run(ROOT, plugin_ctx)


@respx.mock
async def test_invalid_json_is_a_fetch_error(plugin_ctx: PluginContext) -> None:
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, text="<html>busy</html>"))
    with pytest.raises(FetchError, match="crtsh: unexpected payload"):
        await CrtshPlugin().run(ROOT, plugin_ctx)


def test_is_a_built_in_plugin() -> None:
    assert isinstance(default_registry().get("crtsh"), CrtshPlugin)


async def test_ignores_entities_that_are_not_domains(plugin_ctx: PluginContext) -> None:
    assert await CrtshPlugin().run(IPAddress(address="192.0.2.1"), plugin_ctx) == []


@respx.mock
async def test_cached_body_holds_no_email_and_only_needed_fields(
    plugin_ctx: PluginContext, load_fixture: Callable[[str], Any]
) -> None:
    mock_crtsh(load_fixture("crtsh_example.json"))
    await CrtshPlugin().run(ROOT, plugin_ctx)

    rows = plugin_ctx.cache._db.execute("SELECT body FROM responses").fetchall()
    assert rows
    for (body,) in rows:
        assert "jane.doe" not in body
        assert "serial_number" not in body
        assert "www.example.com" in body  # the name after the dropped email survives
