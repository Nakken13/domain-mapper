from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from surfacemap.collect.http import FetchError
from surfacemap.models import Domain, IPAddress, RelationType
from surfacemap.plugins.base import Plugin, PluginContext, ScopeView, default_registry
from surfacemap.plugins.rdap import BOOTSTRAP_URL, RdapPlugin, rdap_server

ROOT = Domain(fqdn="example.com", in_scope=True)
REGISTRY = "https://rdap.verisign.example/com/v1/domain/example.com"

Loader = Callable[[str], Any]


@pytest.fixture
def bootstrap(load_fixture: Loader) -> respx.Route:
    return respx.get(BOOTSTRAP_URL).mock(
        return_value=httpx.Response(200, json=load_fixture("rdap_bootstrap.json"))
    )


def test_declares_a_root_only_enrichment_plugin(scope_view: ScopeView) -> None:
    plugin = RdapPlugin()
    assert isinstance(plugin, Plugin)
    assert plugin.name == "rdap"
    assert plugin.runs_out_of_scope is False
    assert plugin.applies_to(ROOT, scope_view)
    assert not plugin.applies_to(Domain(fqdn="www.example.com", in_scope=True), scope_view)
    assert isinstance(default_registry().get("rdap"), RdapPlugin)


@respx.mock
async def test_emits_name_servers_and_never_caches_contacts(
    plugin_ctx: PluginContext, bootstrap: respx.Route, load_fixture: Loader
) -> None:
    domain_route = respx.get(REGISTRY).mock(
        return_value=httpx.Response(200, json=load_fixture("rdap_example_com.json"))
    )

    [observation] = await RdapPlugin().run(ROOT, plugin_ctx)

    assert domain_route.calls.last.request.headers["accept"] == "application/rdap+json"
    assert observation.provenance.query == "rdap domain example.com"
    assert {r.key for r in observation.relations} == {
        ("domain:example.com", RelationType.NS, "domain:a.iana-servers.net"),
        ("domain:example.com", RelationType.NS, "domain:b.iana-servers.net"),
    }
    servers = [e for e in observation.entities if isinstance(e, Domain) and e.fqdn != "example.com"]
    assert all(not s.in_scope for s in servers)
    assert "Synthetic" not in observation.model_dump_json()
    for (body,) in plugin_ctx.cache._db.execute("SELECT body FROM responses"):
        assert "Synthetic" not in body
        assert "synthetic@" not in body
        assert "tel:" not in body


@respx.mock
async def test_bootstrap_picks_an_https_server_per_tld(
    plugin_ctx: PluginContext, bootstrap: respx.Route
) -> None:
    assert await rdap_server("example.com", plugin_ctx) == "https://rdap.verisign.example/com/v1/"
    assert await rdap_server("example.fr", plugin_ctx) == "https://rdap.nic.example/"
    assert await rdap_server("Example.NET", plugin_ctx) == "https://rdap.verisign.example/com/v1/"
    # Plain-HTTP only, or unknown TLD: no RDAP server (never downgraded to HTTP).
    assert await rdap_server("example.org", plugin_ctx) is None
    assert await rdap_server("example.zz", plugin_ctx) is None
    assert bootstrap.call_count == 1  # cached


@respx.mock
async def test_a_tld_without_rdap_gives_nothing(
    plugin_ctx: PluginContext, bootstrap: respx.Route, scope_view: ScopeView
) -> None:
    org = Domain(fqdn="example.org", in_scope=False)
    assert await RdapPlugin().run(org, plugin_ctx) == []


@respx.mock
async def test_a_domain_without_name_servers_gives_nothing(
    plugin_ctx: PluginContext, bootstrap: respx.Route
) -> None:
    respx.get(REGISTRY).respond(200, json={"objectClassName": "domain", "ldhName": "example.com"})
    assert await RdapPlugin().run(ROOT, plugin_ctx) == []


@respx.mock
async def test_unexpected_payloads_are_fetch_errors(
    plugin_ctx: PluginContext, bootstrap: respx.Route
) -> None:
    respx.get(REGISTRY).respond(200, text="[1, 2]")
    with pytest.raises(FetchError, match="rdap: unexpected payload"):
        await RdapPlugin().run(ROOT, plugin_ctx)


@respx.mock
async def test_a_broken_bootstrap_is_a_fetch_error(plugin_ctx: PluginContext) -> None:
    respx.get(BOOTSTRAP_URL).respond(200, json={"services": "nope"})
    with pytest.raises(FetchError, match="rdap: unexpected payload"):
        await rdap_server("example.com", plugin_ctx)


@respx.mock
async def test_the_registry_of_the_target_itself_is_refused(
    plugin_ctx: PluginContext, load_fixture: Loader
) -> None:
    # A bootstrap pointing at the assessed domain must not make us contact it.
    data = load_fixture("rdap_bootstrap.json")
    data["services"] = [[["com"], ["https://rdap.example.com/"]]]
    respx.get(BOOTSTRAP_URL).respond(200, json=data)
    with pytest.raises(PermissionError):
        await RdapPlugin().run(ROOT, plugin_ctx)


async def test_ignores_entities_that_are_not_domains(plugin_ctx: PluginContext) -> None:
    assert await RdapPlugin().run(IPAddress(address="192.0.2.1"), plugin_ctx) == []


@respx.mock
async def test_in_scope_name_servers_are_flagged_in_scope(
    plugin_ctx: PluginContext, bootstrap: respx.Route
) -> None:
    respx.get(REGISTRY).respond(200, json={"nameservers": [{"ldhName": "ns1.example.com"}]})
    [observation] = await RdapPlugin().run(ROOT, plugin_ctx)
    ns = next(e for e in observation.entities if e.id == "domain:ns1.example.com")
    assert isinstance(ns, Domain)
    assert ns.in_scope


@respx.mock
async def test_invalid_json_is_a_fetch_error(
    plugin_ctx: PluginContext, bootstrap: respx.Route
) -> None:
    respx.get(REGISTRY).respond(200, text="<html>rate limited</html>")
    with pytest.raises(FetchError, match="rdap: unexpected payload"):
        await RdapPlugin().run(ROOT, plugin_ctx)
