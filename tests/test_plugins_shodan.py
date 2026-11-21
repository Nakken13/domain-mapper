from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import httpx
import pytest
import respx

from surfacemap.collect.http import FetchError
from surfacemap.config import Settings
from surfacemap.models import ASN, Domain, IPAddress, RelationType, Technology
from surfacemap.plugins.base import Plugin, PluginContext, ScopeView, default_registry
from surfacemap.plugins.shodan import HOST_URL, ShodanPlugin

KEY = "shodan-test-key-0123456789"  # fake, the tests check it never leaks
IP = IPAddress(address="1.2.3.4")
URL = HOST_URL.format(ip="1.2.3.4")


@pytest.fixture
def ctx(plugin_ctx: PluginContext) -> PluginContext:
    return replace(plugin_ctx, settings=Settings(_env_file=None, shodan_api_key=KEY))


def test_declares_an_optional_ip_enrichment_plugin(scope_view: ScopeView) -> None:
    plugin = ShodanPlugin()
    assert isinstance(plugin, Plugin)
    assert plugin.name == "shodan"
    assert plugin.consumes == frozenset({"ip"})
    assert plugin.runs_out_of_scope is False
    assert not plugin.enabled(Settings(_env_file=None))
    assert plugin.enabled(Settings(_env_file=None, shodan_api_key=KEY))
    assert "shodan" in default_registry()


@respx.mock
async def test_maps_a_host_without_leaking_the_key_or_banners(
    ctx: PluginContext, load_fixture: Callable[[str], Any], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    route = respx.get(URL).mock(
        return_value=httpx.Response(200, json=load_fixture("shodan_host.json"))
    )

    [observation] = await ShodanPlugin().run(IP, ctx)

    assert route.calls.last.request.url.params["key"] == KEY
    assert observation.provenance.query == "shodan host 1.2.3.4"
    assert {r.key for r in observation.relations} == {
        ("ip:1.2.3.4", RelationType.ANNOUNCED_BY, "asn:64500"),
        ("domain:www.example.com", RelationType.RESOLVES_TO, "ip:1.2.3.4"),
        ("domain:www.example.com", RelationType.USES_TECH, "tech:nginx"),
        ("domain:www.example.com", RelationType.USES_TECH, "tech:apache httpd"),
    }
    techs = {e.id: e for e in observation.entities if isinstance(e, Technology)}
    assert techs["tech:nginx"].evidence == ("shodan:443/tcp nginx 1.25.3",)
    assert techs["tech:apache httpd"].evidence == ("shodan:8080/tcp Apache httpd",)
    assert techs["tech:nginx"].category == "service"
    assert ASN(number=64500) in observation.entities
    # Out-of-scope provider hostname and its OpenSSH banner are not kept.
    dumped = observation.model_dump_json()
    for leak in ("provider.example.net", "OpenSSH", KEY, "webmaster", "jane.synthetic"):
        assert leak not in dumped
    rows = ctx.cache._db.execute("SELECT body, query FROM responses").fetchall()
    assert rows
    for body, query in rows:
        assert KEY not in query
        for leak in (KEY, "webmaster", "jane.synthetic", "html", "ESMTP"):
            assert leak not in body
    assert KEY not in caplog.text


@respx.mock
async def test_an_unknown_host_raises_a_fetch_error_without_the_key(ctx: PluginContext) -> None:
    respx.get(URL).respond(404, json={"error": "No information available for that IP."})
    with pytest.raises(FetchError) as caught:
        await ShodanPlugin().run(IP, ctx)
    assert KEY not in str(caught.value)


@respx.mock
@pytest.mark.parametrize("asn", ["bogus", 64500, None])
async def test_a_host_with_nothing_usable_gives_nothing(ctx: PluginContext, asn: object) -> None:
    respx.get(URL).respond(200, json={"ip_str": "1.2.3.4", "asn": asn, "data": []})
    assert await ShodanPlugin().run(IP, ctx) == []


@respx.mock
async def test_unexpected_payloads_are_fetch_errors(ctx: PluginContext) -> None:
    respx.get(URL).respond(200, text="[1]")
    with pytest.raises(FetchError, match="shodan: unexpected payload"):
        await ShodanPlugin().run(IP, ctx)


@respx.mock
async def test_invalid_json_is_a_fetch_error(ctx: PluginContext) -> None:
    respx.get(URL).respond(200, text="<html>")
    with pytest.raises(FetchError, match="shodan: unexpected payload"):
        await ShodanPlugin().run(IP, ctx)


@pytest.mark.parametrize("address", ["10.0.0.1", "192.0.2.1"])
async def test_non_global_addresses_are_never_sent(ctx: PluginContext, address: str) -> None:
    assert await ShodanPlugin().run(IPAddress(address=address), ctx) == []


async def test_without_a_key_nothing_is_sent(plugin_ctx: PluginContext) -> None:
    assert await ShodanPlugin().run(IP, plugin_ctx) == []


async def test_ignores_entities_that_are_not_ips(ctx: PluginContext) -> None:
    assert await ShodanPlugin().run(Domain(fqdn="example.com", in_scope=True), ctx) == []
