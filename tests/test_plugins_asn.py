from __future__ import annotations

import pytest

from surfacemap.models import ASN, Domain, IPAddress, RelationType
from surfacemap.plugins._resolver import DnsAnswer, DnsError, DnspythonResolver, ResourceRecord
from surfacemap.plugins.asn import AsnPlugin, origin_name
from surfacemap.plugins.base import Plugin, PluginContext, ScopeView, default_registry

V4 = IPAddress(address="1.2.3.4")
V6 = IPAddress(address="2606:4700::1111")


class FakeResolver:
    def __init__(self, txt: dict[str, list[str] | DnsError]) -> None:
        self.txt = txt
        self.queries: list[str] = []

    async def resolve(self, name: str, rtype: str) -> DnsAnswer:
        assert rtype == "TXT"
        self.queries.append(name)
        values = self.txt.get(name)
        if isinstance(values, DnsError):
            raise values
        if values is None:
            return DnsAnswer("NXDOMAIN")
        return DnsAnswer("NOERROR", tuple(ResourceRecord(name, "TXT", v) for v in values))


def cymru() -> FakeResolver:
    return FakeResolver(
        {
            # The prefix is announced from DE; the ASN itself is registered in FR.
            "4.3.2.1.origin.asn.cymru.com": ["64500 | 1.2.3.0/24 | DE | ripencc | 2001-01-01"],
            "AS64500.asn.cymru.com": [
                "64500 | FR | ripencc | 2001-01-01 | EXAMPLE-NET - Example SAS, FR"
            ],
        }
    )


def test_declares_an_ip_enrichment_plugin(scope_view: ScopeView) -> None:
    plugin = AsnPlugin(cymru())
    assert isinstance(plugin, Plugin)
    assert plugin.name == "asn"
    assert plugin.consumes == frozenset({"ip"})
    assert plugin.runs_out_of_scope is False
    assert plugin.applies_to(V4, scope_view)
    assert isinstance(default_registry().get("asn"), AsnPlugin)
    assert isinstance(AsnPlugin().resolver, DnspythonResolver)


def test_origin_names_reverse_the_address() -> None:
    assert origin_name(V4) == "4.3.2.1.origin.asn.cymru.com"
    # 2606:4700:0000:0000:0000:0000:0000:1111, one label per nibble, reversed.
    expected = "1.1.1.1." + "0." * 20 + "0.0.7.4.6.0.6.2.origin6.asn.cymru.com"
    assert origin_name(V6) == expected
    assert len(expected.removesuffix(".origin6.asn.cymru.com").split(".")) == 32


async def test_links_an_ip_to_its_announcing_asn(plugin_ctx: PluginContext) -> None:
    resolver = cymru()

    [observation] = await AsnPlugin(resolver).run(V4, plugin_ctx)

    assert observation.provenance.query == "4.3.2.1.origin.asn.cymru.com TXT"
    asn = next(e for e in observation.entities if isinstance(e, ASN))
    assert asn == ASN(number=64500, holder="EXAMPLE-NET - Example SAS, FR", country="FR")
    assert [r.key for r in observation.relations] == [
        ("ip:1.2.3.4", RelationType.ANNOUNCED_BY, "asn:64500")
    ]
    # Country of the address is left to the geoip plugin.
    ip = next(e for e in observation.entities if isinstance(e, IPAddress))
    assert ip.country is None


async def test_answers_are_cached(plugin_ctx: PluginContext) -> None:
    resolver = cymru()
    await AsnPlugin(resolver).run(V4, plugin_ctx)
    await AsnPlugin(resolver).run(V4, plugin_ctx)
    assert resolver.queries == ["4.3.2.1.origin.asn.cymru.com", "AS64500.asn.cymru.com"]


async def test_multi_origin_prefixes_link_every_asn(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver(
        {"4.3.2.1.origin.asn.cymru.com": ["64500 x 64501 | 1.2.3.0/24 | US | arin | 2001-01-01"]}
    )
    [observation] = await AsnPlugin(resolver).run(V4, plugin_ctx)
    assert sorted(r.target for r in observation.relations) == ["asn:64500", "asn:64501"]
    holders = {e.holder for e in observation.entities if isinstance(e, ASN)}
    assert holders == {None}  # holder lookups answered NXDOMAIN


@pytest.mark.parametrize("address", ["10.0.0.1", "192.0.2.1", "127.0.0.1", "fe80::1", "::1"])
async def test_non_global_addresses_are_never_sent(plugin_ctx: PluginContext, address: str) -> None:
    resolver = cymru()
    assert await AsnPlugin(resolver).run(IPAddress(address=address), plugin_ctx) == []
    assert resolver.queries == []


@pytest.mark.parametrize(
    "answer",
    [
        [],
        ["garbage"],
        ["notanumber | 1.2.3.0/24 | FR"],
        ["0 | 1.2.3.0/24 | FR"],
        DnsError("Timeout"),
    ],
)
async def test_unusable_answers_give_nothing(
    plugin_ctx: PluginContext, answer: list[str] | DnsError
) -> None:
    resolver = FakeResolver({"4.3.2.1.origin.asn.cymru.com": answer})
    assert await AsnPlugin(resolver).run(V4, plugin_ctx) == []


async def test_a_failed_holder_lookup_keeps_the_asn(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver(
        {
            "4.3.2.1.origin.asn.cymru.com": ["64500 | 1.2.3.0/24 | ZZZ | ripencc | 2001-01-01"],
            "AS64500.asn.cymru.com": DnsError("Timeout"),
        }
    )
    [observation] = await AsnPlugin(resolver).run(V4, plugin_ctx)
    asn = next(e for e in observation.entities if isinstance(e, ASN))
    assert asn == ASN(number=64500)  # no holder, no country


async def test_every_query_spends_a_rate_limit_token(
    plugin_ctx: PluginContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    spent: list[str] = []

    async def acquire(source: str) -> None:
        spent.append(source)

    monkeypatch.setattr(plugin_ctx.limiter, "acquire", acquire)
    await AsnPlugin(cymru()).run(V4, plugin_ctx)
    assert spent == ["asn", "asn"]


async def test_ignores_entities_that_are_not_ips(plugin_ctx: PluginContext) -> None:
    domain = Domain(fqdn="example.com", in_scope=True)
    assert await AsnPlugin(cymru()).run(domain, plugin_ctx) == []


async def test_a_malformed_holder_answer_is_ignored(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver(
        {
            "4.3.2.1.origin.asn.cymru.com": ["64500 | 1.2.3.0/24 | FR | ripencc | 2001-01-01"],
            "AS64500.asn.cymru.com": ["64500 | FR", "64500 | ZZZ | ripencc | 2001-01-01 | OK-NET"],
        }
    )
    [observation] = await AsnPlugin(resolver).run(V4, plugin_ctx)
    [asn] = [e for e in observation.entities if isinstance(e, ASN)]
    assert asn == ASN(number=64500, holder="OK-NET")  # invalid country code dropped
