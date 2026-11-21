"""The real plugins through the real engine, network faked: the scope policy holds end to end."""

from __future__ import annotations

import respx

from surfacemap.collect.engine import Engine
from surfacemap.models import RelationType
from surfacemap.plugins._resolver import DnsAnswer, ResourceRecord
from surfacemap.plugins.asn import AsnPlugin
from surfacemap.plugins.base import PluginContext
from surfacemap.plugins.crtsh import CRTSH_URL, CrtshPlugin
from surfacemap.plugins.dns_records import DnsPlugin


class TableResolver:
    def __init__(self, table: dict[tuple[str, str], tuple[ResourceRecord, ...]]) -> None:
        self.table = table
        self.queries: list[tuple[str, str]] = []

    async def resolve(self, name: str, rtype: str) -> DnsAnswer:
        self.queries.append((name, rtype))
        return DnsAnswer("NOERROR", self.table.get((name, rtype), ()))


@respx.mock
async def test_out_of_scope_cdn_is_resolved_but_never_enriched(plugin_ctx: PluginContext) -> None:
    respx.get(CRTSH_URL, params={"q": "%.example.com"}).respond(
        200, json=[{"id": 1, "name_value": "www.example.com\napi.example.com"}]
    )
    dns = TableResolver(
        {
            ("www.example.com", "A"): (
                ResourceRecord("www.example.com", "CNAME", "d1.cdn.example.net"),
                ResourceRecord("d1.cdn.example.net", "A", "1.2.3.7"),
            ),
            ("api.example.com", "A"): (ResourceRecord("api.example.com", "A", "1.2.3.4"),),
            ("d1.cdn.example.net", "A"): (ResourceRecord("d1.cdn.example.net", "A", "1.2.3.7"),),
        }
    )
    cymru = TableResolver(
        {
            ("4.3.2.1.origin.asn.cymru.com", "TXT"): (
                ResourceRecord("x", "TXT", "64500 | 1.2.3.0/24 | FR | ripencc | 2001-01-01"),
            ),
        }
    )

    graph = await Engine([CrtshPlugin(), DnsPlugin(dns), AsnPlugin(cymru)], plugin_ctx).run(
        "example.com"
    )

    edges = set(graph.edges)
    assert ("domain:www.example.com", RelationType.CNAME_TO, "domain:d1.cdn.example.net") in edges
    assert ("domain:d1.cdn.example.net", RelationType.RESOLVES_TO, "ip:1.2.3.7") in edges
    assert ("ip:1.2.3.4", RelationType.ANNOUNCED_BY, "asn:64500") in edges
    # The CDN name is only resolved (A/AAAA), and its IP never reaches Team Cymru.
    cdn_queries = {rtype for name, rtype in dns.queries if name == "d1.cdn.example.net"}
    assert cdn_queries == {"A", "AAAA"}
    assert [name for name, _ in cymru.queries] == [
        "4.3.2.1.origin.asn.cymru.com",
        "AS64500.asn.cymru.com",
    ]
    assert graph.nodes["domain:d1.cdn.example.net"].entity.in_scope is False  # type: ignore[union-attr]
