from __future__ import annotations

import pytest

from surfacemap.models import DnsRecord, Domain, IPAddress, Observation, RelationType
from surfacemap.plugins._resolver import DnsAnswer, DnsError, DnspythonResolver, ResourceRecord
from surfacemap.plugins.base import Plugin, PluginContext, ScopeView, default_registry
from surfacemap.plugins.dns_records import DnsPlugin

Answer = DnsAnswer | DnsError


class FakeResolver:
    """Answers from a table; any other query is NODATA (NOERROR, no record)."""

    def __init__(self, table: dict[tuple[str, str], Answer]) -> None:
        self.table = table
        self.queries: list[tuple[str, str]] = []

    async def resolve(self, name: str, rtype: str) -> DnsAnswer:
        self.queries.append((name, rtype))
        answer = self.table.get((name, rtype), DnsAnswer("NOERROR"))
        if isinstance(answer, DnsError):
            raise answer
        return answer


def rr(owner: str, rtype: str, value: str) -> ResourceRecord:
    return ResourceRecord(owner, rtype, value)


def edges(observation: Observation) -> set[tuple[str, RelationType, str]]:
    return {r.key for r in observation.relations}


def domain(observation: Observation, fqdn: str) -> Domain:
    found = next(e for e in observation.entities if e.id == f"domain:{fqdn}")
    assert isinstance(found, Domain)
    return found


async def run(resolver: FakeResolver, fqdn: str, ctx: PluginContext) -> list[Observation]:
    entity = Domain(fqdn=fqdn, in_scope=ctx.scope.is_in_scope(fqdn))
    return await DnsPlugin(resolver).run(entity, ctx)


def test_declares_the_only_out_of_scope_plugin(scope_view: ScopeView) -> None:
    plugin = DnsPlugin(FakeResolver({}))
    assert isinstance(plugin, Plugin)
    assert plugin.name == "dns"
    assert plugin.consumes == frozenset({"domain"})
    assert plugin.runs_out_of_scope is True
    assert plugin.applies_to(Domain(fqdn="cdn.example.net", in_scope=False), scope_view)
    assert isinstance(default_registry().get("dns"), DnsPlugin)
    assert isinstance(DnsPlugin().resolver, DnspythonResolver)


async def test_a_cname_chain_links_the_ip_to_the_name_that_owns_it(
    plugin_ctx: PluginContext,
) -> None:
    resolver = FakeResolver(
        {
            ("www.example.com", "A"): DnsAnswer(
                "NOERROR",
                (
                    rr("www.example.com", "CNAME", "d1.cdn.example.net"),
                    rr("d1.cdn.example.net", "A", "198.51.100.7"),
                ),
            )
        }
    )

    [observation] = await run(resolver, "www.example.com", plugin_ctx)

    assert edges(observation) == {
        ("domain:www.example.com", RelationType.CNAME_TO, "domain:d1.cdn.example.net"),
        ("domain:d1.cdn.example.net", RelationType.RESOLVES_TO, "ip:198.51.100.7"),
    }
    assert domain(observation, "d1.cdn.example.net").in_scope is False
    assert IPAddress(address="198.51.100.7") in observation.entities
    # Not a scope root and no MX: no DMARC lookup.
    assert ("_dmarc.www.example.com", "TXT") not in resolver.queries
    assert observation.provenance.source == "dns"
    assert observation.provenance.query == "www.example.com A/AAAA/MX/NS/TXT"


async def test_the_root_gets_mail_records_and_dmarc(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver(
        {
            ("example.com", "A"): DnsAnswer("NOERROR", (rr("example.com", "A", "192.0.2.10"),)),
            ("example.com", "AAAA"): DnsAnswer(
                "NOERROR", (rr("example.com", "AAAA", "2001:db8::1"),)
            ),
            ("example.com", "MX"): DnsAnswer(
                "NOERROR",
                (rr("example.com", "MX", "mail.example.com"), rr("example.com", "MX", "")),
            ),
            ("example.com", "NS"): DnsAnswer(
                "NOERROR",
                (
                    rr("example.com", "NS", "ns1.example.net"),
                    rr("example.com", "NS", "example.com"),
                ),
            ),
            ("example.com", "TXT"): DnsAnswer(
                "NOERROR",
                (
                    rr("example.com", "TXT", "v=spf1 include:_spf.example.net -all"),
                    rr("example.com", "TXT", "google-site-verification=abc"),
                ),
            ),
            ("_dmarc.example.com", "TXT"): DnsAnswer(
                "NOERROR",
                (
                    rr(
                        "_dmarc.example.com",
                        "TXT",
                        "V=DMARC1; p=none; rua=mailto:dmarc@example.com",
                    ),
                    rr("_dmarc.example.com", "TXT", "unrelated"),
                ),
            ),
        }
    )

    [observation] = await run(resolver, "example.com", plugin_ctx)

    assert edges(observation) == {
        ("domain:example.com", RelationType.RESOLVES_TO, "ip:192.0.2.10"),
        ("domain:example.com", RelationType.RESOLVES_TO, "ip:2001:db8::1"),
        ("domain:example.com", RelationType.MX, "domain:mail.example.com"),
        ("domain:example.com", RelationType.NS, "domain:ns1.example.net"),
    }
    root = domain(observation, "example.com")
    assert set(root.records) == {
        DnsRecord(type="TXT", value="v=spf1 include:_spf.example.net -all"),
        DnsRecord(type="TXT", value="google-site-verification=abc"),
        DnsRecord(type="DMARC", value="V=DMARC1; p=none; rua=mailto:dmarc@example.com"),
    }
    # The `_dmarc` label never becomes a node.
    assert not any("_dmarc" in e.id for e in observation.entities)
    assert observation.provenance.query == "example.com A/AAAA/MX/NS/TXT +_dmarc"


async def test_a_subdomain_without_its_own_dmarc_is_not_reported_absent(
    plugin_ctx: PluginContext,
) -> None:
    # RFC 7489 section 6.6.3: the receiver falls back to the organizational domain's policy,
    # so a missing `_dmarc.shop` says nothing about the effective policy.
    resolver = FakeResolver(
        {
            ("shop.example.com", "MX"): DnsAnswer(
                "NOERROR", (rr("shop.example.com", "MX", "mx.example.net"),)
            ),
            ("_dmarc.shop.example.com", "TXT"): DnsAnswer("NXDOMAIN"),
        }
    )
    [observation] = await run(resolver, "shop.example.com", plugin_ctx)
    assert domain(observation, "shop.example.com").records == ()


async def test_a_root_without_dmarc_is_a_confirmed_absence(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver(
        {
            ("example.com", "A"): DnsAnswer("NOERROR", (rr("example.com", "A", "192.0.2.1"),)),
            ("_dmarc.example.com", "TXT"): DnsAnswer("NXDOMAIN"),
        }
    )
    [observation] = await run(resolver, "example.com", plugin_ctx)
    assert DnsRecord(type="DMARC", value="") in domain(observation, "example.com").records


async def test_several_dmarc_records_are_all_kept(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver(
        {
            ("example.com", "A"): DnsAnswer("NOERROR", (rr("example.com", "A", "192.0.2.1"),)),
            ("_dmarc.example.com", "TXT"): DnsAnswer(
                "NOERROR",
                (
                    rr("_dmarc.example.com", "TXT", "v=DMARC1; p=none"),
                    rr("_dmarc.example.com", "TXT", "v=DMARC1; p=reject"),
                ),
            ),
        }
    )
    [observation] = await run(resolver, "example.com", plugin_ctx)
    values = {r.value for r in domain(observation, "example.com").records if r.type == "DMARC"}
    assert values == {"v=DMARC1; p=none", "v=DMARC1; p=reject"}


async def test_a_failed_dmarc_lookup_records_nothing(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver(
        {
            ("example.com", "A"): DnsAnswer("NOERROR", (rr("example.com", "A", "192.0.2.10"),)),
            ("_dmarc.example.com", "TXT"): DnsError("Timeout"),
        }
    )
    [observation] = await run(resolver, "example.com", plugin_ctx)
    assert domain(observation, "example.com").records == ()


async def test_out_of_scope_names_are_only_resolved(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver(
        {
            ("cdn.example.net", "A"): DnsAnswer(
                "NOERROR", (rr("cdn.example.net", "A", "198.51.100.9"),)
            )
        }
    )
    [observation] = await run(resolver, "cdn.example.net", plugin_ctx)
    assert resolver.queries == [("cdn.example.net", "A"), ("cdn.example.net", "AAAA")]
    assert observation.provenance.query == "cdn.example.net A/AAAA"


async def test_a_dangling_cname_marks_its_missing_target(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver(
        {
            ("old.example.com", "A"): DnsAnswer(
                "NXDOMAIN", (rr("old.example.com", "CNAME", "gone.herokuapp.example"),)
            ),
            ("old.example.com", "AAAA"): DnsAnswer(
                "NXDOMAIN", (rr("old.example.com", "CNAME", "gone.herokuapp.example"),)
            ),
        }
    )
    [observation] = await run(resolver, "old.example.com", plugin_ctx)
    assert edges(observation) == {
        ("domain:old.example.com", RelationType.CNAME_TO, "domain:gone.herokuapp.example")
    }
    assert domain(observation, "gone.herokuapp.example").records == (
        DnsRecord(type="RCODE", value="NXDOMAIN"),
    )
    assert domain(observation, "old.example.com").records == ()


async def test_a_name_that_does_not_exist_is_marked_itself(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver({("gone.example.com", "A"): DnsAnswer("NXDOMAIN")})
    [observation] = await run(resolver, "gone.example.com", plugin_ctx)
    assert domain(observation, "gone.example.com").records == (
        DnsRecord(type="RCODE", value="NXDOMAIN"),
    )


async def test_failures_and_invalid_values_are_skipped(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver(
        {
            ("www.example.com", "A"): DnsError("Timeout"),
            ("www.example.com", "AAAA"): DnsAnswer(
                "NOERROR",
                (
                    rr("www.example.com", "AAAA", "not-an-ip"),
                    rr("www.example.com", "CNAME", "www.example.com"),
                    rr("www.example.com", "CNAME", "bad_target.example.net"),
                    rr("bad_owner.example.com", "A", "192.0.2.1"),
                    rr("www.example.com", "CAA", '0 issue "ca.example.net"'),
                    rr("other.example.com", "TXT", "not the queried name"),
                    rr("www.example.com", "AAAA", "2001:db8::2"),
                ),
            ),
        }
    )
    [observation] = await run(resolver, "www.example.com", plugin_ctx)
    assert edges(observation) == {
        ("domain:www.example.com", RelationType.RESOLVES_TO, "ip:2001:db8::2")
    }


async def test_nothing_found_means_no_observation(plugin_ctx: PluginContext) -> None:
    resolver = FakeResolver({("www.example.com", "A"): DnsError("Timeout")})
    assert await run(resolver, "www.example.com", plugin_ctx) == []


async def test_every_query_spends_a_rate_limit_token(
    plugin_ctx: PluginContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    spent: list[str] = []

    async def acquire(source: str) -> None:
        spent.append(source)

    monkeypatch.setattr(plugin_ctx.limiter, "acquire", acquire)
    resolver = FakeResolver({})
    await run(resolver, "example.com", plugin_ctx)
    assert spent == ["dns"] * len(resolver.queries)
    assert len(resolver.queries) == 6  # A, AAAA, MX, NS, TXT, _dmarc TXT


async def test_ignores_entities_that_are_not_domains(plugin_ctx: PluginContext) -> None:
    plugin = DnsPlugin(FakeResolver({}))
    assert await plugin.run(IPAddress(address="192.0.2.1"), plugin_ctx) == []


async def test_mail_and_name_servers_of_a_cname_target_are_not_kept(
    plugin_ctx: PluginContext,
) -> None:
    chain = rr("shop.example.com", "CNAME", "shops.saas.example.net")
    resolver = FakeResolver(
        {
            ("shop.example.com", "MX"): DnsAnswer(
                "NOERROR", (chain, rr("shops.saas.example.net", "MX", "mx.saas.example.net"))
            ),
            ("shop.example.com", "NS"): DnsAnswer(
                "NOERROR", (chain, rr("shops.saas.example.net", "NS", "ns.saas.example.net"))
            ),
        }
    )
    [observation] = await run(resolver, "shop.example.com", plugin_ctx)
    assert edges(observation) == {
        ("domain:shop.example.com", RelationType.CNAME_TO, "domain:shops.saas.example.net")
    }
    # No MX was found for the queried name itself: no DMARC lookup either.
    assert ("_dmarc.shop.example.com", "TXT") not in resolver.queries
