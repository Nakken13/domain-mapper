import asyncio
import logging
from collections.abc import Callable, Iterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from surfacemap.collect.cache import ResponseCache
from surfacemap.collect.engine import Engine, EngineLimits
from surfacemap.collect.http import HttpClient
from surfacemap.collect.ratelimit import RateLimiter
from surfacemap.config import Settings
from surfacemap.models import (
    ASN,
    Domain,
    Entity,
    IPAddress,
    Observation,
    Provenance,
    Relation,
    RelationType,
)
from surfacemap.plugins.base import PluginBase, PluginContext, ScopeView
from surfacemap.scope import OutOfScopeError, Scope, ScopeEntry

NOW = datetime(2026, 6, 1, tzinfo=UTC)
Handler = Callable[[Entity], list[Observation]]


def obs(source: str, *items: Entity | Relation) -> Observation:
    return Observation(
        provenance=Provenance(source=source, retrieved_at=NOW, query="q"),
        entities=tuple(i for i in items if not isinstance(i, Relation)),
        relations=tuple(i for i in items if isinstance(i, Relation)),
    )


def dom(fqdn: str, in_scope: bool = True) -> Domain:
    return Domain(fqdn=fqdn, in_scope=in_scope)


class Fake(PluginBase):
    """Table-driven plugin: `handler(entity)` returns its observations; calls are recorded."""

    def __init__(
        self,
        name: str,
        consumes: set[str],
        handler: Handler,
        runs_out_of_scope: bool = False,
    ) -> None:
        self.name = name
        self.consumes = frozenset(consumes)
        self.runs_out_of_scope = runs_out_of_scope
        self.handler = handler
        self.calls: list[str] = []

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        self.calls.append(entity.id)
        return self.handler(entity)


def table(name: str, mapping: dict[str, list[Entity | Relation]]) -> Handler:
    def handler(entity: Entity) -> list[Observation]:
        items = mapping.get(entity.id)
        return [obs(name, *items)] if items else []

    return handler


@pytest.fixture
def ctx(tmp_path: Path) -> Iterator[PluginContext]:
    view = ScopeView(Scope([ScopeEntry(domain="example.com", authorization="x")]), date(2026, 6, 1))
    with ResponseCache(tmp_path / "c.sqlite", ttl=timedelta(hours=1)) as cache:
        limiter = RateLimiter({})
        yield PluginContext(
            http=HttpClient(limiter, cache, view.is_target_host),
            cache=cache,
            limiter=limiter,
            settings=Settings(_env_file=None),
            scope=view,
        )


# Scenario: crt.sh-like subdomain finder on the root, DNS everywhere, ASN on IPs.
WWW, API, CDN = dom("www.example.com"), dom("api.example.com"), dom("d1.cloudfront.net", False)
IP_WWW, IP_CDN = IPAddress(address="192.0.2.10"), IPAddress(address="198.51.100.7")


def scenario() -> tuple[Fake, Fake, Fake]:
    subs = Fake(
        "subs",
        {"domain"},
        table(
            "subs",
            {
                "domain:example.com": [
                    WWW,
                    API,
                    Relation.between(dom("example.com"), RelationType.HAS_SUBDOMAIN, WWW),
                ]
            },
        ),
    )
    dns = Fake(
        "dns",
        {"domain"},
        table(
            "dns",
            {
                WWW.id: [WWW, IP_WWW, Relation.between(WWW, RelationType.RESOLVES_TO, IP_WWW)],
                API.id: [API, CDN, Relation.between(API, RelationType.CNAME_TO, CDN)],
                CDN.id: [CDN, IP_CDN, Relation.between(CDN, RelationType.RESOLVES_TO, IP_CDN)],
            },
        ),
        runs_out_of_scope=True,
    )
    asn = Fake(
        "asn",
        {"ip"},
        lambda ip: [
            obs(
                "asn",
                ip,
                ASN(number=64500),
                Relation(source=ip.id, type=RelationType.ANNOUNCED_BY, target="asn:64500"),
            )
        ],
    )
    return subs, dns, asn


async def test_out_of_scope_seed_is_refused_before_any_plugin_call(ctx: PluginContext) -> None:
    subs, dns, asn = scenario()
    with pytest.raises(OutOfScopeError):
        await Engine([subs, dns, asn], ctx).run("evil.org")
    assert subs.calls == dns.calls == asn.calls == []


async def test_seed_is_a_node_even_without_results(ctx: PluginContext) -> None:
    graph = await Engine([], ctx).run("Example.COM.")
    node = graph.nodes["domain:example.com"]
    assert node.entity == dom("example.com")
    assert node.sources == frozenset({"surfacemap"})


async def test_new_subdomains_are_fed_back_to_dns(ctx: PluginContext) -> None:
    subs, dns, asn = scenario()
    graph = await Engine([subs, dns, asn], ctx).run("example.com")
    assert set(dns.calls) >= {"domain:example.com", WWW.id, API.id}
    assert asn.calls == [IP_WWW.id]
    assert graph.nodes["asn:64500"].sources == frozenset({"asn"})


async def test_out_of_scope_node_is_recorded_and_resolved_but_never_enriched(
    ctx: PluginContext,
) -> None:
    subs, dns, asn = scenario()
    graph = await Engine([subs, dns, asn], ctx).run("example.com")
    assert graph.nodes[CDN.id].entity.in_scope is False  # type: ignore[union-attr]
    assert CDN.id in dns.calls  # DNS-resolved
    assert CDN.id not in subs.calls  # not enriched
    assert IP_CDN.id in graph.nodes
    assert IP_CDN.id not in asn.calls  # the IP behind the CDN is not enriched either


async def test_engine_stamps_in_scope_whatever_the_plugin_claims(ctx: PluginContext) -> None:
    liar = Fake(
        "liar",
        {"domain"},
        table("liar", {"domain:example.com": [dom("x.example.com", False), dom("evil.org")]}),
    )
    graph = await Engine([liar], ctx).run("example.com")
    assert graph.nodes["domain:x.example.com"].entity.in_scope is True  # type: ignore[union-attr]
    assert graph.nodes["domain:evil.org"].entity.in_scope is False  # type: ignore[union-attr]


async def test_entity_reached_in_scope_later_is_upgraded_once(ctx: PluginContext) -> None:
    # Wave 1: the shared IP is seen behind the CDN only. Wave 2: an in-scope host resolves to it.
    shared = IP_CDN
    late = dom("late.example.com")
    dns = Fake(
        "dns",
        {"domain"},
        table(
            "dns",
            {
                "domain:example.com": [CDN, late],
                CDN.id: [shared, Relation.between(CDN, RelationType.RESOLVES_TO, shared)],
                late.id: [dom("later.example.com")],
                "domain:later.example.com": [shared],
            },
        ),
        runs_out_of_scope=True,
    )
    asn = Fake("asn", {"ip"}, lambda ip: [obs("asn", ASN(number=64500))])
    ptr = Fake("ptr", {"ip"}, lambda ip: [], runs_out_of_scope=True)
    await Engine([dns, asn, ptr], ctx).run("example.com")
    assert asn.calls == [shared.id]  # only once upgraded
    assert ptr.calls == [shared.id]  # already ran at RESOLVE_ONLY: not re-run on upgrade


async def test_each_plugin_runs_once_per_entity(ctx: PluginContext) -> None:
    subs, dns, asn = scenario()
    await Engine([subs, dns, asn], ctx).run("example.com")
    for plugin in (subs, dns, asn):
        assert len(plugin.calls) == len(set(plugin.calls))


async def test_cname_cycle_terminates(ctx: PluginContext) -> None:
    a, b = dom("a.example.com"), dom("b.example.com")
    dns = Fake(
        "dns",
        {"domain"},
        table(
            "dns",
            {
                "domain:example.com": [a],
                a.id: [b, Relation.between(a, RelationType.CNAME_TO, b)],
                b.id: [a, Relation.between(b, RelationType.CNAME_TO, a)],
            },
        ),
        runs_out_of_scope=True,
    )
    graph = await Engine([dns], ctx).run("example.com")
    assert sorted(dns.calls) == sorted(["domain:example.com", a.id, b.id])
    assert (a.id, RelationType.CNAME_TO, b.id) in graph.edges


async def test_depth_is_bounded(ctx: PluginContext) -> None:
    def chain(entity: Entity) -> list[Observation]:
        assert isinstance(entity, Domain)
        return [obs("chain", dom("x." + entity.fqdn))]

    plugin = Fake("chain", {"domain"}, chain)
    await Engine([plugin], ctx, EngineLimits(max_depth=2)).run("example.com")
    assert plugin.calls == ["domain:example.com", "domain:x.example.com", "domain:x.x.example.com"]


async def test_work_items_are_bounded_deterministically(
    ctx: PluginContext, caplog: pytest.LogCaptureFixture
) -> None:
    many = [dom(f"h{i:02d}.example.com") for i in range(20)]
    finder = Fake("finder", {"domain"}, table("finder", {"domain:example.com": list(many)}))
    dns = Fake("dns", {"domain"}, lambda e: [], runs_out_of_scope=True)
    await Engine([finder, dns], ctx, EngineLimits(max_work_items=6)).run("example.com")
    assert len(finder.calls) + len(dns.calls) == 6
    # Seed wave: 2 items. The next wave is sorted by (entity id, plugin) before truncation.
    kept = {"domain:h00.example.com", "domain:h01.example.com"}
    assert set(dns.calls[1:]) == set(finder.calls[1:]) == kept
    assert "work-item budget" in caplog.text


async def test_failing_plugin_is_isolated_and_logged_by_type_only(
    ctx: PluginContext, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(entity: Entity) -> list[Observation]:
        raise RuntimeError("https://api.example.net/?key=SECRET123")

    broken = Fake("broken", {"domain"}, boom)
    subs, dns, asn = scenario()
    graph = await Engine([broken, subs, dns, asn], ctx).run("example.com")
    assert WWW.id in graph.nodes
    assert "broken" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "SECRET123" not in caplog.text


async def test_hung_plugin_times_out(ctx: PluginContext, caplog: pytest.LogCaptureFixture) -> None:
    class Hung(Fake):
        async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
            await asyncio.sleep(10)
            return []

    hung = Hung("hung", {"domain"}, lambda e: [])
    subs, _, _ = scenario()
    graph = await Engine([hung, subs], ctx, EngineLimits(plugin_timeout=0.05)).run("example.com")
    assert WWW.id in graph.nodes
    assert "TimeoutError" in caplog.text


async def test_applies_to_and_enabled_are_respected(ctx: PluginContext) -> None:
    class RootOnly(Fake):
        def applies_to(self, entity: Entity, scope: ScopeView) -> bool:
            return isinstance(entity, Domain) and scope.root_of(entity.fqdn) == entity.fqdn

    class Disabled(Fake):
        def enabled(self, settings: Settings) -> bool:
            return False

    root_only = RootOnly("rootonly", {"domain"}, table("rootonly", {"domain:example.com": [WWW]}))
    disabled = Disabled("off", {"domain"}, lambda e: [])
    await Engine([root_only, disabled], ctx).run("example.com")
    assert root_only.calls == ["domain:example.com"]
    assert disabled.calls == []


async def test_observation_with_foreign_provenance_is_dropped(
    ctx: PluginContext, caplog: pytest.LogCaptureFixture
) -> None:
    impostor = Fake("impostor", {"domain"}, lambda e: [obs("crtsh", WWW)])
    graph = await Engine([impostor], ctx).run("example.com")
    assert WWW.id not in graph.nodes
    assert "impostor" in caplog.text


async def test_has_subdomain_links_each_domain_to_its_nearest_parent(ctx: PluginContext) -> None:
    deep = dom("a.b.www.example.com")
    finder = Fake("finder", {"domain"}, table("finder", {"domain:example.com": [WWW, deep, CDN]}))
    graph = await Engine([finder], ctx).run("example.com")
    edges = {k for k in graph.edges if k[1] is RelationType.HAS_SUBDOMAIN}
    assert edges == {
        ("domain:example.com", RelationType.HAS_SUBDOMAIN, WWW.id),
        (WWW.id, RelationType.HAS_SUBDOMAIN, deep.id),
    }
    # Structural edges do not count as a source having seen the node.
    assert graph.nodes[WWW.id].sources == frozenset({"finder"})


async def test_unredacted_values_never_reach_the_next_wave(ctx: PluginContext) -> None:
    seen: list[Entity] = []

    class Spy(Fake):
        async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
            seen.append(entity)
            return await super().run(entity, ctx)

    finder = Fake("finder", {"domain"}, table("finder", {"domain:example.com": [WWW]}))
    spy = Spy("spy", {"domain"}, lambda e: [])
    graph = await Engine([finder, spy], ctx).run("example.com")
    www_seen = next(e for e in seen if e.id == WWW.id)
    assert www_seen == graph.nodes[WWW.id].entity  # read back from the (redacted) graph


def test_limits_are_validated() -> None:
    with pytest.raises(ValueError, match="max_depth"):
        EngineLimits(max_depth=-1)
    with pytest.raises(ValueError, match="positive"):
        EngineLimits(concurrency=0)


async def test_non_observation_results_are_dropped(
    ctx: PluginContext, caplog: pytest.LogCaptureFixture
) -> None:
    weird = Fake("weird", {"domain"}, lambda e: ["not an observation"])  # type: ignore[list-item]
    caplog.set_level(logging.WARNING)
    graph = await Engine([weird], ctx).run("example.com")
    assert list(graph.nodes) == ["domain:example.com"]
    assert "weird" in caplog.text
