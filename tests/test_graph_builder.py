from datetime import UTC, datetime
from itertools import permutations

import pytest

from surfacemap.graph.builder import SurfaceGraph, build_graph, merge_entities
from surfacemap.models import (
    ASN,
    ArchivedURL,
    Certificate,
    DnsRecord,
    Domain,
    Entity,
    IPAddress,
    Observation,
    Provenance,
    Relation,
)

T0 = datetime(2026, 1, 1, tzinfo=UTC)
T1 = datetime(2026, 6, 1, tzinfo=UTC)
T2 = datetime(2026, 9, 1, tzinfo=UTC)


def obs(source: str, *items: Entity | Relation) -> Observation:
    return Observation(
        provenance=Provenance(source=source, retrieved_at=T0, query="example.com"),
        entities=[i for i in items if not isinstance(i, Relation)],
        relations=[i for i in items if isinstance(i, Relation)],
    )


WWW = Domain(fqdn="www.example.com", in_scope=True)
IP = IPAddress(address="192.0.2.1")
RESOLVES = Relation(source=WWW.id, type="RESOLVES_TO", target=IP.id)


def test_same_entity_from_two_sources_is_one_node_with_both_sources() -> None:
    graph = build_graph([obs("crtsh", WWW), obs("dns", WWW, IP, RESOLVES)])
    assert set(graph.nodes) == {WWW.id, IP.id}
    assert graph.nodes[WWW.id].sources == frozenset({"crtsh", "dns"})
    assert graph.sources_by_node() == {
        WWW.id: frozenset({"crtsh", "dns"}),
        IP.id: frozenset({"dns"}),
    }


def test_duplicate_edges_are_merged_and_sources_unioned() -> None:
    graph = build_graph([obs("dns", WWW, IP, RESOLVES), obs("passivedns", WWW, IP, RESOLVES)])
    assert list(graph.edges) == [RESOLVES.key]
    assert graph.edges[RESOLVES.key].sources == frozenset({"dns", "passivedns"})


def test_merge_is_idempotent() -> None:
    once = build_graph([obs("dns", WWW, IP, RESOLVES)])
    twice = build_graph([obs("dns", WWW, IP, RESOLVES)] * 2)
    assert once == twice


def test_missing_attribute_is_filled_by_another_source() -> None:
    graph = build_graph(
        [
            obs("dns", IPAddress(address="192.0.2.1")),
            obs("geo", IPAddress(address="192.0.2.1", country="FR")),
        ]
    )
    node = graph.nodes[IP.id].entity
    assert isinstance(node, IPAddress)
    assert node.country == "FR"


CONFLICTING = [
    obs(
        "a",
        Domain(fqdn="x.example.com", in_scope=True, records=[DnsRecord(type="TXT", value="b")]),
        ASN(number=64496, holder="ZETA"),
        ArchivedURL(host="x.example.com", path="/", first_seen=T1, last_seen=T1),
    ),
    obs(
        "b",
        Domain(fqdn="x.example.com", in_scope=False, records=[DnsRecord(type="TXT", value="a")]),
        ASN(number=64496, holder="ALPHA", country="FR"),
        ArchivedURL(host="x.example.com", path="/", first_seen=T0, last_seen=T2),
    ),
    obs("c", Domain(fqdn="x.example.com", in_scope=True)),
]


def test_merge_is_order_independent() -> None:
    graphs = [build_graph(order) for order in permutations(CONFLICTING)]
    assert all(g == graphs[0] for g in graphs)


def test_conflict_resolution_rules() -> None:
    graph = build_graph(CONFLICTING)
    domain = graph.nodes["domain:x.example.com"].entity
    asn = graph.nodes["asn:64496"].entity
    url = graph.nodes["url:x.example.com/"].entity
    assert isinstance(domain, Domain)
    assert isinstance(asn, ASN)
    assert isinstance(url, ArchivedURL)
    assert domain.in_scope is False  # fail closed: any source saying out-of-scope wins
    assert [r.value for r in domain.records] == ["a", "b"]  # sorted union
    assert (asn.holder, asn.country) == ("ALPHA", "FR")
    assert (url.first_seen, url.last_seen) == (T0, T2)  # widest window


def test_observations_are_redacted_before_entering_the_graph() -> None:
    cert = Certificate(
        sha256="a" * 64,
        issuer="R3",
        not_before=T0,
        not_after=T1,
        sans=["jane@example.com", "example.com"],
    )
    graph = build_graph([obs("crtsh", cert)])
    stored = graph.nodes[cert.id].entity
    assert isinstance(stored, Certificate)
    assert stored.sans == ("example.com",)


def test_merge_accumulates_on_an_existing_graph() -> None:
    graph = SurfaceGraph()
    graph.merge(obs("dns", WWW))
    graph.merge(obs("crtsh", WWW))
    assert graph.nodes[WWW.id].sources == frozenset({"crtsh", "dns"})


def test_graph_views_are_read_only() -> None:
    graph = build_graph([obs("dns", WWW)])
    with pytest.raises(TypeError):
        graph.nodes["domain:evil.example"] = graph.nodes[WWW.id]  # type: ignore[index]


def test_merge_entities_refuses_different_ids() -> None:
    with pytest.raises(ValueError, match="cannot merge"):
        merge_entities(WWW, IP)
