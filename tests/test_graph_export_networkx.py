import json
from datetime import UTC, datetime

import networkx as nx

from domain_mapper.graph.builder import build_graph
from domain_mapper.graph.export import to_networkx, write_graphml, write_json
from domain_mapper.models import (
    Certificate,
    Domain,
    Entity,
    IPAddress,
    Observation,
    Provenance,
    Relation,
)

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def obs(source: str, *items: Entity | Relation) -> Observation:
    return Observation(
        provenance=Provenance(source=source, retrieved_at=T0, query="example.com"),
        entities=[i for i in items if not isinstance(i, Relation)],
        relations=[i for i in items if isinstance(i, Relation)],
    )


WWW = Domain(fqdn="www.example.com", in_scope=True)
API = Domain(fqdn="api.example.com", in_scope=True)
IP = IPAddress(address="192.0.2.1")
RESOLVES = Relation(source=WWW.id, type="RESOLVES_TO", target=IP.id)
RESOLVES_API = Relation(source=API.id, type="RESOLVES_TO", target=IP.id)


def sample_graph():
    return build_graph([obs("dns", WWW, API, IP, RESOLVES), obs("crtsh", WWW, RESOLVES_API)])


def test_to_networkx_keeps_nodes_edges_and_sources() -> None:
    g = to_networkx(sample_graph())
    assert isinstance(g, nx.MultiDiGraph)
    assert set(g.nodes) == {WWW.id, API.id, IP.id}
    assert g.nodes[WWW.id]["sources"] == ["crtsh", "dns"]
    assert g.nodes[WWW.id]["kind"] == "domain"
    assert g.nodes[WWW.id]["in_scope"] is True
    edge = g.get_edge_data(WWW.id, IP.id, key="RESOLVES_TO")
    assert edge["sources"] == ["dns"]


def test_to_networkx_adds_dangling_edge_endpoints() -> None:
    graph = build_graph([obs("dns", RESOLVES)])
    g = to_networkx(graph)
    assert set(g.nodes) == {WWW.id, IP.id}


def test_json_export_is_valid_and_reproducible(tmp_path) -> None:
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    write_json(sample_graph(), first)
    write_json(build_graph(reversed(list(_observations()))), second)
    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")
    data = json.loads(first.read_text(encoding="utf-8"))
    assert [n["id"] for n in data["nodes"]] == sorted(n["id"] for n in data["nodes"])
    assert len(data["edges"]) == 2


def _observations():
    return [obs("dns", WWW, API, IP, RESOLVES), obs("crtsh", WWW, RESOLVES_API)]


def test_graphml_roundtrip_flattens_non_scalar_attributes(tmp_path) -> None:
    cert = Certificate(
        sha256="ab" * 32,
        issuer="Test CA",
        not_before=T0,
        not_after=datetime(2027, 1, 1, tzinfo=UTC),
        sans=("www.example.com", "api.example.com"),
    )
    graph = build_graph(
        [obs("crtsh", WWW, cert, Relation(source=WWW.id, type="SECURED_BY", target=cert.id))]
    )
    path = tmp_path / "g.graphml"
    write_graphml(graph, path)
    back = nx.read_graphml(path)
    assert set(back.nodes) == {WWW.id, cert.id}
    assert json.loads(back.nodes[cert.id]["sans"]) == ["www.example.com", "api.example.com"]
    assert json.loads(back.nodes[WWW.id]["sources"]) == ["crtsh"]
