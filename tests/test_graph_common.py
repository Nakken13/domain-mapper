from datetime import UTC, datetime

import pytest

from surfacemap.graph._common import kind_of, label_of
from surfacemap.graph.builder import build_graph
from surfacemap.graph.export import to_networkx
from surfacemap.graph.metrics import compute_metrics
from surfacemap.graph.neo4j_export import cypher_statements
from surfacemap.models import Certificate, Domain, IPAddress, Observation, Provenance, Relation

T0 = datetime(2026, 1, 1, tzinfo=UTC)
WWW = Domain(fqdn="www.example.com", in_scope=True)
IP = IPAddress(address="192.0.2.1")
CERT = Certificate(
    sha256="ab" * 32,
    issuer="Test CA",
    not_before=T0,
    not_after=datetime(2027, 1, 1, tzinfo=UTC),
)


def observation(*items):
    return Observation(
        provenance=Provenance(source="dns", retrieved_at=T0, query="example.com"),
        entities=tuple(i for i in items if not isinstance(i, Relation)),
        relations=tuple(i for i in items if isinstance(i, Relation)),
    )


def test_dangling_endpoint_gets_the_same_kind_as_a_real_entity() -> None:
    secured = Relation(source=WWW.id, type="SECURED_BY", target=CERT.id)
    dangling = to_networkx(build_graph([observation(secured)]))
    real = to_networkx(build_graph([observation(CERT)]))
    assert dangling.nodes[CERT.id]["kind"] == real.nodes[CERT.id]["kind"] == "certificate"


def test_unknown_id_prefix_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown entity id prefix"):
        kind_of("foo:bar")
    with pytest.raises(ValueError, match="unknown entity id prefix"):
        label_of("foo:bar")


def test_neo4j_edge_match_is_labelled_so_the_unique_index_is_used() -> None:
    resolves = Relation(source=WWW.id, type="RESOLVES_TO", target=IP.id)
    edge = next(q for q, _ in cypher_statements(build_graph([observation(resolves)])) if "-[" in q)
    assert "MATCH (a:Domain {id: $source}), (b:IP {id: $target})" in edge


def test_neo4j_dangling_node_carries_kind_and_node_set_replaces_properties() -> None:
    secured = Relation(source=WWW.id, type="SECURED_BY", target=CERT.id)
    statements = cypher_statements(build_graph([observation(secured)]))
    query, params = next((q, p) for q, p in statements if q.startswith("MERGE (n:Certificate"))
    assert "SET n = $props" in query
    assert params["props"]["kind"] == "certificate"
    assert params["props"]["id"] == CERT.id


def test_degree_counts_distinct_neighbours_not_parallel_edges() -> None:
    target = Domain(fqdn="t.example.com", in_scope=True)
    rels = (
        Relation(source=WWW.id, type="CNAME_TO", target=target.id),
        Relation(source=WWW.id, type="MX", target=target.id),
    )
    metrics = compute_metrics(build_graph([observation(WWW, target, *rels)]))
    assert metrics[WWW.id].degree == 1
