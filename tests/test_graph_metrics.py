from datetime import UTC, datetime

import pytest

from surfacemap.graph.builder import build_graph
from surfacemap.graph.metrics import compute_metrics, critical_nodes
from surfacemap.models import Domain, IPAddress, Observation, Provenance, Relation

T0 = datetime(2026, 1, 1, tzinfo=UTC)
A = Domain(fqdn="a.example.com", in_scope=True)
B = Domain(fqdn="b.example.com", in_scope=True)
C = Domain(fqdn="c.example.com", in_scope=True)
HUB = IPAddress(address="192.0.2.1")
LONER = IPAddress(address="192.0.2.9")
EDGE = IPAddress(address="192.0.2.50")


def graph():
    """a, b, c -> HUB (a star); HUB -> nothing else; a also -> EDGE (EDGE is a leaf off a)."""
    rels = [Relation(source=d.id, type="RESOLVES_TO", target=HUB.id) for d in (A, B, C)]
    rels.append(Relation(source=A.id, type="RESOLVES_TO", target=EDGE.id))
    observation = Observation(
        provenance=Provenance(source="dns", retrieved_at=T0, query="example.com"),
        entities=(A, B, C, HUB, EDGE, LONER),
        relations=tuple(rels),
    )
    return build_graph([observation])


def test_degree_counts_in_and_out_edges() -> None:
    metrics = compute_metrics(graph())
    assert metrics[HUB.id].degree == 3
    assert metrics[A.id].degree == 2
    assert metrics[LONER.id].degree == 0


def test_betweenness_is_highest_on_the_bridge_nodes() -> None:
    metrics = compute_metrics(graph())
    assert metrics[LONER.id].betweenness == pytest.approx(0.0)
    assert metrics[HUB.id].betweenness > metrics[B.id].betweenness
    assert metrics[A.id].betweenness > 0


def test_articulation_points_are_flagged() -> None:
    metrics = compute_metrics(graph())
    assert metrics[A.id].articulation is True  # removing a cuts EDGE off
    assert metrics[HUB.id].articulation is True  # removing hub cuts b and c off
    assert metrics[B.id].articulation is False
    assert metrics[LONER.id].articulation is False


def test_critical_nodes_ranked_articulation_first_then_betweenness() -> None:
    ranked = critical_nodes(compute_metrics(graph()))
    assert ranked == [HUB.id, A.id]  # hub 0.5 > a 0.3; leaves and the loner are not critical


def test_empty_graph_has_no_metrics() -> None:
    assert compute_metrics(build_graph([])) == {}
    assert critical_nodes({}) == []
