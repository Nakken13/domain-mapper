from datetime import UTC, datetime

import pytest

from surfacemap.graph.builder import build_graph
from surfacemap.graph.neo4j_export import cypher_statements, push_to_neo4j
from surfacemap.models import Domain, IPAddress, Observation, Provenance, Relation

T0 = datetime(2026, 1, 1, tzinfo=UTC)
WWW = Domain(fqdn="www.example.com", in_scope=True)
IP = IPAddress(address="192.0.2.1")
RESOLVES = Relation(source=WWW.id, type="RESOLVES_TO", target=IP.id)


def graph():
    observation = Observation(
        provenance=Provenance(source="dns", retrieved_at=T0, query="example.com"),
        entities=(WWW, IP),
        relations=(RESOLVES,),
    )
    return build_graph([observation])


def test_statements_use_merge_and_parameters_not_interpolated_values() -> None:
    statements = cypher_statements(graph())
    queries = [q for q, _ in statements]
    assert any(q.startswith("MERGE (n:Domain {id: $id})") for q in queries)
    assert any("MERGE (a)-[r:RESOLVES_TO]->(b)" in q for q in queries)
    assert all("example.com" not in q and "192.0.2.1" not in q for q in queries)


def test_statements_are_deterministic_constraints_then_nodes_then_edges() -> None:
    statements = cypher_statements(graph())
    assert statements == cypher_statements(graph())
    order = [
        0 if q.startswith("CREATE CONSTRAINT") else 1 if "-[" not in q else 2 for q, _ in statements
    ]
    assert order == sorted(order)
    assert set(order) == {0, 1, 2}


def test_node_parameters_carry_properties_and_sources() -> None:
    node_params = [p for q, p in cypher_statements(graph()) if q.startswith("MERGE (n:Domain")]
    assert node_params[0]["id"] == WWW.id
    assert node_params[0]["props"]["in_scope"] is True
    assert node_params[0]["props"]["sources"] == ["dns"]


class FakeSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def run(self, query: str, parameters: dict) -> None:
        self.calls.append((query, parameters))

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        return None


class FakeDriver:
    def __init__(self) -> None:
        self.session_obj = FakeSession()

    def session(self) -> FakeSession:
        return self.session_obj


def test_push_runs_every_statement_through_the_given_driver() -> None:
    driver = FakeDriver()
    push_to_neo4j(graph(), driver)
    assert driver.session_obj.calls == [(q, p) for q, p in cypher_statements(graph())]


def test_push_rejects_unsafe_label() -> None:
    from surfacemap.graph.neo4j_export import _label

    with pytest.raises(ValueError, match="unsafe Cypher identifier"):
        _label("bad`label")
