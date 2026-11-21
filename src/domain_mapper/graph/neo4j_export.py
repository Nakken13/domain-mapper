"""Neo4j export: parameterized Cypher built from a `SurfaceGraph`.

The `neo4j` driver is an optional extra (`pip install domain-mapper[neo4j]`): this module never
imports it, the caller builds the driver and passes it in, so the export stays testable
with a fake. Labels come from the closed id-prefix table in `_common`, relationship types
from the `RelationType` enum; both are validated and every value travels as a query
parameter. Re-exporting is exact: `SET n = $props` drops properties that no longer exist.
"""

from __future__ import annotations

import json
import re
from typing import Any, Protocol

from domain_mapper.graph._common import label_of, node_ids, node_props, sorted_edge_keys
from domain_mapper.graph.builder import SurfaceGraph

Statement = tuple[str, dict[str, Any]]

_SAFE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def _label(name: str) -> str:
    if not _SAFE.match(name):
        raise ValueError(f"unsafe Cypher identifier: {name!r}")
    return name


def _prop(value: Any) -> Any:
    """Neo4j properties hold scalars or homogeneous scalar lists, not maps."""
    if isinstance(value, dict) or (
        isinstance(value, list) and any(isinstance(v, (dict, list)) for v in value)
    ):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return value


def cypher_statements(graph: SurfaceGraph) -> list[Statement]:
    """Constraints, then nodes (sorted by id), then edges (sorted by key). Idempotent."""
    ids = node_ids(graph)
    statements: list[Statement] = [
        (f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE", {})
        for label in sorted({_label(label_of(i)) for i in ids})
    ]
    for node_id in ids:
        props = {k: _prop(v) for k, v in node_props(graph, node_id).items()}
        props["id"] = node_id
        statements.append(
            (
                f"MERGE (n:{_label(label_of(node_id))} {{id: $id}}) SET n = $props",
                {"id": node_id, "props": props},
            )
        )
    for key in sorted_edge_keys(graph):
        source, rel_type, target = key
        statements.append(
            (
                f"MATCH (a:{_label(label_of(source))} {{id: $source}}), "
                f"(b:{_label(label_of(target))} {{id: $target}}) "
                f"MERGE (a)-[r:{_label(str(rel_type))}]->(b) SET r.sources = $sources",
                {
                    "source": source,
                    "target": target,
                    "sources": sorted(graph.edges[key].sources),
                },
            )
        )
    return statements


class Neo4jSession(Protocol):
    def run(self, query: str, parameters: dict[str, Any]) -> Any: ...
    def __enter__(self) -> Neo4jSession: ...
    def __exit__(self, *exc: object) -> Any: ...


class Neo4jDriver(Protocol):
    def session(self) -> Neo4jSession: ...


def push_to_neo4j(graph: SurfaceGraph, driver: Neo4jDriver) -> int:
    """Run every statement through `driver`; returns how many were executed."""
    statements = cypher_statements(graph)
    with driver.session() as session:
        for query, parameters in statements:
            session.run(query, parameters)
    return len(statements)
