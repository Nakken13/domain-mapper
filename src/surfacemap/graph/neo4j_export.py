"""Neo4j export: parameterized Cypher built from a `SurfaceGraph`.

The `neo4j` driver is an optional extra (`pip install surfacemap[neo4j]`): this module never
imports it, the caller builds the driver and passes it in, so the export stays testable
with a fake. Labels and relationship types come from a closed set (entity id prefixes and the
`RelationType` enum) and are validated; every value travels as a query parameter.
"""

from __future__ import annotations

import json
import re
from typing import Any, Protocol

from surfacemap.graph.builder import SurfaceGraph
from surfacemap.models.entities import id_kind

Statement = tuple[str, dict[str, Any]]

_LABELS = {
    "domain": "Domain",
    "ip": "IP",
    "asn": "ASN",
    "cert": "Certificate",
    "tech": "Technology",
    "url": "ArchivedUrl",
}
_SAFE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def _label(name: str) -> str:
    if not _SAFE.match(name):
        raise ValueError(f"unsafe Cypher identifier: {name!r}")
    return name


def _node_label(node_id: str) -> str:
    return _label(_LABELS.get(id_kind(node_id), id_kind(node_id).capitalize()))


def _prop(value: Any) -> Any:
    """Neo4j properties hold scalars or homogeneous scalar lists, not maps."""
    if isinstance(value, dict) or (
        isinstance(value, list) and any(isinstance(v, (dict, list)) for v in value)
    ):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return value


def cypher_statements(graph: SurfaceGraph) -> list[Statement]:
    """Constraints, then nodes (sorted by id), then edges (sorted by key). Idempotent MERGEs."""
    ids = set(graph.nodes)
    for source, _, target in graph.edges:
        ids.update((source, target))
    labels = sorted({_node_label(i) for i in ids})
    statements: list[Statement] = [
        (f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE", {})
        for label in labels
    ]
    for node_id in sorted(ids):
        node = graph.nodes.get(node_id)
        props: dict[str, Any] = {"sources": []}
        if node is not None:
            dumped = node.entity.model_dump(mode="json", exclude_none=True)
            dumped.pop("id", None)
            props = {k: _prop(v) for k, v in dumped.items()}
            props["sources"] = sorted(node.sources)
        statements.append(
            (
                f"MERGE (n:{_node_label(node_id)} {{id: $id}}) SET n += $props",
                {"id": node_id, "props": props},
            )
        )
    for key in sorted(graph.edges, key=lambda k: (k[0], str(k[1]), k[2])):
        source, rel_type, target = key
        statements.append(
            (
                "MATCH (a {id: $source}), (b {id: $target}) "
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
