"""Helpers shared by every exporter, so they agree on ids, order and node properties."""

from __future__ import annotations

from typing import Any

from surfacemap.graph.builder import EdgeKey, SurfaceGraph
from surfacemap.models.entities import id_kind

# entity id prefix -> (entity `kind` value, Neo4j label)
_BY_PREFIX = {
    "domain": ("domain", "Domain"),
    "ip": ("ip", "IP"),
    "asn": ("asn", "ASN"),
    "cert": ("certificate", "Certificate"),
    "tech": ("technology", "Technology"),
    "url": ("archived_url", "ArchivedUrl"),
}


def _entry(node_id: str) -> tuple[str, str]:
    try:
        return _BY_PREFIX[id_kind(node_id)]
    except KeyError:
        raise ValueError(f"unknown entity id prefix: {node_id!r}") from None


def kind_of(node_id: str) -> str:
    return _entry(node_id)[0]


def label_of(node_id: str) -> str:
    return _entry(node_id)[1]


def node_ids(graph: SurfaceGraph) -> list[str]:
    """Every node id, plus edge endpoints no observation described, sorted."""
    ids = set(graph.nodes)
    for source, _, target in graph.edges:
        ids.update((source, target))
    return sorted(ids)


def sorted_edge_keys(graph: SurfaceGraph) -> list[EdgeKey]:
    return sorted(graph.edges, key=lambda k: (k[0], str(k[1]), k[2]))


def node_props(graph: SurfaceGraph, node_id: str) -> dict[str, Any]:
    """JSON-safe properties; `kind` is always set, even for a not-yet-described endpoint."""
    node = graph.nodes.get(node_id)
    if node is None:
        return {"kind": kind_of(node_id), "sources": []}
    props = node.entity.model_dump(mode="json", exclude_none=True)
    props.pop("id", None)
    props["sources"] = sorted(node.sources)
    return props
