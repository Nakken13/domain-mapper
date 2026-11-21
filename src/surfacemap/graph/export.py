"""Export a `SurfaceGraph` to NetworkX, JSON and GraphML.

Output is reproducible: nodes sorted by id, edges by `(source, type, target)`, source sets
as sorted lists. The graph was already redacted at merge time, so exports carry no PII.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx

from surfacemap.graph.builder import SurfaceGraph
from surfacemap.models.entities import id_kind


def _node_attrs(graph: SurfaceGraph, node_id: str) -> dict[str, Any]:
    node = graph.nodes.get(node_id)
    if node is None:  # edge endpoint emitted by another observation: keep it, minimal
        return {"kind": id_kind(node_id), "sources": []}
    attrs = node.entity.model_dump(mode="json", exclude_none=True)
    attrs.pop("id", None)
    attrs["sources"] = sorted(node.sources)
    return attrs


def to_networkx(graph: SurfaceGraph) -> nx.MultiDiGraph:
    """Directed multigraph; edge key = relation type, so parallel typed edges coexist."""
    g = nx.MultiDiGraph()
    ids = set(graph.nodes)
    for source, _, target in graph.edges:
        ids.update((source, target))
    for node_id in sorted(ids):
        g.add_node(node_id, **_node_attrs(graph, node_id))
    for key in sorted(graph.edges, key=lambda k: (k[0], str(k[1]), k[2])):
        source, rel_type, target = key
        g.add_edge(source, target, key=str(rel_type), sources=sorted(graph.edges[key].sources))
    return g


def write_json(graph: SurfaceGraph, path: Path) -> None:
    g = to_networkx(graph)
    data = {
        "nodes": [{"id": n, **attrs} for n, attrs in sorted(g.nodes(data=True))],
        "edges": [
            {"source": s, "type": k, "target": t, **attrs}
            for s, t, k, attrs in sorted(g.edges(keys=True, data=True), key=lambda e: e[:3])
        ],
    }
    Path(path).write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _flatten(attrs: dict[str, Any]) -> dict[str, Any]:
    """GraphML only stores scalars: lists/dicts become JSON strings."""
    return {
        k: json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v
        for k, v in attrs.items()
    }


def write_graphml(graph: SurfaceGraph, path: Path) -> None:
    g = to_networkx(graph)
    flat = nx.MultiDiGraph()
    for node_id, attrs in g.nodes(data=True):
        flat.add_node(node_id, **_flatten(attrs))
    for s, t, k, attrs in g.edges(keys=True, data=True):
        flat.add_edge(s, t, key=k, type=k, **_flatten(attrs))
    nx.write_graphml(flat, Path(path), encoding="utf-8")
