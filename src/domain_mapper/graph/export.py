"""Export a `SurfaceGraph` to NetworkX, JSON and GraphML.

Output is reproducible: nodes sorted by id, edges by `(source, type, target)`, source sets
as sorted lists. The graph was already redacted at merge time, so exports carry no PII.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx

from domain_mapper.graph._common import node_ids, node_props, sorted_edge_keys
from domain_mapper.graph.builder import SurfaceGraph


def to_networkx(graph: SurfaceGraph) -> nx.MultiDiGraph:
    """Directed multigraph; edge key = relation type, so parallel typed edges coexist."""
    g = nx.MultiDiGraph()
    for node_id in node_ids(graph):
        g.add_node(node_id, **node_props(graph, node_id))
    for key in sorted_edge_keys(graph):
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
