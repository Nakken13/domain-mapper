"""Graph data for Cytoscape.js, safe to embed inside an HTML `<script>` block."""

from __future__ import annotations

import json
from typing import Any

from surfacemap.graph._common import kind_of, node_ids, node_props, sorted_edge_keys
from surfacemap.graph.builder import SurfaceGraph
from surfacemap.models.entities import id_kind


def _label(node_id: str) -> str:
    return node_id.partition(":")[2]


def graph_elements(graph: SurfaceGraph) -> dict[str, list[dict[str, Any]]]:
    """Nodes and edges as plain dicts; endpoints no plugin described are included."""
    nodes = []
    for node_id in node_ids(graph):
        props = node_props(graph, node_id)
        nodes.append(
            {
                "id": node_id,
                "label": _label(node_id),
                "kind": kind_of(node_id),
                # Only domains carry a scope flag; an undescribed endpoint is not authorized.
                "in_scope": bool(props.get("in_scope", False)) and id_kind(node_id) == "domain",
            }
        )
    edges = [
        {"source": source, "type": str(relation_type), "target": target}
        for source, relation_type, target in sorted_edge_keys(graph)
    ]
    return {"nodes": nodes, "edges": edges}


def to_script_json(data: object) -> str:
    """JSON that cannot terminate or reopen a `<script>` element.

    Node labels come from DNS and certificates, i.e. from third parties. `<` and `&`
    are escaped as unicode so `</script>` and `<!--` never appear literally; the
    parsed value is unchanged.
    """
    return (
        json.dumps(data, ensure_ascii=True, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
