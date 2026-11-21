"""Centrality metrics that flag the critical nodes of the surface.

A node is critical when removing it disconnects part of the surface (articulation point):
a single provider, certificate or IP the rest depends on. Betweenness ranks them.
Connectivity is computed on the undirected view: dependency direction does not matter for
"what breaks if this goes away".
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from domain_mapper.graph.builder import SurfaceGraph
from domain_mapper.graph.export import to_networkx


@dataclass(frozen=True)
class NodeMetrics:
    degree: int
    betweenness: float
    articulation: bool


def compute_metrics(graph: SurfaceGraph) -> dict[str, NodeMetrics]:
    g = to_networkx(graph)
    if g.number_of_nodes() == 0:
        return {}
    simple = nx.Graph(g.to_undirected())  # collapse parallel edges for connectivity metrics
    betweenness = nx.betweenness_centrality(simple)
    cut_points = set(nx.articulation_points(simple))
    return {
        node: NodeMetrics(
            degree=simple.degree(node),
            betweenness=betweenness[node],
            articulation=node in cut_points,
        )
        for node in sorted(g.nodes)
    }


def critical_nodes(metrics: dict[str, NodeMetrics]) -> list[str]:
    """Articulation points, most between first (ties broken by id for stable output)."""
    flagged = [n for n, m in metrics.items() if m.articulation]
    return sorted(flagged, key=lambda n: (-metrics[n].betweenness, n))
