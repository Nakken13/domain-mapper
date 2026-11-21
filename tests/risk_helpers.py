"""Shared test helper: build a SurfaceGraph from entities and relations."""

from __future__ import annotations

from datetime import UTC, datetime

from surfacemap.graph.builder import SurfaceGraph, build_graph
from surfacemap.models import Entity, Observation, Provenance, Relation


def graph_of(*items: Entity | Relation, source: str = "dns_records") -> SurfaceGraph:
    return build_graph(
        [
            Observation(
                provenance=Provenance(
                    source=source, retrieved_at=datetime(2026, 1, 1, tzinfo=UTC), query="q"
                ),
                entities=tuple(i for i in items if not isinstance(i, Relation)),
                relations=tuple(i for i in items if isinstance(i, Relation)),
            )
        ]
    )
