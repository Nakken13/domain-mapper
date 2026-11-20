"""Merge plugin observations into one deduplicated graph.

Nodes are keyed by entity id, edges by `(source, type, target)`. Each node and edge keeps
the set of plugin names that saw it (the per-source sets behind the Venn diagram).

Every observation is redacted by `privacy.redact_observation` before it is merged, so no
personal datum can enter the graph whatever the plugin emitted.

When two sources describe the same entity differently, the merge is deterministic and
independent of arrival order (async collection finishes in any order):

* tuple fields (DNS records, SANs): sorted union;
* a missing value (`None`) is filled by the other source;
* `last_seen`: the latest date; every other conflict: the smallest value. For `in_scope`
  that means `False` wins (fail closed: one source saying out-of-scope is enough).

Node and edge *values* are order-independent; the *iteration order* of `nodes`/`edges`
follows arrival order, so exports must sort (by id / edge key) for reproducible output.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from surfacemap.models import Entity, Observation, Relation, RelationType
from surfacemap.privacy import redact_observation

EdgeKey = tuple[str, RelationType, str]


@dataclass(frozen=True)
class Node:
    entity: Entity
    sources: frozenset[str]


@dataclass(frozen=True)
class Edge:
    relation: Relation
    sources: frozenset[str]


def _merge_value(name: str, left: Any, right: Any) -> Any:
    if left == right:
        return left
    if left is None:
        return right
    if right is None:
        return left
    if isinstance(left, tuple):
        return tuple(sorted(set(left) | set(right), key=str))
    if name == "last_seen":
        return max(left, right)
    return min(left, right)


def merge_entities(left: Entity, right: Entity) -> Entity:
    """Combine two descriptions of the same entity (same id) into one."""
    if left.id != right.id:
        raise ValueError(f"cannot merge {left.id} with {right.id}")
    if left == right:
        return left
    merged = {
        name: _merge_value(name, getattr(left, name), getattr(right, name))
        for name in type(left).model_fields
    }
    return type(left).model_validate(merged)


@dataclass
class SurfaceGraph:
    """Deduplicated attack-surface graph. Only `merge` adds to it."""

    _nodes: dict[str, Node] = field(default_factory=dict)
    _edges: dict[EdgeKey, Edge] = field(default_factory=dict)

    @property
    def nodes(self) -> Mapping[str, Node]:
        return MappingProxyType(self._nodes)

    @property
    def edges(self) -> Mapping[EdgeKey, Edge]:
        return MappingProxyType(self._edges)

    def merge(self, observation: Observation) -> None:
        """Add one observation, after redaction, deduplicating nodes and edges."""
        clean = redact_observation(observation)
        source = clean.provenance.source
        for entity in clean.entities:
            existing = self._nodes.get(entity.id)
            if existing is None:
                self._nodes[entity.id] = Node(entity, frozenset({source}))
            else:
                self._nodes[entity.id] = Node(
                    merge_entities(existing.entity, entity), existing.sources | {source}
                )
        for relation in clean.relations:
            edge = self._edges.get(relation.key)
            sources = frozenset({source}) if edge is None else edge.sources | {source}
            self._edges[relation.key] = Edge(relation, sources)

    def sources_by_node(self) -> dict[str, frozenset[str]]:
        """Which plugins saw each node: input of the per-source Venn diagram."""
        return {node_id: node.sources for node_id, node in self._nodes.items()}


def build_graph(observations: Iterable[Observation]) -> SurfaceGraph:
    """Build a graph from observations, in any order."""
    graph = SurfaceGraph()
    for observation in observations:
        graph.merge(observation)
    return graph
