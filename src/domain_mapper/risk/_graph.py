"""Graph helpers shared by the risk rules (pure reads, no traffic)."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from domain_mapper.graph.builder import SurfaceGraph
from domain_mapper.models import Domain, RelationType


def in_scope_domains(graph: SurfaceGraph) -> Iterator[Domain]:
    """In-scope domains, in id order so findings do not depend on arrival order."""
    for node_id in sorted(graph.nodes):
        entity = graph.nodes[node_id].entity
        if isinstance(entity, Domain) and entity.in_scope:
            yield entity


def targets_by_type(graph: SurfaceGraph) -> dict[tuple[str, RelationType], list[str]]:
    """`(source id, relation type) -> sorted target ids`, one pass over the edges."""
    index: dict[tuple[str, RelationType], list[str]] = defaultdict(list)
    for source, rel_type, target in graph.edges:
        index[(source, rel_type)].append(target)
    for targets in index.values():
        targets.sort()
    return index


def cname_chain(index: dict[tuple[str, RelationType], list[str]], start: str) -> Iterator[str]:
    """Ids reached from `start` by following CNAME edges (start excluded, loop-safe)."""
    seen = {start}
    stack = [start]
    while stack:
        for target in index.get((stack.pop(), RelationType.CNAME_TO), ()):
            if target not in seen:
                seen.add(target)
                stack.append(target)
                yield target
