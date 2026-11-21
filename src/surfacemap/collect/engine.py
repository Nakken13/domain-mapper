"""Iterative asyncio collection engine.

Scope first: `run` calls `ScopeView.require(seed)` before any plugin is called.

Collection runs in waves (breadth-first). Each wave runs every applicable
`(plugin, entity)` pair once, merges the results into the graph, and feeds the entities
that are new, or newly reachable at a higher level, into the next wave. Waves keep the
run deterministic: work is sorted before the budget cut, and results are merged in
that order.

Reach, per entity id, encodes the out-of-scope policy ("recorded + DNS-resolved, never
enriched further"):

* a domain's reach comes from the scope alone: FULL when authorized, else RESOLVE_ONLY;
* any other entity inherits the reach of the entity whose plugin produced it, so an IP
  behind an out-of-scope CDN CNAME is RESOLVE_ONLY and gets no ASN lookup;
* reach only goes up (an in-scope path reaching that IP later upgrades it, and the
  plugins it missed run in the next wave), so the loop terminates;
* RESOLVE_ONLY entities only see plugins declaring `runs_out_of_scope=True`.

The engine, not the plugin, stamps `Domain.in_scope` before merging: the builder makes
`False` win, so a wrong plugin flag would otherwise stick. The next wave reads entities
back from the graph, i.e. after `privacy` redaction, so an unredacted value can never
become a query sent to a third party.

Bounds: `max_depth` waves, `max_work_items` plugin calls in total, a timeout per call and
a concurrency cap. A failing plugin is isolated and logged by exception *type* only (an
exception message may carry a URL with an API key).

Finally the engine adds `HAS_SUBDOMAIN` edges from each domain to its nearest ancestor
present in the graph, in one relations-only observation from source `surfacemap`: the
edge is structural, so no plugin is credited with seeing the nodes.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum

from surfacemap.graph.builder import SurfaceGraph
from surfacemap.models import Domain, Entity, Observation, Provenance, Relation, RelationType
from surfacemap.plugins.base import Plugin, PluginContext

ENGINE_SOURCE = "surfacemap"

logger = logging.getLogger(__name__)


class Reach(IntEnum):
    RESOLVE_ONLY = 1
    FULL = 2


@dataclass(frozen=True)
class EngineLimits:
    max_depth: int = 8
    """Waves after the seed wave (a CNAME chain or cycle stops here at the latest)."""
    max_work_items: int = 5000
    """Plugin calls in the whole run: one certificate can carry hundreds of SANs."""
    concurrency: int = 8
    plugin_timeout: float = 120.0

    def __post_init__(self) -> None:
        if self.max_depth < 0:
            raise ValueError("max_depth must be >= 0")
        for name in ("max_work_items", "concurrency", "plugin_timeout"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


WorkItem = tuple[Plugin, Entity]


class Engine:
    def __init__(
        self,
        plugins: Iterable[Plugin],
        ctx: PluginContext,
        limits: EngineLimits | None = None,
    ) -> None:
        self._ctx = ctx
        self._limits = limits or EngineLimits()
        self._plugins = sorted(
            (p for p in plugins if p.enabled(ctx.settings)), key=lambda p: p.name
        )

    async def run(self, seed: str) -> SurfaceGraph:
        root = self._ctx.scope.require(seed)  # raises before anything else happens
        graph = SurfaceGraph()
        seed_entity = Domain(fqdn=root, in_scope=True)
        graph.merge(_engine_observation(root, entities=(seed_entity,)))

        reach: dict[str, Reach] = {seed_entity.id: Reach.FULL}
        done: set[tuple[str, str]] = set()
        frontier = {seed_entity.id}
        budget = self._limits.max_work_items
        semaphore = asyncio.Semaphore(self._limits.concurrency)

        for _depth in range(self._limits.max_depth + 1):
            items = self._schedule(graph, frontier, reach, done)
            if len(items) > budget:
                logger.warning("work-item budget reached: %d calls skipped", len(items) - budget)
                items = items[:budget]
            if not items:
                break
            budget -= len(items)
            done.update((plugin.name, entity.id) for plugin, entity in items)
            results = await asyncio.gather(*(self._call(semaphore, *item) for item in items))
            frontier = set()
            for (plugin, entity), observations in zip(items, results, strict=True):
                for observation in observations:
                    frontier |= self._absorb(graph, reach, plugin, reach[entity.id], observation)
        else:
            if frontier:
                logger.info("max depth reached with %d entities left", len(frontier))

        self._link_subdomains(graph, root)
        return graph

    def _schedule(
        self,
        graph: SurfaceGraph,
        frontier: set[str],
        reach: dict[str, Reach],
        done: set[tuple[str, str]],
    ) -> list[WorkItem]:
        items: list[WorkItem] = []
        for entity_id in sorted(frontier):
            entity = graph.nodes[entity_id].entity
            for plugin in self._plugins:
                if (
                    entity.kind in plugin.consumes
                    and (plugin.name, entity_id) not in done
                    and (reach[entity_id] is Reach.FULL or plugin.runs_out_of_scope)
                    and plugin.applies_to(entity, self._ctx.scope)
                ):
                    items.append((plugin, entity))
        return items

    async def _call(
        self, semaphore: asyncio.Semaphore, plugin: Plugin, entity: Entity
    ) -> list[Observation]:
        async with semaphore:
            try:
                async with asyncio.timeout(self._limits.plugin_timeout):
                    return list(await plugin.run(entity, self._ctx))
            except Exception as exc:  # isolate any plugin bug; cancellation still propagates
                logger.warning(
                    "plugin %s failed on %s: %s", plugin.name, entity.id, type(exc).__name__
                )
                return []

    def _absorb(
        self,
        graph: SurfaceGraph,
        reach: dict[str, Reach],
        plugin: Plugin,
        subject_reach: Reach,
        observation: object,
    ) -> set[str]:
        """Merge one observation; return the ids whose reach was created or raised."""
        if not isinstance(observation, Observation):
            logger.warning("plugin %s returned a non-Observation: dropped", plugin.name)
            return set()
        if observation.provenance.source != plugin.name:
            logger.warning(
                "plugin %s emitted an observation attributed to another source: dropped",
                plugin.name,
            )
            return set()

        stamped = observation.model_copy(
            update={"entities": tuple(self._stamp(e) for e in observation.entities)}
        )
        graph.merge(stamped)

        raised = set()
        for entity in stamped.entities:
            if isinstance(entity, Domain):
                level = Reach.FULL if entity.in_scope else Reach.RESOLVE_ONLY
            else:
                level = subject_reach
            if level > reach.get(entity.id, 0):
                reach[entity.id] = level
                raised.add(entity.id)
        return raised

    def _stamp(self, entity: Entity) -> Entity:
        if isinstance(entity, Domain):
            return entity.model_copy(update={"in_scope": self._ctx.scope.is_in_scope(entity.fqdn)})
        return entity

    @staticmethod
    def _link_subdomains(graph: SurfaceGraph, root: str) -> None:
        fqdns = {
            node.entity.fqdn for node in graph.nodes.values() if isinstance(node.entity, Domain)
        }
        relations = []
        for fqdn in sorted(fqdns):
            labels = fqdn.split(".")
            parent = next(
                (p for i in range(1, len(labels)) if (p := ".".join(labels[i:])) in fqdns), None
            )
            if parent is not None:
                relations.append(
                    Relation(
                        source=f"domain:{parent}",
                        type=RelationType.HAS_SUBDOMAIN,
                        target=f"domain:{fqdn}",
                    )
                )
        if relations:
            graph.merge(_engine_observation(root, relations=tuple(relations)))


def _engine_observation(
    query: str,
    entities: tuple[Entity, ...] = (),
    relations: tuple[Relation, ...] = (),
) -> Observation:
    return Observation(
        provenance=Provenance(source=ENGINE_SOURCE, retrieved_at=datetime.now(UTC), query=query),
        entities=entities,
        relations=relations,
    )
