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
* any other entity takes the highest reach of the nodes pointing at it in the same
  observation (the queried entity when nothing links it), so an IP behind an
  out-of-scope CDN CNAME is RESOLVE_ONLY and gets no ASN lookup, even when the resolver
  returned the whole chain for an in-scope name;
* reach only goes up (an in-scope path reaching that IP later upgrades it, and the
  plugins it missed run in the next wave), so the loop terminates;
* RESOLVE_ONLY entities only see plugins declaring `runs_out_of_scope=True`, and what
  they produce is only expanded along their CNAME chain (or when the scope authorizes
  it): a CDN's NS/MX hosts are recorded, not crawled hop after hop. Expansion is tracked
  apart from reach, so a node recorded unexpanded is still resolved if a later path
  (e.g. an in-scope CNAME) allows it.

The engine, not the plugin, stamps `Domain.in_scope` before merging: the builder makes
`False` win, so a wrong plugin flag would otherwise stick. The next wave reads entities
back from the graph, i.e. after `privacy` redaction, so an unredacted value can never
become a query sent to a third party.

Bounds: `max_depth` waves, `max_work_items` plugin calls in total, a timeout per call and
a concurrency cap. A failing plugin is isolated and logged by exception *type* only (an
exception message may carry a URL with an API key).

Finally the engine adds `HAS_SUBDOMAIN` edges from each domain to its nearest ancestor
present in the graph, in one relations-only observation from source `domain-mapper`: the
edge is structural, so no plugin is credited with seeing the nodes.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum

from domain_mapper.collect.http import PassiveViolationError
from domain_mapper.graph.builder import SurfaceGraph
from domain_mapper.models import Domain, Entity, Observation, Provenance, Relation, RelationType
from domain_mapper.models.entities import id_kind
from domain_mapper.plugins.base import ENGINE_SOURCE, Plugin, PluginContext, ScopeView
from domain_mapper.privacy import redact_observation

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
        expanded: dict[str, Reach] = {seed_entity.id: Reach.FULL}
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
            for (_plugin, entity), observations in zip(items, results, strict=True):
                for observation in observations:
                    frontier |= self._absorb(graph, reach, expanded, entity, observation)
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
                    and self._applies(plugin, entity)
                ):
                    items.append((plugin, entity))
        return items

    def _applies(self, plugin: Plugin, entity: Entity) -> bool:
        try:
            return plugin.applies_to(entity, self._ctx.scope)
        except Exception as exc:  # a filter bug skips the call, not the run
            logger.warning(
                "plugin %s applies_to failed on %s: %s", plugin.name, entity.id, type(exc).__name__
            )
            return False

    async def _call(
        self, semaphore: asyncio.Semaphore, plugin: Plugin, entity: Entity
    ) -> list[Observation]:
        async with semaphore:
            try:
                async with asyncio.timeout(self._limits.plugin_timeout):
                    results = list(await plugin.run(entity, self._ctx))
            except Exception as exc:  # isolate any plugin bug; cancellation still propagates
                # A plugin aiming at the target breaks the passive contract: louder than a bug.
                level = logging.ERROR if isinstance(exc, PassiveViolationError) else logging.WARNING
                logger.log(
                    level, "plugin %s failed on %s: %s", plugin.name, entity.id, type(exc).__name__
                )
                return []
        return [o for o in results if _is_own_observation(plugin, o)]

    def _absorb(
        self,
        graph: SurfaceGraph,
        reach: dict[str, Reach],
        expanded: dict[str, Reach],
        subject: Entity,
        observation: Observation,
    ) -> set[str]:
        """Merge one observation; return the ids to expand in the next wave."""

        # Redact here (merge redacts again, idempotently): redaction can change an id
        # (an email scrubbed from a URL path), and the next wave must use graph ids.
        clean = redact_observation(
            observation.model_copy(
                update={"entities": tuple(self._stamp(e) for e in observation.entities)}
            )
        )
        graph.merge(clean)

        assessed = _ReachAssessment(clean, reach, reach[subject.id], self._ctx.scope)
        cname_targets = {r.target for r in clean.relations if r.type is RelationType.CNAME_TO}
        expand = set()
        for entity in clean.entities:
            level = max(assessed.levels[entity.id], reach.get(entity.id, Reach.RESOLVE_ONLY))
            reach[entity.id] = level
            # Out of scope, only the CNAME chain is followed (to reach the IPs); names the
            # scope authorizes are always expanded. The rest is recorded, not crawled.
            may_expand = (
                Reach.FULL in (level, assessed.parent_levels[entity.id])
                or entity.id in cname_targets
            )
            # Tracked apart from reach: a node first recorded without expansion must still
            # be expanded when a later path allows it (review I1).
            if may_expand and expanded.get(entity.id, 0) < level:
                expanded[entity.id] = level
                expand.add(entity.id)
        return expand

    def _stamp(self, entity: Entity) -> Entity:
        if isinstance(entity, Domain):
            return entity.model_copy(update={"in_scope": self._ctx.scope.is_in_scope(entity.fqdn)})
        return entity

    @staticmethod
    def _link_subdomains(graph: SurfaceGraph, root: str) -> None:
        domains = {
            node.entity.fqdn: node.entity
            for node in graph.nodes.values()
            if isinstance(node.entity, Domain)
        }
        relations = []
        for fqdn in sorted(domains):
            labels = fqdn.split(".")
            parent = next(
                (p for i in range(1, len(labels)) if (p := ".".join(labels[i:])) in domains), None
            )
            if parent is not None:
                relations.append(
                    Relation.between(domains[parent], RelationType.HAS_SUBDOMAIN, domains[fqdn])
                )
        if relations:
            graph.merge(_engine_observation(root, relations=tuple(relations)))


class _ReachAssessment:
    """Reach of each entity of one observation, and of the nodes pointing at it (review I2).

    Domains: from the scope. Other entities: from the nodes pointing at them inside the
    observation (a resolver answer carries the whole CNAME chain, so a CDN IP takes the
    CDN name's reach, not the queried name's); the queried subject only when nothing
    points at them. A parent known only as a relation endpoint is judged fail-closed: by
    the scope for a domain id, RESOLVE_ONLY otherwise.
    """

    def __init__(
        self,
        observation: Observation,
        reach: Mapping[str, Reach],
        subject_reach: Reach,
        scope: ScopeView,
    ) -> None:
        self._reach = reach
        self._subject_reach = subject_reach
        self._scope = scope
        self._parents: dict[str, list[str]] = defaultdict(list)
        for relation in observation.relations:
            self._parents[relation.target].append(relation.source)

        self.levels: dict[str, Reach] = {
            e.id: Reach.FULL if e.in_scope else Reach.RESOLVE_ONLY
            for e in observation.entities
            if isinstance(e, Domain)
        }
        others = [e.id for e in observation.entities if not isinstance(e, Domain)]
        for _ in range(len(others) + 1):  # chains (domain -> ip -> asn) settle in a few passes
            changed = False
            for entity_id in others:
                level = self._parent_level(entity_id)
                if self.levels.get(entity_id) != level:
                    self.levels[entity_id] = level
                    changed = True
            if not changed:
                break
        self.parent_levels = {e.id: self._parent_level(e.id) for e in observation.entities}

    def _parent_level(self, entity_id: str) -> Reach:
        parents = self._parents.get(entity_id)
        if not parents:
            return self._subject_reach
        return max(self._known_level(parent) for parent in parents)

    def _known_level(self, entity_id: str) -> Reach:
        level = self.levels.get(entity_id) or self._reach.get(entity_id)
        if level is not None:
            return level
        if id_kind(entity_id) == "domain" and self._scope.is_in_scope(
            entity_id.removeprefix("domain:")
        ):
            return Reach.FULL
        return Reach.RESOLVE_ONLY


def _is_own_observation(plugin: Plugin, result: object) -> bool:
    """Drop anything but an Observation attributed to the plugin that returned it."""
    if not isinstance(result, Observation):
        logger.warning("plugin %s returned a non-Observation: dropped", plugin.name)
        return False
    if result.provenance.source != plugin.name:
        logger.warning(
            "plugin %s emitted an observation attributed to another source: dropped",
            plugin.name,
        )
        return False
    return True


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
