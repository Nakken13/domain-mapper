"""Plugin contract, run context and registry.

A plugin is any object matching the `Plugin` protocol (subclassing `PluginBase` only
buys default methods). The engine calls `run` once per entity whose `kind` is in
`consumes`; the plugin returns `Observation`s and never touches the graph.

Scope policy is declared, not inferred:

* `runs_out_of_scope` must be an explicit bool. Only pure DNS resolution says True: the
  project rule is that out-of-scope nodes are recorded and DNS-resolved, never enriched.
  An ASN lookup is enrichment even though it travels over DNS, so it says False.
* `applies_to` narrows further, e.g. crt.sh/RDAP/WHOIS run on the scope root only.

`name` is also the cache, rate-limit and provenance key, hence unique and slug-shaped.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Protocol, TypeVar, get_args, runtime_checkable

import idna

from surfacemap.collect.cache import ResponseCache
from surfacemap.collect.http import HttpClient
from surfacemap.collect.ratelimit import RateLimiter
from surfacemap.config import Settings
from surfacemap.models import (
    Domain,
    Entity,
    Observation,
    Provenance,
)
from surfacemap.scope import InvalidDomainError, Scope, normalize_domain

# Derived from the `Entity` union, so a new entity type is accepted without edits here.
ENTITY_KINDS = frozenset(
    get_args(model.model_fields["kind"].annotation)[0] for model in get_args(get_args(Entity)[0])
)
_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
ENGINE_SOURCE = "surfacemap"
"""Provenance source of the engine's own (structural) observations: no plugin may use it."""


class ScopeView:
    """Read-only view of the scope, with the date pinned once for the whole run.

    Pinning matters: `Scope.check` defaults to today, so a run crossing midnight past an
    `expires` date would flip a domain to out-of-scope mid-run (and `False` wins merges).
    """

    def __init__(self, scope: Scope, today: date) -> None:
        self._scope = scope
        self.today = today
        self._in_scope: dict[str, bool] = {}
        self._target_hosts: dict[str, bool] = {}

    def is_in_scope(self, fqdn: str) -> bool:
        # Memoized: the date is pinned, so the answer cannot change during the run.
        cached = self._in_scope.get(fqdn)
        if cached is None:
            cached = self._in_scope[fqdn] = self._scope.check(fqdn, today=self.today).allowed
        return cached

    def root_of(self, fqdn: str) -> str | None:
        """The authorized domain covering `fqdn`, or None when it is out of scope."""
        decision = self._scope.check(fqdn, today=self.today)
        return decision.entry.domain if decision.allowed and decision.entry else None

    def is_root(self, fqdn: str) -> bool:
        """True when `fqdn` is itself an authorized domain (not merely a name under one)."""
        return self.root_of(fqdn) == fqdn

    def require(self, raw_domain: str) -> str:
        """Normalized domain, or OutOfScopeError, judged on the pinned date."""
        return self._scope.require(raw_domain, today=self.today)

    def is_target_host(self, host: str) -> bool:
        """True for any name under a listed domain, even expired or restricted (fail closed).

        Used to refuse direct HTTP traffic to the target: passive means never contacting it.
        Every spelling is tried, because scope names are normalized with Python's IDNA 2003
        codec (`ß` -> `ss`) while httpx sends IDNA 2008 (`ß` -> `xn--zca`).
        """
        cached = self._target_hosts.get(host)
        if cached is None:
            # Not `ScopeEntry.covers`: that honours include_subdomains, this must not.
            cached = self._target_hosts[host] = any(
                name == e.domain or name.endswith("." + e.domain)
                for name in _spellings(host)
                for e in self._scope.entries
            )
        return cached


def _spellings(host: str) -> set[str]:
    raw = host.strip().lower().removesuffix(".")
    names = {raw}
    for candidate in (raw, _punycode_decoded(raw)):
        # e.g. `_dmarc.example.com` is refused by both: the raw spelling still matches.
        with contextlib.suppress(InvalidDomainError):
            names.add(normalize_domain(candidate))
        with contextlib.suppress(idna.IDNAError):
            names.add(idna.encode(candidate, uts46=True).decode("ascii"))
    return names


def _punycode_decoded(name: str) -> str:
    try:
        return idna.decode(name)
    except idna.IDNAError:
        return name


@dataclass(frozen=True)
class PluginContext:
    """What a plugin may use. Non-HTTP plugins (DNS, WHOIS) get the cache and limiter too."""

    http: HttpClient
    cache: ResponseCache
    limiter: RateLimiter
    settings: Settings
    scope: ScopeView


@runtime_checkable
class Plugin(Protocol):
    name: str
    consumes: frozenset[str]
    runs_out_of_scope: bool

    def enabled(self, settings: Settings) -> bool:
        """False when a requirement is missing (e.g. no API key): the plugin is skipped."""
        ...

    def applies_to(self, entity: Entity, scope: ScopeView) -> bool:
        """Finer filter than `consumes`, e.g. only the scope root."""
        ...

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        """Observations about `entity`. Raising is allowed: the engine isolates failures."""
        ...


class PluginBase:
    """Optional base class: always enabled, applies to every consumed entity."""

    name: str
    consumes: frozenset[str]
    runs_out_of_scope: bool

    def enabled(self, settings: Settings) -> bool:
        return True

    def applies_to(self, entity: Entity, scope: ScopeView) -> bool:
        return True

    def provenance(self, query: str) -> Provenance:
        """Provenance of an observation this plugin makes now."""
        return Provenance(source=self.name, retrieved_at=datetime.now(UTC), query=query)


class RootOnlyPlugin(PluginBase):
    """A plugin that only enriches the authorized domains themselves, never their subdomains."""

    def applies_to(self, entity: Entity, scope: ScopeView) -> bool:
        return isinstance(entity, Domain) and scope.is_root(entity.fqdn)


def _validate(plugin: Plugin) -> None:
    if not isinstance(plugin, Plugin):
        raise TypeError(f"{plugin!r} does not implement the Plugin protocol")
    if not _NAME.match(plugin.name):
        raise ValueError(f"plugin name {plugin.name!r} must be a lowercase slug")
    if plugin.name == ENGINE_SOURCE:
        raise ValueError(f"plugin name {ENGINE_SOURCE!r} is reserved for the engine")
    if not plugin.consumes or not plugin.consumes <= ENTITY_KINDS:
        raise ValueError(
            f"{plugin.name}: consumes must be a non-empty subset of {sorted(ENTITY_KINDS)}"
        )
    if not isinstance(plugin.runs_out_of_scope, bool):
        raise TypeError(f"{plugin.name}: runs_out_of_scope must be declared as a bool")


P = TypeVar("P", bound=Plugin)


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}

    def register(self, plugin: P) -> P:
        _validate(plugin)
        if plugin.name in self._plugins:
            raise ValueError(f"plugin {plugin.name!r} is already registered")
        self._plugins[plugin.name] = plugin
        return plugin

    def get(self, name: str) -> Plugin:
        return self._plugins[name]

    def __contains__(self, name: object) -> bool:
        return name in self._plugins

    def __iter__(self) -> Iterator[Plugin]:
        return iter(sorted(self._plugins.values(), key=lambda p: p.name))

    def enabled(self, settings: Settings) -> list[Plugin]:
        return [p for p in self if p.enabled(settings)]


def default_registry() -> PluginRegistry:
    """A fresh registry with the built-in plugins."""
    # Imported here: plugin modules import this one.
    from surfacemap.plugins.asn import AsnPlugin
    from surfacemap.plugins.crtsh import CrtshPlugin
    from surfacemap.plugins.dns_records import DnsPlugin
    from surfacemap.plugins.geoip import GeoipPlugin
    from surfacemap.plugins.rdap import RdapPlugin
    from surfacemap.plugins.shodan import ShodanPlugin
    from surfacemap.plugins.wayback import WaybackPlugin
    from surfacemap.plugins.whois import WhoisPlugin

    registry = PluginRegistry()
    builtins = (
        AsnPlugin(),
        CrtshPlugin(),
        DnsPlugin(),
        GeoipPlugin(),
        RdapPlugin(),
        ShodanPlugin(),
        WaybackPlugin(),
        WhoisPlugin(),
    )
    for plugin in builtins:
        registry.register(plugin)
    return registry
