"""DNS records of a domain: addresses, CNAME chain, mail and name servers, TXT, DMARC.

Traffic: DNS queries to the system's recursive resolver (see `_resolver.py`), one per
record type, each spending a `dns` rate-limit token. Nothing else is sent anywhere.

The only plugin that runs on out-of-scope names (the project rule: out-of-scope nodes are
recorded and DNS-resolved, never enriched), and there it asks A/AAAA only. In-scope names
also get MX, NS and TXT; a scope root, or an in-scope name with a mail server, also gets
its `_dmarc` TXT. That label is built here from an already-validated name and never
becomes a node: the policy is stored on the domain as a `DMARC` record. A `DMARC` record
with an empty value is a *confirmed* absence (NXDOMAIN or no `v=DMARC1` TXT) and is only
recorded for a scope root: a subdomain falls back to its organizational domain's policy
(RFC 7489 section 6.6.3). A failed lookup records nothing.
DKIM is not looked up: finding keys means guessing selectors.

An IP is linked to the name that owns its A/AAAA record, i.e. the end of the CNAME chain,
so an address behind an out-of-scope CDN stays out of scope. When the answer is NXDOMAIN,
the last name of the chain (the one that does not exist) gets an `RCODE=NXDOMAIN` record:
a CNAME to a missing name is the passive half of a subdomain-takeover signal.
"""

from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict
from datetime import UTC, datetime

from surfacemap.models import (
    DnsRecord,
    Domain,
    Entity,
    IPAddress,
    Observation,
    Provenance,
    Relation,
    RelationType,
)
from surfacemap.plugins._resolver import DnsAnswer, DnsError, DnspythonResolver, Resolver
from surfacemap.plugins.base import PluginBase, PluginContext
from surfacemap.scope import InvalidDomainError, normalize_domain

RESOLVE_TYPES = ("A", "AAAA")
ENRICH_TYPES = ("MX", "NS", "TXT")
_EDGE_TYPES = {"CNAME": RelationType.CNAME_TO, "MX": RelationType.MX, "NS": RelationType.NS}
NXDOMAIN = DnsRecord(type="RCODE", value="NXDOMAIN")

logger = logging.getLogger(__name__)


def _hostname(raw: str) -> str | None:
    try:
        return normalize_domain(raw)
    except InvalidDomainError:
        return None


def _address(raw: str) -> str | None:
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        return None


class _Collected:
    """Nodes, records and edges gathered over the queries of one name."""

    def __init__(self) -> None:
        self.records: defaultdict[str, set[DnsRecord]] = defaultdict(set)
        self.names: set[str] = set()
        self.ips: set[str] = set()
        self.edges: set[tuple[str, RelationType, str]] = set()

    def add_answer(self, queried: str, answer: DnsAnswer) -> None:
        last = queried
        for record in answer.records:
            owner = _hostname(record.owner)
            if owner is None:
                continue
            if record.type in ("A", "AAAA"):
                ip = _address(record.value)
                if ip is not None:
                    self.names.add(owner)
                    self.ips.add(ip)
                    self.edges.add((f"domain:{owner}", RelationType.RESOLVES_TO, f"ip:{ip}"))
            elif record.type in _EDGE_TYPES:
                if record.type != "CNAME" and owner != queried:
                    continue  # MX/NS of a CNAME target: enrichment of another name
                target = _hostname(record.value) if record.value else None
                if target is not None and target != owner:
                    self.names.update((owner, target))
                    self.edges.add(
                        (f"domain:{owner}", _EDGE_TYPES[record.type], f"domain:{target}")
                    )
                    if record.type == "CNAME":
                        last = target
            elif record.type == "TXT" and owner == queried:
                self.records[owner].add(DnsRecord(type="TXT", value=record.value))
        if answer.rcode == "NXDOMAIN":
            self.names.add(last)
            self.records[last].add(NXDOMAIN)

    def has_mail_server(self, name: str) -> bool:
        return any(src == f"domain:{name}" and rel is RelationType.MX for src, rel, _ in self.edges)

    def empty(self) -> bool:
        return not (self.edges or self.records)


class DnsPlugin(PluginBase):
    name = "dns"
    consumes = frozenset({"domain"})
    runs_out_of_scope = True

    def __init__(self, resolver: Resolver | None = None) -> None:
        self.resolver: Resolver = resolver if resolver is not None else DnspythonResolver()

    async def _query(self, name: str, rtype: str, ctx: PluginContext) -> DnsAnswer | None:
        await ctx.limiter.acquire(self.name)
        try:
            return await self.resolver.resolve(name, rtype)
        except DnsError as exc:
            logger.warning("dns: %s %s failed: %s", name, rtype, exc)
            return None

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        if not isinstance(entity, Domain):
            return []
        name = entity.fqdn
        in_scope = ctx.scope.is_in_scope(name)
        types = RESOLVE_TYPES + ENRICH_TYPES if in_scope else RESOLVE_TYPES
        collected = _Collected()
        for rtype in types:
            answer = await self._query(name, rtype, ctx)
            if answer is not None:
                collected.add_answer(name, answer)
        query = f"{name} {'/'.join(types)}"
        if in_scope and (ctx.scope.root_of(name) == name or collected.has_mail_server(name)):
            query += " +_dmarc"
            is_root = ctx.scope.root_of(name) == name
            collected.records[name].update(await self._dmarc(name, is_root, ctx))
        if collected.empty():
            return []
        return [self._observation(name, query, collected, ctx)]

    async def _dmarc(self, name: str, is_root: bool, ctx: PluginContext) -> list[DnsRecord]:
        """DMARC records of `name`; a confirmed absence only for a scope root.

        A subdomain without its own `_dmarc` falls back to the organizational domain's
        policy (RFC 7489 section 6.6.3), so its absence proves nothing: no record, which
        `dmarc_of` reads as unknown. Every `v=DMARC1` TXT is kept: several make the
        policy invalid, which `dmarc_of` reports.
        """
        answer = await self._query(f"_dmarc.{name}", "TXT", ctx)
        if answer is None:
            return []
        policies = sorted(
            r.value
            for r in answer.records
            if r.type == "TXT" and r.value.strip().lower().startswith("v=dmarc1")
        )
        if policies:
            return [DnsRecord(type="DMARC", value=value) for value in policies]
        return [DnsRecord(type="DMARC", value="")] if is_root else []

    def _observation(
        self, name: str, query: str, collected: _Collected, ctx: PluginContext
    ) -> Observation:
        names = sorted({name, *collected.names, *collected.records})
        domains = tuple(
            Domain(
                fqdn=fqdn,
                in_scope=ctx.scope.is_in_scope(fqdn),
                records=tuple(sorted(collected.records.get(fqdn, ()), key=str)),
            )
            for fqdn in names
        )
        return Observation(
            provenance=Provenance(source=self.name, retrieved_at=datetime.now(UTC), query=query),
            entities=(*domains, *(IPAddress(address=ip) for ip in sorted(collected.ips))),
            relations=tuple(
                Relation(source=src, type=rel, target=dst)
                for src, rel, dst in sorted(collected.edges)
            ),
        )
