"""ASN of an IP address, through the Team Cymru IP-to-ASN DNS service.

Traffic: DNS TXT queries, through the system resolver, for names under `asn.cymru.com`
(a free third-party service): `<reversed address>.origin.asn.cymru.com` (`origin6` for
IPv6) for the announcing ASN, then `AS<n>.asn.cymru.com` for its holder. Nothing reaches
the target. Answers are cached per address and per ASN and every query spends an `asn`
rate-limit token: Team Cymru asks heavy users to switch to its bulk interface.

Only globally routable addresses are looked up: private, loopback, link-local or
documentation addresses have no ASN, and sending them would leak internal addressing.
The ASN carries its registration country; the country of the *address* is left to the
geoip plugin, so that field has a single source.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import UTC, datetime

from surfacemap.models import (
    ASN,
    Entity,
    IPAddress,
    Observation,
    Provenance,
    Relation,
    RelationType,
)
from surfacemap.plugins._resolver import DnsError, DnspythonResolver, Resolver
from surfacemap.plugins.base import PluginBase, PluginContext

_COUNTRY = re.compile(r"^[A-Za-z]{2}$")
_MAX_ASN = 2**32 - 1

logger = logging.getLogger(__name__)


def origin_name(ip: IPAddress) -> str:
    address = ipaddress.ip_address(ip.address)
    if address.version == 4:
        return ".".join(reversed(address.exploded.split("."))) + ".origin.asn.cymru.com"
    nibbles = address.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _fields(value: str) -> list[str]:
    return [field.strip() for field in value.split("|")]


def _country(raw: str) -> str | None:
    return raw if _COUNTRY.match(raw) else None


class AsnPlugin(PluginBase):
    name = "asn"
    consumes = frozenset({"ip"})
    runs_out_of_scope = False

    def __init__(self, resolver: Resolver | None = None) -> None:
        self.resolver: Resolver = resolver if resolver is not None else DnspythonResolver()

    async def _txt(self, name: str, ctx: PluginContext) -> list[str] | None:
        """TXT values of `name` (cached), or None when the lookup failed."""
        cached = ctx.cache.get(self.name, name)
        if cached is not None:
            return list(json.loads(cached))
        await ctx.limiter.acquire(self.name)
        try:
            answer = await self.resolver.resolve(name, "TXT")
        except DnsError as exc:
            logger.warning("asn: %s failed: %s", name, exc)
            return None
        values = [r.value for r in answer.records if r.type == "TXT"]
        ctx.cache.set(self.name, name, json.dumps(values))
        return values

    async def _holder(self, number: int, ctx: PluginContext) -> str | None:
        for value in await self._txt(f"AS{number}.asn.cymru.com", ctx) or []:
            fields = _fields(value)
            if len(fields) >= 5 and fields[4]:
                return fields[4]
        return None

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        if not isinstance(entity, IPAddress) or not ipaddress.ip_address(entity.address).is_global:
            return []
        query = origin_name(entity)
        origins: dict[int, str | None] = {}
        for value in await self._txt(query, ctx) or []:
            fields = _fields(value)
            if len(fields) < 3:
                continue
            for raw in fields[0].split():
                if raw.isdigit() and 1 <= int(raw) <= _MAX_ASN:
                    origins[int(raw)] = _country(fields[2])
        if not origins:
            return []
        asns = [
            ASN(number=number, holder=await self._holder(number, ctx), country=country)
            for number, country in sorted(origins.items())
        ]
        ip = IPAddress(address=entity.address)
        return [
            Observation(
                provenance=Provenance(
                    source=self.name, retrieved_at=datetime.now(UTC), query=f"{query} TXT"
                ),
                entities=(ip, *asns),
                relations=tuple(Relation.between(ip, RelationType.ANNOUNCED_BY, a) for a in asns),
            )
        ]
