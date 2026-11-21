"""Shodan host lookup (read-only), enabled only when the user supplies an API key.

Traffic: one HTTPS GET per globally routable IP to `api.shodan.io` (a third party that
already scanned the address; SurfaceMap never contacts the host). The key is sent as a
secret parameter: it never reaches the cache key, the logs, the provenance or an error.
Results belong to Shodan: the report must credit it ("Data: Shodan"), and use stays
within the user's own plan terms (no redistribution of exported data).

Banners can carry personal data (HTML pages, SMTP greetings). The body is reduced,
before the cache, to the fields used here: the ASN, hostnames and, per banner, port,
transport, product, version and hostnames. Only in-scope hostnames are kept: they get a
`RESOLVES_TO` edge and, for banners naming them, a `USES_TECH` edge to the product.
Open ports have no model yet, and the address country is left to the geoip plugin.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from typing import Any

from surfacemap.collect.http import FetchError
from surfacemap.config import Settings
from surfacemap.models import (
    ASN,
    Domain,
    Entity,
    IPAddress,
    Observation,
    Provenance,
    Relation,
    RelationType,
    Technology,
)
from surfacemap.plugins.base import PluginBase, PluginContext
from surfacemap.scope import InvalidDomainError, normalize_domain

HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
_BANNER_FIELDS = ("port", "transport", "product", "version", "hostnames")


def _payload(body: str) -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = None
    if not isinstance(payload, dict):
        raise FetchError("shodan: unexpected payload")
    return payload


def _minimize(body: str) -> str:
    """Only the fields used here: banners (HTML, greetings) never reach the cache."""
    payload = _payload(body)
    banners = payload.get("data")
    return json.dumps(
        {
            "asn": payload.get("asn"),
            "hostnames": payload.get("hostnames"),
            "data": [
                {key: banner.get(key) for key in _BANNER_FIELDS}
                for banner in (banners if isinstance(banners, list) else [])
                if isinstance(banner, dict)
            ],
        }
    )


def _asn(raw: object) -> ASN | None:
    if not isinstance(raw, str):
        return None
    try:
        return ASN.model_validate({"number": raw})
    except ValueError:
        return None


class ShodanPlugin(PluginBase):
    name = "shodan"
    consumes = frozenset({"ip"})
    runs_out_of_scope = False

    def enabled(self, settings: Settings) -> bool:
        return settings.shodan_enabled

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        key = ctx.settings.shodan_api_key
        if not isinstance(entity, IPAddress) or key is None:
            return []
        if not ipaddress.ip_address(entity.address).is_global:
            return []
        query = f"shodan host {entity.address}"
        payload = _payload(
            await ctx.http.get_text(
                self.name,
                HOST_URL.format(ip=entity.address),
                query=query,
                secret_params={"key": key.get_secret_value()},
                redact=_minimize,
            )
        )
        return self._observations(entity, query, payload, ctx)

    def _in_scope(self, names: object, ctx: PluginContext) -> list[str]:
        kept: set[str] = set()
        for raw in names if isinstance(names, list) else []:
            try:
                name = normalize_domain(str(raw))
            except InvalidDomainError:
                continue
            if ctx.scope.is_in_scope(name):
                kept.add(name)
        return sorted(kept)

    def _observations(
        self, ip: IPAddress, query: str, payload: dict[str, Any], ctx: PluginContext
    ) -> list[Observation]:
        entities: list[Entity] = []
        relations: list[Relation] = []
        asn = _asn(payload.get("asn"))
        if asn is not None:
            entities.append(asn)
            relations.append(Relation.between(ip, RelationType.ANNOUNCED_BY, asn))
        for name in self._in_scope(payload.get("hostnames"), ctx):
            host = Domain(fqdn=name, in_scope=True)
            entities.append(host)
            relations.append(Relation.between(host, RelationType.RESOLVES_TO, ip))
        for banner in payload.get("data") or []:
            product = banner.get("product")
            hosts = self._in_scope(banner.get("hostnames"), ctx)
            if not (isinstance(product, str) and product.strip() and hosts):
                continue
            evidence = f"shodan:{banner.get('port')}/{banner.get('transport')} {product}"
            if isinstance(banner.get("version"), str):
                evidence += f" {banner['version']}"
            tech = Technology(name=product.strip(), category="service", evidence=(evidence,))
            entities.append(tech)
            for name in hosts:
                relations.append(
                    Relation(source=f"domain:{name}", type=RelationType.USES_TECH, target=tech.id)
                )
        if not relations:
            return []
        return [
            Observation(
                provenance=Provenance(
                    source=self.name, retrieved_at=datetime.now(UTC), query=query
                ),
                entities=(ip, *entities),
                relations=tuple(relations),
            )
        ]
