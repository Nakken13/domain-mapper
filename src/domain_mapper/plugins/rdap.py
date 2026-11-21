"""RDAP (RFC 9083): the name servers registered for a scope root.

Traffic: HTTPS GETs to third parties only: the IANA bootstrap file (`data.iana.org`, once,
cached) and the registry's RDAP server for the root's TLD (`<server>/domain/<root>`).
The server is taken from the bootstrap rather than a redirecting proxy such as rdap.org:
the HTTP client never follows redirects. HTTPS servers only, never downgraded to HTTP.

Registration data carries personal data (registrant vCards, remarks). The payload goes
through `privacy.redact_registration` (an allow-list) *before* the response cache, so
contacts never reach the disk. Only the name servers are turned into graph data (`NS`
edges); TLDs without an RDAP server are left to the WHOIS fallback.
"""

from __future__ import annotations

import json
from typing import Any

from domain_mapper.collect.http import FetchError, parse_json
from domain_mapper.models import Domain, Entity, Observation, Relation, RelationType
from domain_mapper.plugins.base import PluginBase, PluginContext, RootOnlyPlugin
from domain_mapper.privacy import redact_registration
from domain_mapper.scope import try_normalize_domain

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
SOURCE = "rdap"


def _redacted(body: str) -> str:
    return json.dumps(redact_registration(parse_json(body, SOURCE, dict)))


def ns_observation(
    plugin: PluginBase, root: str, servers: list[str], query: str, ctx: PluginContext
) -> Observation:
    """`root` NS `servers`: shared by RDAP and its WHOIS fallback."""
    domain = Domain(fqdn=root, in_scope=ctx.scope.is_in_scope(root))
    targets = [Domain(fqdn=ns, in_scope=ctx.scope.is_in_scope(ns)) for ns in servers]
    return Observation(
        provenance=plugin.provenance(query),
        entities=(domain, *targets),
        relations=tuple(Relation.between(domain, RelationType.NS, ns) for ns in targets),
    )


async def rdap_server(domain: str, ctx: PluginContext) -> str | None:
    """Base URL of the HTTPS RDAP server for the TLD of `domain`, or None."""
    bootstrap = parse_json(
        await ctx.http.get_text(SOURCE, BOOTSTRAP_URL, query="rdap bootstrap"), SOURCE, dict
    )
    services = bootstrap.get("services")
    if not isinstance(services, list):
        raise FetchError(f"{SOURCE}: unexpected payload")
    tld = domain.lower().rstrip(".").rsplit(".", 1)[-1]
    for service in services:
        if not (isinstance(service, list) and len(service) == 2):
            continue
        tlds, urls = service
        if isinstance(tlds, list) and tld in (str(t).lower() for t in tlds):
            https = [u for u in urls if isinstance(u, str) and u.startswith("https://")]
            if https:
                return https[0] if https[0].endswith("/") else https[0] + "/"
    return None


def _name_servers(payload: Any) -> list[str]:
    servers: set[str] = set()
    entries = payload.get("nameservers") if isinstance(payload, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        name = entry.get("ldhName") if isinstance(entry, dict) else None
        if isinstance(name, str) and (host := try_normalize_domain(name)):
            servers.add(host)
    return sorted(servers)


class RdapPlugin(RootOnlyPlugin):
    name = SOURCE
    consumes = frozenset({"domain"})
    runs_out_of_scope = False

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        if not isinstance(entity, Domain):
            return []
        root = entity.fqdn
        server = await rdap_server(root, ctx)
        if server is None:
            return []
        query = f"rdap domain {root}"
        body = await ctx.http.get_text(
            self.name,
            f"{server}domain/{root}",
            query=query,
            headers={"Accept": "application/rdap+json"},
            redact=_redacted,
        )
        servers = [ns for ns in _name_servers(parse_json(body, SOURCE, dict)) if ns != root]
        if not servers:
            return []
        return [ns_observation(self, root, servers, query, ctx)]
