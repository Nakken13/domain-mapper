"""crt.sh: subdomains seen in Certificate Transparency logs.

Traffic: one HTTPS GET to `crt.sh` (a third-party CT log search run by Sectigo) per scope
root, `q=%.<root>`. Nothing is sent to the target or its subdomains.

Only names under the queried root are kept: a certificate may also list unrelated
co-tenant names, which are not part of the assessed surface. Email identities (S/MIME
certificates) and names that are not valid hostnames are dropped. The crt.sh JSON API
carries no certificate fingerprint, so no `Certificate` entity is built here.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from surfacemap.collect.http import FetchError
from surfacemap.models import Domain, Entity, Observation, Provenance
from surfacemap.plugins.base import PluginBase, PluginContext, ScopeView
from surfacemap.scope import InvalidDomainError, normalize_domain

CRTSH_URL = "https://crt.sh/"

logger = logging.getLogger(__name__)


class CrtshPlugin(PluginBase):
    name = "crtsh"
    consumes = frozenset({"domain"})
    runs_out_of_scope = False

    def applies_to(self, entity: Entity, scope: ScopeView) -> bool:
        return isinstance(entity, Domain) and scope.root_of(entity.fqdn) == entity.fqdn

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        if not isinstance(entity, Domain):
            return []
        root = entity.fqdn
        query = f"%.{root}"
        body = await ctx.http.get_text(
            self.name, CRTSH_URL, query=query, params={"q": query, "output": "json"}
        )
        rows = _rows(body)
        names = sorted(_names_under(root, rows))
        if not names:
            return []
        return [
            Observation(
                provenance=Provenance(
                    source=self.name, retrieved_at=datetime.now(UTC), query=query
                ),
                entities=tuple(
                    Domain(fqdn=name, in_scope=ctx.scope.is_in_scope(name)) for name in names
                ),
            )
        ]


def _rows(body: str) -> list[Any]:
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        rows = None
    if not isinstance(rows, list):
        raise FetchError("crtsh: unexpected payload")
    return rows


def _identities(row: object) -> Iterable[str]:
    if not isinstance(row, dict):
        return
    for key in ("common_name", "name_value"):
        value = row.get(key)
        if isinstance(value, str):
            yield from value.splitlines()


def _names_under(root: str, rows: list[Any]) -> set[str]:
    names: set[str] = set()
    for row in rows:
        for identity in _identities(row):
            if "@" in identity:
                continue  # an email (S/MIME), i.e. personal data
            try:
                name = normalize_domain(identity.strip().removeprefix("*."))
            except InvalidDomainError:
                logger.debug("crtsh: skipped an identity that is not a hostname")
                continue
            if name == root or name.endswith("." + root):
                names.add(name)
    return names
