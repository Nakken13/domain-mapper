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
            self.name,
            CRTSH_URL,
            query=query,
            params={"q": query, "output": "json"},
            redact=_minimize,
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


_IDENTITY_FIELDS = ("common_name", "name_value")
_KEPT_FIELDS = frozenset({"id", "issuer_name", "not_before", "not_after", *_IDENTITY_FIELDS})


def _minimize(body: str) -> str:
    """The crt.sh payload reduced to the fields used here, email identities removed.

    Runs before the response cache: S/MIME certificates list personal emails, and the raw
    body must never reach disk. Structural, not a regex over the JSON text, so the name
    following an email in a multi-line `name_value` survives.
    """
    kept: list[dict[str, Any]] = []
    for row in _rows(body):
        if not isinstance(row, dict):
            continue
        fields = {k: v for k, v in row.items() if k in _KEPT_FIELDS and isinstance(v, str | int)}
        for key in _IDENTITY_FIELDS:
            value = fields.get(key)
            if isinstance(value, str):
                fields[key] = "\n".join(x for x in value.splitlines() if "@" not in x)
        kept.append(fields)
    return json.dumps(kept)


def _identities(row: dict[str, Any]) -> Iterable[str]:
    """Names of a row already passed through `_minimize` (no email left)."""
    for key in _IDENTITY_FIELDS:
        value = row.get(key)
        if isinstance(value, str):
            yield from value.splitlines()


def _names_under(root: str, rows: list[Any]) -> set[str]:
    names: set[str] = set()
    for row in rows:
        for identity in _identities(row):
            try:
                name = normalize_domain(identity.strip().removeprefix("*."))
            except InvalidDomainError:
                logger.debug("crtsh: skipped an identity that is not a hostname")
                continue
            if name == root or name.endswith("." + root):
                names.add(name)
    return names
