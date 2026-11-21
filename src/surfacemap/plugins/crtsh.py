"""crt.sh: subdomains and certificates seen in Certificate Transparency logs.

Traffic: HTTPS GETs to `crt.sh` (a third-party CT log search run by Sectigo), never to
the target or its subdomains: one search per scope root (`q=%.<root>`), then one
download (`d=<id>`) per certificate valid on the run date, newest first, at most
`MAX_CERTIFICATES`. Both go through the shared HTTP client (rate limit, cache).

Only names under the queried root are kept: a certificate may also list unrelated
co-tenant names, which are not part of the assessed surface. Email identities (S/MIME
certificates) and names that are not valid hostnames are dropped.

Nothing personal reaches the cache: the search body is reduced to the fields used here
without emails, and a downloaded PEM is reduced to its SHA-256 fingerprint (the DER
itself may embed email SANs). Issuer, dates and names come from the search row, so no
ASN.1 parser is needed. CT logs say a certificate was *issued*, not that a server serves
it: rules built on these certificates must word their findings accordingly.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from surfacemap.collect.http import FetchError
from surfacemap.models import (
    Certificate,
    Domain,
    Entity,
    Observation,
    Provenance,
    Relation,
    RelationType,
)
from surfacemap.plugins.base import PluginBase, PluginContext, ScopeView
from surfacemap.scope import InvalidDomainError, normalize_domain

CRTSH_URL = "https://crt.sh/"
MAX_CERTIFICATES = 50
"""Downloads per root: crt.sh is a free, often overloaded service."""

_IDENTITY_FIELDS = ("common_name", "name_value")
_KEPT_FIELDS = frozenset({"id", "issuer_name", "not_before", "not_after", *_IDENTITY_FIELDS})

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Candidate:
    """A search row describing a certificate valid on the run date."""

    id: int
    issuer: str
    not_before: datetime
    not_after: datetime
    sans: tuple[str, ...]


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
        rows = [row for row in _rows(body) if isinstance(row, dict)]
        names = sorted({_host(san) for row in rows for san in _sans(root, row)})
        if not names:
            return []
        observations = [
            Observation(
                provenance=_provenance(self.name, query),
                entities=tuple(
                    Domain(fqdn=name, in_scope=ctx.scope.is_in_scope(name)) for name in names
                ),
            )
        ]
        for candidate in _valid_certificates(root, rows, ctx.scope.today):
            certificate = await self._download(candidate, ctx)
            if certificate is not None:
                observations.append(certificate)
        return observations

    async def _download(self, candidate: _Candidate, ctx: PluginContext) -> Observation | None:
        query = f"crt.sh id {candidate.id}"
        try:
            sha256 = await ctx.http.get_text(
                self.name,
                CRTSH_URL,
                query=query,
                params={"d": str(candidate.id)},
                redact=_fingerprint,
            )
            certificate = Certificate(
                sha256=sha256,
                issuer=candidate.issuer,
                not_before=candidate.not_before,
                not_after=candidate.not_after,
                sans=candidate.sans,
            )
        except (FetchError, ValueError) as exc:  # ValidationError is a ValueError
            logger.warning("crtsh: skipped certificate %s: %s", candidate.id, type(exc).__name__)
            return None
        hosts = sorted({_host(san) for san in candidate.sans})
        return Observation(
            provenance=_provenance(self.name, query),
            entities=(certificate,),
            relations=tuple(
                Relation(
                    source=f"domain:{host}", type=RelationType.SECURED_BY, target=certificate.id
                )
                for host in hosts
            ),
        )


def _provenance(source: str, query: str) -> Provenance:
    return Provenance(source=source, retrieved_at=datetime.now(UTC), query=query)


def _rows(body: str) -> list[Any]:
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        rows = None
    if not isinstance(rows, list):
        raise FetchError("crtsh: unexpected payload")
    return rows


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


def _fingerprint(pem: str) -> str:
    """SHA-256 of the DER inside a PEM body; raises ValueError when it is not one."""
    lines = [line.strip() for line in pem.strip().splitlines()]
    framed = lines[:1] == ["-----BEGIN CERTIFICATE-----"] and lines[-1:] == [
        "-----END CERTIFICATE-----"
    ]
    if len(lines) < 3 or not framed:
        raise ValueError("not a PEM certificate")
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except binascii.Error as exc:
        raise ValueError("not a PEM certificate") from exc
    return hashlib.sha256(der).hexdigest()


def _sans(root: str, row: dict[str, Any]) -> tuple[str, ...]:
    """Names of a minimized row under `root`, normalized, `*.` wildcards kept."""
    sans: set[str] = set()
    for key in _IDENTITY_FIELDS:
        value = row.get(key)
        if not isinstance(value, str):
            continue
        for identity in value.splitlines():
            raw = identity.strip().lower()
            wildcard = raw.startswith("*.")
            try:
                name = normalize_domain(raw.removeprefix("*."))
            except InvalidDomainError:
                logger.debug("crtsh: skipped an identity that is not a hostname")
                continue
            if name == root or name.endswith("." + root):
                sans.add(f"*.{name}" if wildcard else name)
    return tuple(sorted(sans))


def _host(san: str) -> str:
    return san.removeprefix("*.")


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _valid_certificates(root: str, rows: list[dict[str, Any]], today: date) -> list[_Candidate]:
    """Certificates valid on `today`, newest first, capped at `MAX_CERTIFICATES`."""
    candidates: dict[int, _Candidate] = {}
    for row in rows:
        cert_id, issuer = row.get("id"), row.get("issuer_name")
        not_before, not_after = _timestamp(row.get("not_before")), _timestamp(row.get("not_after"))
        sans = _sans(root, row)
        if not (isinstance(cert_id, int) and isinstance(issuer, str) and sans):
            continue
        if not_before is None or not_after is None:
            continue
        if not_before.date() <= today <= not_after.date():
            candidates[cert_id] = _Candidate(cert_id, issuer, not_before, not_after, sans)
    newest = sorted(candidates.values(), key=lambda c: (c.not_before, c.id), reverse=True)
    return newest[:MAX_CERTIFICATES]
