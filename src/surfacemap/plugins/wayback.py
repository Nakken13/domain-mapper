"""Wayback Machine CDX: paths archived under the scope root.

Traffic: one HTTPS GET to `web.archive.org` (the Internet Archive CDX API, a third
party) per scope root, `url=<root>&matchType=domain`. Nothing is sent to the target.

Query strings, fragments, path parameters (`;jsessionid=`) and encoded `;`/`?`/`#`/`%`
(tokens, emails, session ids) are dropped before anything is built, so captures of one
path merge into one `ArchivedURL` whose first/last seen span every capture. Hosts
outside the root are dropped; out-of-scope hosts under it are recorded as bare domains,
without their paths. Only HTTP 200 captures are requested, capped at `CDX_LIMIT` rows;
the body is reduced to those cut URLs before the response cache.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import UTC, datetime
from functools import partial
from typing import Any
from urllib.parse import unquote, urlsplit

from surfacemap.collect.http import FetchError
from surfacemap.models import (
    ArchivedURL,
    Domain,
    Entity,
    Observation,
    Provenance,
    Relation,
    RelationType,
)
from surfacemap.plugins.base import PluginBase, PluginContext, ScopeView
from surfacemap.privacy import REDACTED_EMAIL, scrub_emails, strip_query
from surfacemap.scope import InvalidDomainError, normalize_domain

CDX_URL = "https://web.archive.org/cdx/search/cdx"
CDX_LIMIT = 10_000
_TIMESTAMP = "%Y%m%d%H%M%S"
# Path parameters (`;jsessionid=…`) and percent-encoded `;`/`?`/`#` smuggle the same
# secrets as a query string past `strip_query`: the path is cut at the first one. An
# encoded `%` (`%25`) can only hide another escape (`%253F`), so it cuts too (fail closed).
_PATH_CUT = re.compile(r";|%3b|%3f|%23|%25", re.IGNORECASE)

_Span = tuple[datetime, datetime]


class WaybackPlugin(PluginBase):
    name = "wayback"
    consumes = frozenset({"domain"})
    runs_out_of_scope = False

    def applies_to(self, entity: Entity, scope: ScopeView) -> bool:
        return isinstance(entity, Domain) and scope.root_of(entity.fqdn) == entity.fqdn

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        if not isinstance(entity, Domain):
            return []
        root = entity.fqdn
        body = await ctx.http.get_text(
            self.name,
            CDX_URL,
            query=f"{root}/*",
            params={
                "url": root,
                "matchType": "domain",
                "output": "json",
                "fl": "timestamp,original",
                "filter": "statuscode:200",
                "limit": str(CDX_LIMIT),
            },
            redact=partial(_minimize, root),
        )
        spans = _spans(root, _rows(body))
        if not spans:
            return []
        hosts = {host: Domain(fqdn=host, in_scope=ctx.scope.is_in_scope(host)) for host, _ in spans}
        # An out-of-scope host (e.g. root listed without include_subdomains) is recorded,
        # never enriched: its archived paths are not kept.
        urls = [
            ArchivedURL(host=host, path=path, first_seen=first, last_seen=last)
            for (host, path), (first, last) in sorted(spans.items())
            if hosts[host].in_scope
        ]
        return [
            Observation(
                provenance=Provenance(
                    source=self.name, retrieved_at=datetime.now(UTC), query=f"{root}/*"
                ),
                entities=(*hosts.values(), *urls),
                relations=tuple(
                    Relation.between(hosts[url.host], RelationType.ARCHIVED_AT, url) for url in urls
                ),
            )
        ]


def _rows(body: str) -> list[Any]:
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        rows = None
    if not isinstance(rows, list):
        raise FetchError("wayback: unexpected payload")
    return rows[1:]  # the first row is the field header


def _minimize(root: str, body: str) -> str:
    """Rows reduced to `[timestamp, https://host/cut-path]` under `root`, before the cache.

    The raw CDX body holds full original URLs (query strings with tokens or emails): it
    must never reach the disk. Running `_spans` on the result gives the same spans.
    """
    kept: list[list[str]] = [["timestamp", "original"]]
    for row in _rows(body):
        capture = _capture(row)
        location = capture and _location(root, capture[1])
        if capture and location:
            kept.append([row[0], f"https://{location[0]}{location[1]}"])
    return json.dumps(kept)


def _capture(row: object) -> tuple[datetime, str] | None:
    if not (isinstance(row, list) and len(row) == 2 and all(isinstance(v, str) for v in row)):
        return None
    try:
        seen = datetime.strptime(row[0], _TIMESTAMP).replace(tzinfo=UTC)
    except ValueError:
        return None
    return seen, row[1]


def _location(root: str, original: str) -> tuple[str, str] | None:
    parts = urlsplit(strip_query(original))
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    try:
        host = normalize_domain(parts.hostname)
    except InvalidDomainError:
        return None
    if host != root and not host.endswith("." + root):
        return None
    # Emails in a path (`/unsubscribe/jane@…`) are scrubbed here, before the cache.
    path = _PATH_CUT.split(_redact_email_segments(parts.path), maxsplit=1)[0]
    return host, scrub_emails(path) or "/"


_MAX_DECODE_ROUNDS = 4


def _redact_email_segments(path: str) -> str:
    """Path with every segment that decodes to an email replaced by a placeholder.

    Obfuscated emails (`%6A%61ne%40…`, double-encoded `%2540`, fullwidth at-sign) dodge a
    plain scrubber and the `%25` cut would leave their local part behind. Each segment is
    decoded (repeated `unquote`, NFKC) until stable; one holding an `@` is dropped whole,
    and so is one that never settles (fail closed).
    """
    return "/".join(
        REDACTED_EMAIL if "@" in _decode(segment) else segment for segment in path.split("/")
    )


def _decode(segment: str) -> str:
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unicodedata.normalize("NFKC", unquote(segment))
        if decoded == segment:
            return decoded
        segment = decoded
    return "@"  # still changing after several rounds: treat as hostile


def _spans(root: str, rows: list[Any]) -> dict[tuple[str, str], _Span]:
    spans: dict[tuple[str, str], _Span] = {}
    for row in rows:
        capture = _capture(row)
        location = capture and _location(root, capture[1])
        if not capture or not location:
            continue
        seen = capture[0]
        first, last = spans.get(location, (seen, seen))
        spans[location] = (min(first, seen), max(last, seen))
    return spans
