"""Typed edges between entities, and the provenance of every observation."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Self
from urllib.parse import unquote

from pydantic import Field, field_validator, model_validator

from surfacemap.models.base import FrozenModel, UtcDatetime
from surfacemap.models.entities import BaseEntity

# Credentials must never reach the cache, the graph or the report. Matched on the
# URL-decoded query: `name=`/`name:` parameters (also `access_token`, `x_api_key`, …),
# HTTP auth headers and `user:password@` userinfo. Deliberately broad: a false positive
# only means the plugin has to describe its query without the secret.
_CREDENTIAL = re.compile(
    r"(?<![a-z0-9])(?:[a-z0-9]+[_-])*"
    r"(?:api[_-]?key|key|token|secret|password|passwd|pass|pwd|auth|sig|signature)\s*[=:]"
    r"|\b(?:authorization|bearer)\b"
    r"|://[^/@\s]+:[^/@\s]*@",
    re.IGNORECASE,
)


class RelationType(StrEnum):
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    CNAME_TO = "CNAME_TO"
    MX = "MX"
    NS = "NS"
    ANNOUNCED_BY = "ANNOUNCED_BY"
    SECURED_BY = "SECURED_BY"
    USES_TECH = "USES_TECH"
    ARCHIVED_AT = "ARCHIVED_AT"


# (source id prefix, target id prefix) allowed for each relation type.
ENDPOINTS: dict[RelationType, tuple[str, str]] = {
    RelationType.HAS_SUBDOMAIN: ("domain", "domain"),
    RelationType.RESOLVES_TO: ("domain", "ip"),
    RelationType.CNAME_TO: ("domain", "domain"),
    RelationType.MX: ("domain", "domain"),
    RelationType.NS: ("domain", "domain"),
    RelationType.ANNOUNCED_BY: ("ip", "asn"),
    RelationType.SECURED_BY: ("domain", "cert"),
    RelationType.USES_TECH: ("domain", "tech"),
    RelationType.ARCHIVED_AT: ("domain", "url"),
}


def _kind(entity_id: str) -> str:
    return entity_id.partition(":")[0]


class Relation(FrozenModel):
    """A directed edge `source -[type]-> target`, endpoints given as entity ids.

    Prefer `Relation.between(entity, type, entity)`: raw id strings are not normalized.
    An edge may reference a node emitted by another observation, so the graph accepts
    edges whose endpoints are not (yet) nodes.
    """

    source: str = Field(min_length=3)
    type: RelationType
    target: str = Field(min_length=3)

    @model_validator(mode="after")
    def _check_endpoints(self) -> Self:
        expected = ENDPOINTS[self.type]
        actual = (_kind(self.source), _kind(self.target))
        if actual != expected:
            raise ValueError(
                f"{self.type} endpoints must be {expected[0]} -> {expected[1]}, "
                f"got {actual[0]} -> {actual[1]}"
            )
        if self.source == self.target:
            raise ValueError("a relation cannot point to its own source")
        return self

    @classmethod
    def between(cls, source: BaseEntity, type: RelationType, target: BaseEntity) -> Relation:
        """Build a relation from entities, so endpoints always carry their canonical ids."""
        return cls(source=source.id, type=type, target=target.id)

    @property
    def key(self) -> tuple[str, RelationType, str]:
        """Deduplication key of the edge in the graph."""
        return (self.source, self.type, self.target)


class Provenance(FrozenModel):
    """Where an observation comes from: plugin name, retrieval time, query sent.

    `query` describes what was asked (e.g. `%.example.com`), never a URL with credentials.
    """

    source: str = Field(min_length=1)
    retrieved_at: UtcDatetime
    query: str

    @field_validator("source")
    @classmethod
    def _source(cls, value: str) -> str:
        source = value.strip()
        if not source:
            raise ValueError("source must not be blank")
        return source

    @field_validator("query")
    @classmethod
    def _no_credentials(cls, value: str) -> str:
        if _CREDENTIAL.search(unquote(value)):
            raise ValueError("query must not carry a credential (key/token/secret parameter)")
        return value
