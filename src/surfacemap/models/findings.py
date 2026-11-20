"""What plugins emit (observations) and what risk rules conclude (findings)."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Self

from pydantic import Field, field_validator, model_validator

from surfacemap.models.base import FrozenModel
from surfacemap.models.entities import ID_PREFIXES, Entity
from surfacemap.models.relations import Provenance, Relation

_RULE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class Observation(FrozenModel):
    """The only output of a plugin: entities and relations seen by one query.

    Plugins never mutate the graph; `graph.builder` merges observations.
    """

    provenance: Provenance
    entities: tuple[Entity, ...] = ()
    relations: tuple[Relation, ...] = ()

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not self.entities and not self.relations:
            raise ValueError("an observation must carry at least one entity or relation")
        return self


class Severity(StrEnum):
    """Finding severity, ordered from INFO (lowest) to CRITICAL (highest)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def _ranks(self, other: object) -> tuple[int, int]:
        # Refuse plain strings: StrEnum would otherwise fall back to alphabetical order.
        if not isinstance(other, Severity):
            raise TypeError(f"cannot compare Severity with {type(other).__name__}")
        return _RANK[self], _RANK[other]

    def __lt__(self, other: object) -> bool:
        mine, theirs = self._ranks(other)
        return mine < theirs

    def __le__(self, other: object) -> bool:
        mine, theirs = self._ranks(other)
        return mine <= theirs

    def __gt__(self, other: object) -> bool:
        mine, theirs = self._ranks(other)
        return mine > theirs

    def __ge__(self, other: object) -> bool:
        mine, theirs = self._ranks(other)
        return mine >= theirs


_RANK = {severity: rank for rank, severity in enumerate(Severity)}


def _not_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    return value.strip()


class Finding(FrozenModel):
    """An explainable risk: why it matters, which graph nodes prove it, how to fix it."""

    rule_id: str
    severity: Severity
    title: str
    rationale: str
    evidence: tuple[str, ...] = Field(min_length=1)
    remediation: str

    @field_validator("rule_id")
    @classmethod
    def _rule_id(cls, value: str) -> str:
        if not _RULE_ID.match(value):
            raise ValueError("rule_id must be a lowercase kebab-case slug")
        return value

    @field_validator("title", "rationale", "remediation")
    @classmethod
    def _filled(cls, value: str) -> str:
        return _not_blank(value)

    @field_validator("evidence")
    @classmethod
    def _entity_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for entity_id in value:
            prefix, sep, rest = entity_id.partition(":")
            if not sep or not rest or prefix not in ID_PREFIXES:
                raise ValueError(f"{entity_id!r} is not an entity id")
        return value
