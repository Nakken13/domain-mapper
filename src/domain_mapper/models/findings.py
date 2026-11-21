"""What plugins emit (observations) and what risk rules conclude (findings)."""

from __future__ import annotations

import operator
import re
from collections.abc import Callable
from enum import StrEnum
from typing import Self

from pydantic import Field, field_validator, model_validator

from domain_mapper.models.base import FrozenModel, NonBlankStr
from domain_mapper.models.entities import ID_PREFIXES, Entity, id_kind
from domain_mapper.models.relations import Provenance, Relation

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


def _by_rank(op: Callable[[int, int], bool]) -> Callable[[Severity, object], bool]:
    def compare(self: Severity, other: object) -> bool:
        if not isinstance(other, Severity):
            raise TypeError(f"cannot compare Severity with {type(other).__name__}")
        return op(_RANK[self], _RANK[other])

    return compare


class Severity(StrEnum):
    """Finding severity, ordered from INFO (lowest) to CRITICAL (highest)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    # Refuse plain strings: StrEnum would otherwise fall back to alphabetical order.
    __lt__ = _by_rank(operator.lt)
    __le__ = _by_rank(operator.le)
    __gt__ = _by_rank(operator.gt)
    __ge__ = _by_rank(operator.ge)


_RANK = {severity: rank for rank, severity in enumerate(Severity)}


class Finding(FrozenModel):
    """An explainable risk: why it matters, which graph nodes prove it, how to fix it."""

    rule_id: str
    severity: Severity
    title: NonBlankStr
    rationale: NonBlankStr
    evidence: tuple[str, ...] = Field(min_length=1)
    remediation: NonBlankStr

    @field_validator("rule_id")
    @classmethod
    def _rule_id(cls, value: str) -> str:
        if not _RULE_ID.match(value):
            raise ValueError("rule_id must be a lowercase kebab-case slug")
        return value

    @field_validator("evidence")
    @classmethod
    def _entity_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for entity_id in value:
            _, sep, rest = entity_id.partition(":")
            if not sep or not rest or id_kind(entity_id) not in ID_PREFIXES:
                raise ValueError(f"{entity_id!r} is not an entity id")
        return value
