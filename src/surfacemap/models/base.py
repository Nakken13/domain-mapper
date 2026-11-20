"""Shared building blocks for every SurfaceMap model."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict


def _to_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


UtcDatetime = Annotated[AwareDatetime, AfterValidator(_to_utc)]
"""A timezone-aware datetime, normalized to UTC (naive datetimes are refused)."""


class FrozenModel(BaseModel):
    """Immutable, strict model: once emitted by a plugin, nothing can mutate it."""

    model_config = ConfigDict(frozen=True, extra="forbid")
