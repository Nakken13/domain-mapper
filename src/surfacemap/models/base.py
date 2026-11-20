"""Shared building blocks for every SurfaceMap model."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, StringConstraints


def _to_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


UtcDatetime = Annotated[AwareDatetime, AfterValidator(_to_utc)]
"""A timezone-aware datetime, normalized to UTC (naive datetimes are refused)."""

NonBlankStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
"""A string stripped of surrounding whitespace, refused when empty."""


class FrozenModel(BaseModel):
    """Immutable, strict model: once emitted by a plugin, nothing can mutate it."""

    # hide_input_in_errors: a refused value (credential, email) must never be echoed into a
    # log line or traceback through the ValidationError message.
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)
