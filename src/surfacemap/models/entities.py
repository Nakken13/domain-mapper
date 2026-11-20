"""Graph entities. Each one has a stable id `type:value` built from canonical fields.

Two sources that see the same asset must produce the same id, so every identifying
field is normalized here (lowercase IDNA names, compressed IPs, bare ASN numbers,
lowercase hex fingerprints). The id is the deduplication key of the graph merge.
"""

from __future__ import annotations

import ipaddress
import re
from abc import ABC, abstractmethod
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from surfacemap.models.base import FrozenModel, UtcDatetime
from surfacemap.scope import normalize_domain

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COUNTRY = re.compile(r"^[A-Z]{2}$")
_MAX_ASN = 2**32 - 1

ID_PREFIXES = frozenset({"domain", "ip", "asn", "cert", "tech", "url"})
"""Every valid entity id starts with one of these, followed by `:`."""


def _normalize_country(value: object) -> object:
    if value is None:
        return None
    country = str(value).strip().upper()
    if not _COUNTRY.match(country):
        raise ValueError(f"{value!r} is not an ISO 3166-1 alpha-2 country code")
    return country


class _Entity(FrozenModel, ABC):
    @property
    @abstractmethod
    def id(self) -> str:
        """Stable `type:value` identifier, the deduplication key of the graph."""


class DnsRecord(FrozenModel):
    """A raw DNS record kept on a domain (TXT, CAA, …), not modeled as a relation."""

    type: str = Field(min_length=1)
    value: str

    @field_validator("type")
    @classmethod
    def _upper(cls, value: str) -> str:
        return value.strip().upper()


class Domain(_Entity):
    kind: Literal["domain"] = "domain"
    fqdn: str
    in_scope: bool
    records: tuple[DnsRecord, ...] = ()

    @field_validator("fqdn")
    @classmethod
    def _normalize(cls, value: str) -> str:
        return normalize_domain(value)

    @property
    def id(self) -> str:
        return f"domain:{self.fqdn}"


class IPAddress(_Entity):
    kind: Literal["ip"] = "ip"
    address: str
    country: str | None = None

    @field_validator("address")
    @classmethod
    def _compress(cls, value: str) -> str:
        return ipaddress.ip_address(value.strip()).compressed

    @field_validator("country", mode="before")
    @classmethod
    def _country(cls, value: object) -> object:
        return _normalize_country(value)

    @property
    def id(self) -> str:
        return f"ip:{self.address}"


class ASN(_Entity):
    kind: Literal["asn"] = "asn"
    number: int = Field(ge=1, le=_MAX_ASN)
    holder: str | None = None
    country: str | None = None

    @field_validator("number", mode="before")
    @classmethod
    def _strip_prefix(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().upper().removeprefix("AS")
        return value

    @field_validator("country", mode="before")
    @classmethod
    def _country(cls, value: object) -> object:
        return _normalize_country(value)

    @property
    def id(self) -> str:
        return f"asn:{self.number}"


class Certificate(_Entity):
    kind: Literal["certificate"] = "certificate"
    sha256: str
    issuer: str
    not_before: UtcDatetime
    not_after: UtcDatetime
    sans: tuple[str, ...] = ()

    @field_validator("sha256")
    @classmethod
    def _fingerprint(cls, value: str) -> str:
        digest = value.strip().lower().replace(":", "")
        if not _SHA256.match(digest):
            raise ValueError("sha256 must be 64 hex characters")
        return digest

    @field_validator("sans")
    @classmethod
    def _lower_sans(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(san.strip().lower().removesuffix(".") for san in value)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.not_after < self.not_before:
            raise ValueError("not_after is before not_before")
        return self

    @property
    def id(self) -> str:
        return f"cert:{self.sha256}"


class Technology(_Entity):
    kind: Literal["technology"] = "technology"
    name: str = Field(min_length=1)
    category: str
    evidence: str

    @property
    def id(self) -> str:
        return f"tech:{self.name.strip().lower()}"


class ArchivedURL(_Entity):
    """A URL seen in a web archive. Query strings and fragments are never stored."""

    kind: Literal["archived_url"] = "archived_url"
    host: str
    path: str
    first_seen: UtcDatetime
    last_seen: UtcDatetime

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        return normalize_domain(value)

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        if "?" in value or "#" in value:
            raise ValueError("archived URL path must not carry a query string or fragment")
        return value if value.startswith("/") else f"/{value}"

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen is before first_seen")
        return self

    @property
    def id(self) -> str:
        return f"url:{self.host}{self.path}"


Entity = Annotated[
    Domain | IPAddress | ASN | Certificate | Technology | ArchivedURL,
    Field(discriminator="kind"),
]
"""Any graph node, discriminated by its `kind` field."""
