"""Authorization guard: domain-mapper only works on domains listed in `scope.yaml`.

Every entry point must call `Scope.require()` before any collection. Matching is
done on normalized names (lowercase, IDNA/punycode, no trailing dot) with an
exact-label suffix rule, so `evil-example.com` never matches `example.com` and
`example.com.evil.net` never matches either.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_MAX_NAME_LENGTH = 253


class InvalidDomainError(ValueError):
    """The input is not a syntactically valid hostname."""


class ScopeFileError(Exception):
    """`scope.yaml` is missing or malformed."""


class OutOfScopeError(PermissionError):
    """The requested domain is not covered by a valid authorization."""


def try_normalize_domain(raw: str) -> str | None:
    """`normalize_domain`, or None when `raw` is not a valid hostname."""
    try:
        return normalize_domain(raw)
    except InvalidDomainError:
        return None


def normalize_domain(raw: str) -> str:
    """Return the canonical ASCII form of a hostname, or raise InvalidDomainError."""
    name = raw.strip().lower().removesuffix(".")
    if not name:
        raise InvalidDomainError("empty domain")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise InvalidDomainError(f"{raw!r} is an IP address, not a domain")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDomainError(f"{raw!r} is not a valid domain: {exc}") from exc
    labels = name.split(".")
    if len(name) > _MAX_NAME_LENGTH or not all(_LABEL.match(label) for label in labels):
        raise InvalidDomainError(f"{raw!r} is not a valid domain")
    return name


class ScopeEntry(BaseModel):
    """One authorized domain, with the authorization that justifies it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    domain: str
    include_subdomains: bool = True
    authorization: str = Field(min_length=1)
    expires: date | None = None

    @field_validator("domain")
    @classmethod
    def _valid_registrable_domain(cls, value: str) -> str:
        domain = normalize_domain(value)
        if "." not in domain:
            raise ValueError(f"{value!r} is a bare TLD: it would authorize a whole namespace")
        return domain

    @field_validator("authorization", mode="before")
    @classmethod
    def _strip_authorization(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    def covers(self, domain: str) -> bool:
        return domain == self.domain or (
            self.include_subdomains and domain.endswith("." + self.domain)
        )

    def is_expired(self, today: date) -> bool:
        return self.expires is not None and today > self.expires


class _ScopeFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorized: list[ScopeEntry] = Field(min_length=1)


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    domain: str | None = None
    entry: ScopeEntry | None = None


class Scope:
    def __init__(self, entries: list[ScopeEntry]) -> None:
        # Longest (most specific) domain first: see check() for the precedence rule.
        self.entries = sorted(entries, key=lambda e: len(e.domain), reverse=True)

    @classmethod
    def load(cls, path: Path) -> Scope:
        if not path.is_file():
            raise ScopeFileError(
                f"{path} not found. Copy scope.example.yaml to scope.yaml and list "
                "only the domains you own or are authorized in writing to assess."
            )
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ScopeFileError(f"{path}: expected a mapping with an 'authorized' list")
            parsed = _ScopeFile.model_validate(data)
        except yaml.YAMLError as exc:
            raise ScopeFileError(f"{path}: invalid YAML: {exc}") from exc
        except ValidationError as exc:
            raise ScopeFileError(f"{path}: invalid scope file:\n{exc}") from exc
        return cls(parsed.authorized)

    def check(self, raw_domain: str, today: date | None = None) -> ScopeDecision:
        today = today or date.today()
        try:
            domain = normalize_domain(raw_domain)
        except InvalidDomainError as exc:
            return ScopeDecision(allowed=False, reason=f"invalid domain: {exc}")

        # The most specific entry naming the domain or one of its parents decides
        # alone (fail closed): a parent never overrides a restrictive or expired child.
        entry = next(
            (e for e in self.entries if domain == e.domain or domain.endswith("." + e.domain)),
            None,
        )
        if entry is None:
            reason = f"{domain} is not listed in the scope file"
        elif not entry.covers(domain):
            reason = f"subdomains of {entry.domain} are not authorized"
        elif entry.is_expired(today):
            reason = f"authorization for {entry.domain} expired on {entry.expires}"
        else:
            return ScopeDecision(
                allowed=True, reason=f"covered by {entry.domain}", domain=domain, entry=entry
            )
        return ScopeDecision(allowed=False, reason=reason, domain=domain)

    def require(self, raw_domain: str, today: date | None = None) -> str:
        """Return the normalized domain, or raise OutOfScopeError."""
        decision = self.check(raw_domain, today=today)
        if not decision.allowed or decision.domain is None:
            raise OutOfScopeError(f"{raw_domain!r} refused: {decision.reason}")
        return decision.domain
