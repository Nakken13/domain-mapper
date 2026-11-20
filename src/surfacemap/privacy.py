"""Personal-data filters. Everything a plugin emits passes through here before the graph.

Two layers, both fail-closed (when in doubt, drop):

* `redact_registration` works on the **raw** WHOIS/RDAP payload, before a plugin builds
  entities from it. Expected shape: the decoded JSON object (dict) of an RDAP response
  (RFC 9083) or a flat WHOIS dict as returned by python-whois. It is an **allow-list**:
  only the technical fields below survive (names, status, dates, name servers, DNSSEC,
  registrar). Everything else (RDAP `entities` vCards, `remarks`, raw WHOIS text, any
  registrant/admin/tech key, unknown keys) is dropped, so a new contact field in some
  registry's output can never slip through.
* `redact_observation` works on the typed `Observation` that enters the graph: drops
  certificate SANs that are email addresses, scrubs emails from **every** string field
  of every entity, relation endpoint and provenance, then re-validates each model (ids
  are recomputed, `model_construct` shortcuts are caught).

`strip_query` removes query strings and fragments (tokens, emails, session ids) from URLs.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, TypeVar, cast
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel

from surfacemap.models import Certificate, Observation

REDACTED_EMAIL = "[redacted-email]"

# Unicode-aware and fail-closed: any non-separator run, `@` or its URL-encoded form `%40`,
# then a dotted domain. Separators keep the surrounding text (`mailto:`, `/path/`, `rua=`).
# Lengths are capped at the RFC 5321 limits (local part 64, domain 253): unbounded runs
# made the backtracking quadratic, minutes on a 60 kB TXT record or archived path.
_SEP = r"\s@<>\"'(),;:\[\]/=?&#"
_EMAIL = re.compile(
    rf"[^{_SEP}]{{1,64}}(?:@|%40)[^{_SEP}%]{{1,253}}\.[^{_SEP}%.]{{2,63}}", re.IGNORECASE
)

# Allowed keys, normalized (lowercase, spaces/hyphens -> "_"). `None` = scalar or list of
# scalars kept (strings email-scrubbed); a dict = nested object(s) filtered recursively.
_Spec = Mapping[str, "_Spec | None"]
_REGISTRATION_ALLOWED: _Spec = {
    # RDAP (RFC 9083)
    "objectclassname": None,
    "ldhname": None,
    "unicodename": None,
    "status": None,
    "events": {"eventaction": None, "eventdate": None},
    "nameservers": {"ldhname": None, "unicodename": None},
    "securedns": {"delegationsigned": None, "zonesigned": None},
    # flat WHOIS (python-whois)
    "domain_name": None,
    "registrar": None,
    "whois_server": None,
    "creation_date": None,
    "updated_date": None,
    "expiration_date": None,
    "name_servers": None,
    "dnssec": None,
}

_DROP = object()


def _normalize_key(key: object) -> str:
    return re.sub(r"[\s-]+", "_", str(key).strip().lower())


def scrub_emails(text: str) -> str:
    """Replace every email address in `text` (Unicode, `%40`-encoded) with a placeholder."""
    return _EMAIL.sub(REDACTED_EMAIL, text)


def _scalar(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _DROP  # an object where a scalar is expected: unknown shape, drop it
    if isinstance(value, list | tuple):
        return [item for item in (_scalar(v) for v in value) if item is not _DROP]
    return scrub_emails(value) if isinstance(value, str) else value


def _filter(value: Any, spec: _Spec | None) -> Any:
    if spec is None:
        return _scalar(value)
    if isinstance(value, Mapping):
        kept = {}
        for key, item in value.items():
            normalized = _normalize_key(key)
            if normalized in spec:
                filtered = _filter(item, spec[normalized])
                if filtered is not _DROP:
                    kept[key] = filtered
        return kept
    if isinstance(value, list | tuple):
        return [_filter(item, spec) for item in value if isinstance(item, Mapping)]
    return _DROP


def redact_registration(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of a raw WHOIS/RDAP payload keeping only allow-listed technical fields."""
    # A Mapping input always yields a dict (never _DROP).
    return cast(dict[str, Any], _filter(payload, _REGISTRATION_ALLOWED))


def drop_email_sans(sans: tuple[str, ...]) -> tuple[str, ...]:
    """Remove certificate SANs that contain an `@` (rfc822Name, i.e. a person's email)."""
    return tuple(san for san in sans if "@" not in san)


def strip_query(url: str) -> str:
    """Remove the query string and fragment of a URL (absolute or path-only)."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


_M = TypeVar("_M", bound=BaseModel)


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return scrub_emails(value)
    if isinstance(value, tuple):
        return tuple(_scrub(item) for item in value)
    if isinstance(value, BaseModel):
        return _scrub_model(value)
    return value


def _scrub_model(model: _M) -> _M:
    fields = dict(model)
    if isinstance(model, Certificate):
        fields["sans"] = drop_email_sans(fields["sans"])
    return type(model).model_validate({name: _scrub(value) for name, value in fields.items()})


def redact_observation(observation: Observation) -> Observation:
    """Return the observation, re-validated, with every personal datum removed."""
    return _scrub_model(observation)
