"""Personal-data filters. Everything a plugin emits passes through here before the graph.

Two layers, both fail-closed (when in doubt, drop):

* `redact_registration` works on the **raw** WHOIS/RDAP payload, before a plugin builds
  entities from it. Expected shape: the decoded JSON object (dict) of an RDAP response
  (RFC 9083) or a flat WHOIS dict (keys such as `registrant_name`, `Admin Email`). Every
  contact is removed: the RDAP `entities` array (vCards of registrant/admin/tech/abuse),
  any key naming a contact role or personal attribute, and email addresses in free text.
* `redact_observation` works on the typed `Observation` that enters the graph: drops
  certificate SANs that are email addresses and scrubs emails from free-text fields.

`strip_query` removes query strings and fragments (tokens, emails, session ids) from URLs.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from surfacemap.models import Certificate, DnsRecord, Domain, Entity, Observation, Technology

REDACTED_EMAIL = "[redacted-email]"
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Keys whose whole value is dropped. Normalized: lowercase, spaces and hyphens -> "_".
_CONTACT_KEYS = frozenset(
    {
        "entities",
        "vcardarray",
        "name",
        "email",
        "emails",
        "phone",
        "fax",
        "address",
        "street",
        "city",
        "postal_code",
        "contact",
        "contacts",
    }
)
_CONTACT_PREFIXES = ("registrant", "admin", "tech", "billing", "abuse", "contact", "owner")


def _is_contact_key(key: str) -> bool:
    normalized = re.sub(r"[\s-]+", "_", key.strip().lower())
    return normalized in _CONTACT_KEYS or normalized.startswith(_CONTACT_PREFIXES)


def scrub_emails(text: str) -> str:
    """Replace every email address in `text` with a fixed placeholder."""
    return _EMAIL.sub(REDACTED_EMAIL, text)


def _redact_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return redact_registration(value)
    if isinstance(value, list | tuple):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        return scrub_emails(value)
    return value


def redact_registration(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of a raw WHOIS/RDAP payload without any contact data."""
    return {
        key: _redact_value(value) for key, value in payload.items() if not _is_contact_key(str(key))
    }


def drop_email_sans(sans: tuple[str, ...]) -> tuple[str, ...]:
    """Remove certificate SANs that contain an `@` (rfc822Name, i.e. a person's email)."""
    return tuple(san for san in sans if "@" not in san)


def strip_query(url: str) -> str:
    """Remove the query string and fragment of a URL (absolute or path-only)."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _redact_entity(entity: Entity) -> Entity:
    if isinstance(entity, Certificate):
        return entity.model_copy(update={"sans": drop_email_sans(entity.sans)})
    if isinstance(entity, Domain):
        records = tuple(
            DnsRecord(type=record.type, value=scrub_emails(record.value))
            for record in entity.records
        )
        return entity.model_copy(update={"records": records})
    if isinstance(entity, Technology):
        return entity.model_copy(update={"evidence": scrub_emails(entity.evidence)})
    return entity


def redact_observation(observation: Observation) -> Observation:
    """Return the observation with every personal datum removed from its free text."""
    provenance = observation.provenance.model_copy(
        update={"query": scrub_emails(observation.provenance.query)}
    )
    return observation.model_copy(
        update={
            "provenance": provenance,
            "entities": tuple(_redact_entity(entity) for entity in observation.entities),
        }
    )
