"""SPF (RFC 7208) and DMARC (RFC 7489) parsing of records already collected.

Traffic: none. These are pure functions over the `TXT` and `DMARC` records the DNS plugin
stores on a `Domain`; the risk rules call them. No include is followed: counting the
lookup-costing terms of the record itself is enough to flag a likely limit overflow.

Report addresses (`rua`/`ruf`) are email addresses: only their presence is kept.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from surfacemap.models import Domain

SPF_LOOKUP_LIMIT = 10
"""RFC 7208 § 4.6.4: more DNS-querying terms than this is a permanent error."""
_LOOKUP_MECHANISMS = frozenset({"a", "mx", "ptr", "exists", "include"})
_QUALIFIERS = "+-~?"

Disposition = Literal["none", "quarantine", "reject"]
_DISPOSITIONS: frozenset[str] = frozenset({"none", "quarantine", "reject"})


@dataclass(frozen=True)
class SpfPolicy:
    all_qualifier: str | None
    """Qualifier of the final `all` (`-` fail, `~` softfail, `?` neutral, `+` pass)."""
    includes: tuple[str, ...]
    redirect: str | None
    dns_lookups: int
    uses_ptr: bool

    @property
    def is_strict(self) -> bool:
        return self.all_qualifier == "-"

    @property
    def within_lookup_limit(self) -> bool:
        return self.dns_lookups <= SPF_LOOKUP_LIMIT


def parse_spf(record: str) -> SpfPolicy | None:
    """The SPF policy of one TXT value, or None when it is not an SPF record."""
    terms = record.split()
    if not terms or terms[0].lower() != "v=spf1":
        return None
    all_qualifier: str | None = None
    includes: list[str] = []
    redirect: str | None = None
    lookups = 0
    uses_ptr = False
    for term in (t.lower() for t in terms[1:]):
        if term.startswith("redirect="):
            redirect = term.removeprefix("redirect=")
            lookups += 1
            continue
        qualifier = term[0] if term[0] in _QUALIFIERS else "+"
        mechanism, _, value = term.lstrip(_QUALIFIERS).partition(":")
        mechanism = mechanism.split("/", 1)[0]  # `a/24`, `mx/24`
        if mechanism == "all":
            all_qualifier = qualifier
        elif mechanism in _LOOKUP_MECHANISMS:
            lookups += 1
            uses_ptr = uses_ptr or mechanism == "ptr"
            if mechanism == "include":
                includes.append(value)
    return SpfPolicy(all_qualifier, tuple(includes), redirect, lookups, uses_ptr)


def spf_of(domain: Domain) -> list[SpfPolicy]:
    """Every SPF policy published on `domain` (more than one is itself an error)."""
    found = (parse_spf(r.value) for r in domain.records if r.type == "TXT")
    return [policy for policy in found if policy is not None]


@dataclass(frozen=True)
class DmarcPolicy:
    policy: Disposition
    subdomain_policy: Disposition
    percent: int
    reports: bool
    """True when aggregate or forensic reports are requested (addresses not kept)."""
    strict_dkim_alignment: bool
    strict_spf_alignment: bool

    @property
    def is_enforced(self) -> bool:
        return self.policy != "none" and self.percent == 100


def _tags(record: str) -> list[tuple[str, str]]:
    pairs = []
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            pairs.append((key.strip().lower(), value.strip()))
    return pairs


def parse_dmarc(record: str) -> DmarcPolicy | None:
    """The DMARC policy of one record, or None when it is missing or invalid."""
    pairs = _tags(record)
    # RFC 7489 § 6.3: `v` must be the first tag.
    if not pairs or pairs[0][0] != "v" or pairs[0][1].upper() != "DMARC1":
        return None
    tags = dict(pairs)
    policy = tags.get("p", "").lower()
    subdomain = tags.get("sp", policy).lower()
    if policy not in _DISPOSITIONS or subdomain not in _DISPOSITIONS:
        return None
    try:
        percent = int(tags.get("pct", "100"))
    except ValueError:
        return None
    if not 0 <= percent <= 100:
        return None
    return DmarcPolicy(
        policy=policy,  # type: ignore[arg-type]  # checked against _DISPOSITIONS
        subdomain_policy=subdomain,  # type: ignore[arg-type]
        percent=percent,
        reports=bool(tags.get("rua") or tags.get("ruf")),
        strict_dkim_alignment=tags.get("adkim", "r").lower() == "s",
        strict_spf_alignment=tags.get("aspf", "r").lower() == "s",
    )


def dmarc_of(domain: Domain) -> DmarcPolicy | Literal["absent", "invalid"] | None:
    """DMARC state of `domain`: a policy, `absent` (confirmed), `invalid`, or None (unknown).

    None means the DNS plugin never looked it up or the lookup failed: a rule must not
    report a missing DMARC policy then.
    """
    values = [r.value for r in domain.records if r.type == "DMARC"]
    if not values:
        return None
    published = [v for v in values if v]
    if not published:
        return "absent"
    if len(published) > 1:  # RFC 7489 section 6.6.3: several records are discarded
        return "invalid"
    policy = parse_dmarc(published[0])
    return policy if policy is not None else "invalid"
