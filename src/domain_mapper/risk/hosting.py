"""Hosting-sprawl rule: in-scope names spread over many hosting providers.

Traffic: none. Walks `in-scope name -> CNAME chain -> IP -> ASN` over edges already in the
graph. The provider of an address is the holder of its announcing ASN.

Each extra provider is another contract, another console and another place where an
asset can be forgotten or misconfigured, so a wide spread is worth a review. It is a
posture hint, not a vulnerability: LOW severity, and one summary finding for the whole scan
(a finding per provider would be noise).

Holders are grouped by their first alphanumeric token (`AMAZON-02` and `AMAZON-AES` are
one operator). That is an approximation, and it errs toward *merging* names that start with
the same word, i.e. toward under-reporting.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable

from domain_mapper.models import ASN, Finding, RelationType, Severity
from domain_mapper.risk._graph import cname_chain, in_scope_domains, targets_by_type
from domain_mapper.risk.engine import RuleContext

MIN_PROVIDERS = 3
"""Report when in-scope names are hosted by at least this many distinct providers."""
_TOKEN = re.compile(r"[a-z0-9]+")


def provider_key(holder: str | None, number: int) -> str:
    """Grouping key of an ASN holder; falls back to the AS number when unnamed."""
    if holder:
        match = _TOKEN.search(holder.lower())
        if match:
            return match.group()
    return f"as{number}"


class HostingSprawlRule:
    id = "hosting-sprawl"

    def evaluate(self, ctx: RuleContext) -> Iterable[Finding]:
        graph = ctx.graph
        targets = targets_by_type(graph)

        asns: dict[str, set[str]] = defaultdict(set)  # provider key -> ASN ids
        names: dict[str, set[str]] = defaultdict(set)  # provider key -> in-scope names
        for domain in in_scope_domains(graph):
            for name in (domain.id, *cname_chain(targets, domain.id)):
                for ip_id in targets.get((name, RelationType.RESOLVES_TO), ()):
                    for asn_id in targets.get((ip_id, RelationType.ANNOUNCED_BY), ()):
                        asn_node = graph.nodes.get(asn_id)
                        if asn_node is None or not isinstance(asn_node.entity, ASN):
                            continue
                        key = provider_key(asn_node.entity.holder, asn_node.entity.number)
                        asns[key].add(asn_id)
                        names[key].add(domain.id)

        if len(asns) < MIN_PROVIDERS:
            return
        listing = ", ".join(
            f"{key} ({len(names[key])} name{'s' if len(names[key]) != 1 else ''})"
            for key in sorted(asns)
        )
        yield Finding(
            rule_id=self.id,
            severity=Severity.LOW,
            title=f"In-scope names are hosted by {len(asns)} different providers",
            rationale=(
                f"Providers (grouped by ASN holder): {listing}. Every extra provider adds "
                "an account to secure and a place where an asset can be forgotten; it is "
                "a posture hint, not a vulnerability."
            ),
            evidence=tuple(sorted(asn for ids in asns.values() for asn in ids)),
            remediation=(
                "Check that each provider is intended and has an owner, MFA and monitoring; "
                "consolidate where it makes sense."
            ),
        )
