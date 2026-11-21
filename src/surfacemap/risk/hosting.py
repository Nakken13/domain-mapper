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

from surfacemap.models import ASN, Domain, Finding, RelationType, Severity
from surfacemap.risk.engine import RuleContext

MIN_PROVIDERS = 3
"""Report when in-scope names are hosted by at least this many distinct providers."""
_TOKEN = re.compile(r"[a-z0-9]+")


def provider_key(holder: str | None, number: int | None = None) -> str:
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
        targets: dict[tuple[str, RelationType], set[str]] = defaultdict(set)
        for source, rel_type, target in graph.edges:
            targets[(source, rel_type)].add(target)

        asns: dict[str, set[str]] = defaultdict(set)  # provider key -> ASN ids
        names: dict[str, set[str]] = defaultdict(set)  # provider key -> in-scope names
        for node_id, node in graph.nodes.items():
            if not (isinstance(node.entity, Domain) and node.entity.in_scope):
                continue
            seen: set[str] = set()
            stack = [node_id]
            while stack:  # follow the CNAME chain; `seen` also stops a CNAME loop
                current = stack.pop()
                if current in seen:
                    continue
                seen.add(current)
                stack.extend(targets.get((current, RelationType.CNAME_TO), ()))
                for ip_id in targets.get((current, RelationType.RESOLVES_TO), ()):
                    for asn_id in targets.get((ip_id, RelationType.ANNOUNCED_BY), ()):
                        asn_node = graph.nodes.get(asn_id)
                        if asn_node is None or not isinstance(asn_node.entity, ASN):
                            continue
                        key = provider_key(asn_node.entity.holder, asn_node.entity.number)
                        asns[key].add(asn_id)
                        names[key].add(node_id)

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
