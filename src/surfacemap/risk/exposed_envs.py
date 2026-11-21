"""Exposed non-production names: dev, staging, test… that resolve on the public Internet.

Traffic: none. A name-pattern heuristic over in-scope domains plus resolution evidence
(`RESOLVES_TO` or `CNAME_TO`) already in the graph. Pre-production environments often run
with weaker auth, debug modes and real data copies, so a public one is worth a look; but a
name is only a hint, hence LOW severity and wording that says so.

Matching is on whole tokens (split on `.` and `-`) so `development` or `contest` do not
match. The last two labels (the registered domain, e.g. `example.com`) are not inspected,
so a scope root named `test.com` is not an environment. This approximates the public-suffix
rule: under a two-label suffix (`www.test.co.uk`) the registered label `test` is wrongly
inspected, a known false-positive accepted to avoid shipping a public-suffix list.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from surfacemap.models import Domain, Finding, RelationType, Severity
from surfacemap.risk.engine import RuleContext

ENVIRONMENT_TOKENS = frozenset(
    {"dev", "staging", "stage", "stg", "test", "testing", "qa", "uat", "preprod", "sandbox"}
)
_SPLIT = re.compile(r"[.\-]")
_EXPOSING = frozenset({RelationType.RESOLVES_TO, RelationType.CNAME_TO})


def environment_tokens(fqdn: str) -> list[str]:
    """Environment words found left of the registered domain, in name order."""
    prefix = ".".join(fqdn.split(".")[:-2])
    return [t for t in _SPLIT.split(prefix) if t in ENVIRONMENT_TOKENS]


class ExposedEnvironmentRule:
    id = "exposed-environments"

    def evaluate(self, ctx: RuleContext) -> Iterable[Finding]:
        exposed = {key[0] for key in ctx.graph.edges if key[1] in _EXPOSING}
        for node_id in sorted(exposed):
            node = ctx.graph.nodes.get(node_id)
            if node is None or not isinstance(node.entity, Domain) or not node.entity.in_scope:
                continue
            domain = node.entity
            tokens = environment_tokens(domain.fqdn)
            if not tokens:
                continue
            yield Finding(
                rule_id=self.id,
                severity=Severity.LOW,
                title=f"Non-production name resolves publicly: {domain.fqdn}",
                rationale=(
                    f"The name contains {', '.join(sorted(set(tokens)))!r} and resolves in "
                    "public DNS. Pre-production environments often have weaker access control, "
                    "debug features or copies of real data. The name is only a hint: confirm "
                    "what it serves."
                ),
                evidence=(domain.id,),
                remediation=(
                    "Restrict it (VPN, IP allow-list, SSO) or remove the DNS record if unused."
                ),
            )
