"""Exposed non-production names: dev, staging, test… that resolve on the public Internet.

Traffic: none. A name-pattern heuristic over in-scope domains plus resolution evidence
(an address reached directly or through a CNAME chain) already in the graph. Pre-production
environments often run with weaker auth, debug modes and real data copies, so a public one
is worth a look; but a name is only a hint, hence LOW severity and wording that says so.

Matching is on whole tokens (split on `.` and `-`) so `development` or `contest` do not
match. The last two labels (the registered domain, e.g. `example.com`) are not inspected,
so a scope root named `test.com` is not an environment. This approximates the public-suffix
rule: under a two-label suffix (`www.test.co.uk`) the registered label `test` is wrongly
inspected, a known false-positive accepted to avoid shipping a public-suffix list.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from domain_mapper.models import Finding, RelationType, Severity
from domain_mapper.risk._graph import cname_chain, in_scope_domains, targets_by_type
from domain_mapper.risk.engine import RuleContext

ENVIRONMENT_TOKENS = frozenset(
    {"dev", "staging", "stage", "stg", "test", "testing", "qa", "uat", "preprod", "sandbox"}
)
_SPLIT = re.compile(r"[.\-]")


def environment_tokens(fqdn: str) -> list[str]:
    """Environment words found left of the registered domain, in name order."""
    prefix = ".".join(fqdn.split(".")[:-2])
    return [t for t in _SPLIT.split(prefix) if t in ENVIRONMENT_TOKENS]


class ExposedEnvironmentRule:
    id = "exposed-environments"

    def evaluate(self, ctx: RuleContext) -> Iterable[Finding]:
        index = targets_by_type(ctx.graph)
        for domain in in_scope_domains(ctx.graph):
            tokens = environment_tokens(domain.fqdn)
            if not tokens:
                continue
            # A dangling CNAME does not "resolve": that case belongs to the takeover rule.
            if not any(
                (name, RelationType.RESOLVES_TO) in index
                for name in (domain.id, *cname_chain(index, domain.id))
            ):
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
