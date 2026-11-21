"""Email-authentication rule: missing or weak DMARC and SPF on in-scope domains.

Traffic: none. Reads the `TXT` and `DMARC` records the DNS plugin stored on each `Domain`,
through the `mailauth` parsers.

Two conservative choices, both to avoid reporting a risk that is only a failed lookup:

* DMARC is judged only when the plugin recorded a state for the name (`dmarc_of` returns
  None for "unknown", which stays silent);
* a missing SPF is reported only for a name with an MX edge, i.e. one that really handles
  mail: an absent TXT set cannot be told apart from a failed lookup, and a name that sends
  no mail does not need SPF.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from surfacemap.models import Domain, Finding, RelationType, Severity
from surfacemap.plugins.mailauth import SPF_LOOKUP_LIMIT, DmarcPolicy, SpfPolicy, dmarc_of, spf_of
from surfacemap.risk.engine import RuleContext


class EmailAuthRule:
    id = "email-auth"

    def evaluate(self, ctx: RuleContext) -> Iterable[Finding]:
        mail_domains = {key[0] for key in ctx.graph.edges if key[1] is RelationType.MX}
        for node_id in sorted(ctx.graph.nodes):
            domain = ctx.graph.nodes[node_id].entity
            if not isinstance(domain, Domain) or not domain.in_scope:
                continue
            dmarc = dmarc_of(domain)
            yield from self._dmarc(domain, dmarc)
            yield from self._spf(
                domain,
                spf_of(domain),
                handles_mail=domain.id in mail_domains,
                dmarc_enforced=isinstance(dmarc, DmarcPolicy) and dmarc.is_enforced,
            )

    def _finding(
        self, domain: Domain, severity: Severity, title: str, rationale: str, fix: str
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            severity=severity,
            title=f"{title} on {domain.fqdn}",
            rationale=rationale,
            evidence=(domain.id,),
            remediation=fix,
        )

    def _dmarc(self, domain: Domain, state: DmarcPolicy | str | None) -> Iterator[Finding]:
        if state is None:
            return
        if state == "absent":
            yield self._finding(
                domain,
                Severity.MEDIUM,
                "No DMARC policy",
                "No DMARC record is published: receivers cannot be told to reject mail that "
                "spoofs this domain, so phishing in its name is easier.",
                "Publish a _dmarc TXT record, start with p=none and rua reporting, then move "
                "to quarantine and reject.",
            )
        elif state == "invalid":
            yield self._finding(
                domain,
                Severity.MEDIUM,
                "Invalid DMARC record",
                "The DMARC record is malformed or several are published; receivers discard "
                "it, which is the same as having no policy.",
                "Publish exactly one valid v=DMARC1 record with a p= tag.",
            )
        elif isinstance(state, DmarcPolicy):
            if state.policy == "none":
                yield self._finding(
                    domain,
                    Severity.MEDIUM,
                    "DMARC in monitoring mode (p=none)",
                    "The policy asks receivers to take no action on failing mail, so spoofed "
                    "messages are still delivered.",
                    "Move to p=quarantine then p=reject once the reports look clean.",
                )
            elif state.percent < 100:
                yield self._finding(
                    domain,
                    Severity.LOW,
                    f"DMARC applied to only {state.percent}% of mail",
                    f"pct={state.percent}: the remaining mail is treated as if p=none.",
                    "Raise pct to 100 when reports confirm legitimate senders pass.",
                )
            if state.is_enforced and state.subdomain_policy == "none":
                yield self._finding(
                    domain,
                    Severity.LOW,
                    "DMARC subdomain policy is weaker (sp=none)",
                    "Subdomains are exempt from the enforced policy, so they can be spoofed.",
                    "Remove sp= or set it to the same disposition as p=.",
                )

    def _spf(
        self,
        domain: Domain,
        policies: list[SpfPolicy],
        *,
        handles_mail: bool,
        dmarc_enforced: bool,
    ) -> Iterator[Finding]:
        if not policies:
            if handles_mail:
                yield self._finding(
                    domain,
                    Severity.MEDIUM,
                    "No SPF record",
                    "The domain has a mail server but publishes no SPF record, so receivers "
                    "cannot check which hosts may send for it.",
                    "Publish a v=spf1 TXT record listing the legitimate senders, ending in -all.",
                )
            return
        if len(policies) > 1:
            yield self._finding(
                domain,
                Severity.MEDIUM,
                "Several SPF records",
                "RFC 7208 allows one SPF record; several give a permanent error and SPF "
                "is ignored.",
                "Merge them into a single v=spf1 record.",
            )
            return
        (policy,) = policies
        qualifier = policy.all_qualifier
        if qualifier == "+":
            yield self._finding(
                domain,
                Severity.HIGH,
                "SPF allows any sender (+all)",
                "The record ends in +all: every host on the Internet passes SPF for this domain.",
                "Replace +all with -all (or ~all while DMARC is rolled out).",
            )
        elif qualifier == "?" or (qualifier is None and policy.redirect is None):
            yield self._finding(
                domain,
                Severity.MEDIUM,
                "SPF has no enforcing all",
                "The record ends in ?all or has no all mechanism, so it never rejects anyone.",
                "End the record with -all (or ~all while DMARC is rolled out).",
            )
        elif qualifier == "~" and not dmarc_enforced:
            yield self._finding(
                domain,
                Severity.LOW,
                "SPF softfail (~all) without enforced DMARC",
                "Softfail only marks mail as suspicious; without an enforced DMARC policy "
                "nothing acts on that mark.",
                "Enforce DMARC (p=quarantine or reject), or switch SPF to -all.",
            )
        if not policy.within_lookup_limit:
            yield self._finding(
                domain,
                Severity.MEDIUM,
                f"SPF exceeds the {SPF_LOOKUP_LIMIT}-DNS-lookup limit",
                f"The record costs about {policy.dns_lookups} lookups; above the limit receivers "
                "return a permanent error and SPF stops working.",
                "Flatten includes or drop unused ones.",
            )
        if policy.uses_ptr:
            yield self._finding(
                domain,
                Severity.LOW,
                "SPF uses the ptr mechanism",
                "RFC 7208 discourages ptr: slow, unreliable and costly for receivers.",
                "Replace ptr with explicit ip4/ip6 or include mechanisms.",
            )
