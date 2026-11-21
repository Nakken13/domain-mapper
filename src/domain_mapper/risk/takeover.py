"""Subdomain-takeover rule: a CNAME that points to a claimable provider and no longer resolves.

Traffic: none. The evidence is already in the graph: a `CNAME_TO` chain, and the
`RCODE=NXDOMAIN` record the DNS plugin put on the last name of the chain. We deliberately do
not fetch the page to look for a provider error banner: that would be an HTTP request to the
target, and "possible takeover" is a *lead* to verify by the owner, not a proof.

Fails quiet on purpose in one place only: if the NXDOMAIN observation is absent the absence is
unconfirmed, so nothing is reported (no guess).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

from domain_mapper.models import Domain, Finding, Severity
from domain_mapper.plugins.dns_records import NXDOMAIN
from domain_mapper.risk._graph import cname_chain, in_scope_domains, targets_by_type
from domain_mapper.risk.engine import RuleContext

DATA_FILE = Path(__file__).parent / "data" / "takeover_providers.yaml"


@dataclass(frozen=True)
class Provider:
    name: str
    suffixes: tuple[str, ...]

    def matches(self, fqdn: str) -> bool:
        # Label boundary: "evilgithub.io" must not match "github.io".
        return any(fqdn == s or fqdn.endswith(f".{s}") for s in self.suffixes)


def load_providers(path: Path = DATA_FILE) -> tuple[Provider, ...]:
    """Read the provider list; a malformed entry is an error, never silently dropped."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = raw.get("providers") if isinstance(raw, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{path}: expected a non-empty 'providers' list")
    providers = []
    for entry in entries:
        name = entry.get("name") if isinstance(entry, dict) else None
        suffixes = entry.get("suffixes") if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{path}: provider without a name: {entry!r}")
        if not isinstance(suffixes, list) or not suffixes:
            raise ValueError(f"{path}: provider {name!r} needs a non-empty 'suffixes' list")
        providers.append(Provider(name, tuple(str(s).lower().strip(".") for s in suffixes)))
    return tuple(providers)


class TakeoverRule:
    id = "takeover"

    def __init__(self, providers: Iterable[Provider] | None = None) -> None:
        self._providers = tuple(providers) if providers is not None else load_providers()

    def evaluate(self, ctx: RuleContext) -> Iterable[Finding]:
        nodes = ctx.graph.nodes
        index = targets_by_type(ctx.graph)
        for src in in_scope_domains(ctx.graph):
            # Every hop, not only the first: www -> partner CDN (out of scope) -> x.github.io
            # is still www's takeover risk.
            for target_id in cname_chain(index, src.id):
                target = nodes.get(target_id)
                dst = target.entity if target is not None else None
                if not isinstance(dst, Domain):
                    continue
                if NXDOMAIN not in dst.records:
                    continue
                provider = next((p for p in self._providers if p.matches(dst.fqdn)), None)
                if provider is None:
                    continue
                yield Finding(
                    rule_id=self.id,
                    severity=Severity.HIGH,
                    title=f"Possible subdomain takeover: {src.fqdn} -> {dst.fqdn}",
                    rationale=(
                        f"{src.fqdn} is a CNAME to {dst.fqdn} ({provider.name}), which answers "
                        "NXDOMAIN. Anyone who registers that name at the provider could serve "
                        "content on your subdomain. Detected from DNS only, no HTTP request was "
                        "sent to the target: confirm before acting."
                    ),
                    evidence=(src.id, dst.id),
                    remediation=(
                        f"Delete the CNAME for {src.fqdn}, or re-create the resource at "
                        f"{provider.name} under your account."
                    ),
                )
