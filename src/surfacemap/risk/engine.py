"""Risk rule engine: run pure rules over the merged graph and return explainable findings.

Traffic: none. A rule is a pure function of the graph and a pinned date; it never opens a
socket, so the engine stays passive by construction and every run is reproducible.

Guarantees of `run_rules`:

* the result does not depend on the order of the rules (sorted, deduplicated);
* a rule may only emit findings carrying its own `id` (otherwise `rule_id` in the report
  would lie about which rule fired);
* a rule that crashes aborts the run with a `RuleError` naming it: a silently skipped rule
  would read as "no risk found", which is the worst possible failure for this tool.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Protocol, runtime_checkable

from surfacemap.graph.builder import SurfaceGraph
from surfacemap.models import Finding, Severity


class RuleError(RuntimeError):
    """A rule crashed or broke the rule contract."""


@dataclass(frozen=True)
class RuleContext:
    """What a rule may read. `today` is pinned once so a run crossing midnight is coherent."""

    graph: SurfaceGraph
    today: date


@runtime_checkable
class Rule(Protocol):
    id: str

    def evaluate(self, ctx: RuleContext) -> Iterable[Finding]: ...


_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Severity)}


def _sort_key(finding: Finding) -> tuple[int, str, tuple[str, ...], str]:
    # Severity is compared by rank (highest first); the title makes the order total.
    return (
        -_SEVERITY_RANK[finding.severity],
        finding.rule_id,
        finding.evidence,
        finding.title,
    )


def run_rules(ctx: RuleContext, rules: Sequence[Rule]) -> tuple[Finding, ...]:
    """Evaluate every rule and return findings, most severe first, deduplicated."""
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise ValueError(f"duplicate rule id: {rule.id}")
        seen.add(rule.id)

    findings: set[Finding] = set()
    for rule in rules:
        try:
            produced = tuple(rule.evaluate(ctx))
        except Exception as exc:
            raise RuleError(f"rule {rule.id!r} failed: {exc}") from exc
        for finding in produced:
            if finding.rule_id != rule.id:
                raise RuleError(
                    f"rule {rule.id!r} emitted a finding with rule_id {finding.rule_id!r}"
                )
            findings.add(finding)
    return tuple(sorted(findings, key=_sort_key))
