"""Risk rule engine: contract, determinism, error handling. Pure, no network."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date

import pytest

from domain_mapper.graph.builder import SurfaceGraph
from domain_mapper.models import Finding, Severity
from domain_mapper.risk import RuleContext, RuleError, run_rules

TODAY = date(2026, 11, 21)


def finding(rule_id: str, severity: Severity, evidence: str = "domain:a.example.com") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="t",
        rationale="r",
        evidence=(evidence,),
        remediation="fix",
    )


class FakeRule:
    def __init__(self, rule_id: str, findings: Iterable[Finding]) -> None:
        self.id = rule_id
        self._findings = tuple(findings)
        self.calls = 0

    def evaluate(self, ctx: RuleContext) -> Iterable[Finding]:
        self.calls += 1
        return self._findings


class BoomRule:
    id = "boom"

    def evaluate(self, ctx: RuleContext) -> Iterable[Finding]:
        raise ValueError("bad data")


def ctx() -> RuleContext:
    return RuleContext(graph=SurfaceGraph(), today=TODAY)


def test_no_rules_no_findings() -> None:
    assert run_rules(ctx(), []) == ()


def test_collects_findings_of_every_rule() -> None:
    a = FakeRule("rule-a", [finding("rule-a", Severity.LOW)])
    b = FakeRule("rule-b", [finding("rule-b", Severity.HIGH)])
    result = run_rules(ctx(), [a, b])
    assert {f.rule_id for f in result} == {"rule-a", "rule-b"}
    assert a.calls == b.calls == 1


def test_sorted_by_severity_desc_then_rule_then_evidence() -> None:
    rules = [
        FakeRule("rule-b", [finding("rule-b", Severity.LOW)]),
        FakeRule(
            "rule-a",
            [
                finding("rule-a", Severity.HIGH, "domain:z.example.com"),
                finding("rule-a", Severity.HIGH, "domain:b.example.com"),
                finding("rule-a", Severity.LOW),
            ],
        ),
    ]
    result = run_rules(ctx(), rules)
    assert [(f.severity, f.rule_id, f.evidence[0]) for f in result] == [
        (Severity.HIGH, "rule-a", "domain:b.example.com"),
        (Severity.HIGH, "rule-a", "domain:z.example.com"),
        (Severity.LOW, "rule-a", "domain:a.example.com"),
        (Severity.LOW, "rule-b", "domain:a.example.com"),
    ]


def test_order_of_rules_does_not_change_result() -> None:
    a = FakeRule("rule-a", [finding("rule-a", Severity.MEDIUM)])
    b = FakeRule("rule-b", [finding("rule-b", Severity.MEDIUM)])
    assert run_rules(ctx(), [a, b]) == run_rules(ctx(), [b, a])


def test_identical_findings_are_deduplicated() -> None:
    same = finding("rule-a", Severity.LOW)
    assert run_rules(ctx(), [FakeRule("rule-a", [same, same])]) == (same,)


def test_duplicate_rule_ids_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate rule id"):
        run_rules(ctx(), [FakeRule("rule-a", []), FakeRule("rule-a", [])])


def test_finding_with_foreign_rule_id_rejected() -> None:
    liar = FakeRule("rule-a", [finding("rule-b", Severity.LOW)])
    with pytest.raises(RuleError, match=r"rule-a.*rule-b"):
        run_rules(ctx(), [liar])


def test_crashing_rule_is_named_and_chained() -> None:
    with pytest.raises(RuleError, match="boom") as info:
        run_rules(ctx(), [BoomRule()])
    assert isinstance(info.value.__cause__, ValueError)
