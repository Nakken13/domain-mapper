"""Exposed dev/staging/test names rule. Name heuristic + resolution evidence, no network."""

from __future__ import annotations

from datetime import date

import pytest

from risk_helpers import graph_of
from domain_mapper.models import (
    Domain,
    Entity,
    Finding,
    IPAddress,
    Relation,
    RelationType,
    Severity,
)
from domain_mapper.risk import RuleContext
from domain_mapper.risk.exposed_envs import ExposedEnvironmentRule

IP = IPAddress(address="192.0.2.1")


def check(*items: Entity | Relation) -> tuple[Finding, ...]:
    ctx = RuleContext(graph=graph_of(*items), today=date(2026, 11, 21))
    return tuple(ExposedEnvironmentRule().evaluate(ctx))


def resolving(fqdn: str, *, in_scope: bool = True) -> list[Entity | Relation]:
    d = Domain(fqdn=fqdn, in_scope=in_scope)
    return [d, IP, Relation.between(d, RelationType.RESOLVES_TO, IP)]


@pytest.mark.parametrize(
    "fqdn",
    [
        "dev.example.com",
        "staging.example.com",
        "api-test.example.com",
        "qa.eu.example.com",
        "uat-app.example.com",
        "preprod.example.com",
    ],
)
def test_environment_names_that_resolve_are_flagged(fqdn: str) -> None:
    (finding,) = check(*resolving(fqdn))
    assert finding.rule_id == "exposed-environments"
    assert finding.severity is Severity.LOW
    assert finding.evidence == (f"domain:{fqdn}",)


@pytest.mark.parametrize(
    "fqdn",
    ["www.example.com", "development.example.com", "latest.example.com", "contest.example.com"],
)
def test_ordinary_names_are_not_flagged(fqdn: str) -> None:
    assert check(*resolving(fqdn)) == ()


def test_name_that_does_not_resolve_is_not_exposed() -> None:
    assert check(Domain(fqdn="dev.example.com", in_scope=True)) == ()


def test_out_of_scope_name_is_ignored() -> None:
    assert check(*resolving("dev.other.org", in_scope=False)) == ()


def test_registrable_part_is_not_inspected() -> None:
    # A scope root called test.com is not a "test environment".
    assert check(*resolving("test.com")) == ()


def test_dangling_cname_is_not_reported_as_resolving() -> None:
    dev = Domain(fqdn="dev.example.com", in_scope=True)
    target = Domain(fqdn="old.herokuapp.com", in_scope=False)
    assert check(dev, target, Relation.between(dev, RelationType.CNAME_TO, target)) == ()


def test_cname_chain_ending_in_an_address_is_exposed() -> None:
    dev = Domain(fqdn="dev.example.com", in_scope=True)
    cdn = Domain(fqdn="x.cdn.example.net", in_scope=False)
    items = [
        dev,
        cdn,
        IP,
        Relation.between(dev, RelationType.CNAME_TO, cdn),
        Relation.between(cdn, RelationType.RESOLVES_TO, IP),
    ]
    assert len(check(*items)) == 1
