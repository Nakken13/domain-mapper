from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from surfacemap.models import (
    Domain,
    Finding,
    IPAddress,
    Observation,
    Provenance,
    Relation,
    Severity,
)

PROV = Provenance(source="dns", retrieved_at=datetime(2026, 11, 20, tzinfo=UTC), query="a.example")


def test_observation_groups_entities_and_relations_under_one_provenance() -> None:
    obs = Observation(
        provenance=PROV,
        entities=[Domain(fqdn="a.example", in_scope=True), IPAddress(address="192.0.2.1")],
        relations=[Relation(source="domain:a.example", type="RESOLVES_TO", target="ip:192.0.2.1")],
    )
    assert isinstance(obs.entities, tuple)
    assert [e.id for e in obs.entities] == ["domain:a.example", "ip:192.0.2.1"]


def test_observation_parses_entities_from_dicts() -> None:
    obs = Observation(provenance=PROV, entities=[{"kind": "asn", "number": "AS64496"}])
    assert obs.entities[0].id == "asn:64496"


def test_observation_must_not_be_empty() -> None:
    with pytest.raises(ValidationError):
        Observation(provenance=PROV)


def test_severity_is_ordered() -> None:
    assert sorted([Severity.HIGH, Severity.INFO, Severity.CRITICAL, Severity.LOW]) == [
        Severity.INFO,
        Severity.LOW,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.MEDIUM >= Severity.MEDIUM
    assert Severity.LOW <= Severity.HIGH


def _finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "rule_id": "dangling-cname",
        "severity": "high",
        "title": "CNAME to unclaimed host",
        "rationale": "The target does not resolve; whoever claims it serves your subdomain.",
        "evidence": ["domain:old.example.com", "domain:gone.cdn.example"],
        "remediation": "Remove the CNAME record or reclaim the target.",
    }
    fields.update(overrides)
    return Finding(**fields)  # type: ignore[arg-type]


def test_finding_holds_explainable_fields() -> None:
    finding = _finding()
    assert finding.severity is Severity.HIGH
    assert finding.evidence == ("domain:old.example.com", "domain:gone.cdn.example")


@pytest.mark.parametrize(
    "overrides",
    [
        {"evidence": []},
        {"evidence": ["not-an-id"]},
        {"evidence": ["person:alice"]},
        {"rationale": ""},
        {"remediation": "   "},
        {"rule_id": "Dangling CNAME"},
        {"severity": "urgent"},
    ],
)
def test_finding_refuses_unexplained_or_malformed_input(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _finding(**overrides)


def test_severity_refuses_comparison_with_plain_strings() -> None:
    with pytest.raises(TypeError):
        _ = Severity.CRITICAL < "high"
