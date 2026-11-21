"""`domain-mapper scan`: scope is checked before anything runs; the report is one HTML file."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from domain_mapper import cli
from domain_mapper.models import (
    Domain,
    Entity,
    IPAddress,
    Observation,
    Provenance,
    Relation,
    RelationType,
)
from domain_mapper.plugins.base import PluginBase, PluginContext, PluginRegistry

runner = CliRunner()
calls: list[str] = []


class FakePlugin(PluginBase):
    name = "fake"
    consumes = frozenset({"domain"})
    runs_out_of_scope = False

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        calls.append(entity.id)
        return []


def _registry() -> PluginRegistry:
    registry = PluginRegistry()
    registry.register(FakePlugin())
    return registry


@pytest.fixture(autouse=True)
def _fake_sources(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls.clear()
    monkeypatch.setattr(cli, "default_registry", _registry)
    monkeypatch.setenv("DOMAIN_MAPPER_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(
        "authorized:\n  - domain: example.com\n    authorization: owner\n", encoding="utf-8"
    )
    return path


def test_scan_writes_a_self_contained_report(scope_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.html"
    result = runner.invoke(cli.app, ["scan", "example.com", "-s", str(scope_file), "-o", str(out)])
    assert result.exit_code == 0, result.output
    html = out.read_text(encoding="utf-8")
    assert "example.com" in html
    assert "domain:example.com" in calls


def test_scan_refuses_an_unlisted_domain_before_any_work(scope_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "out.html"
    result = runner.invoke(cli.app, ["scan", "evil.org", "-s", str(scope_file), "-o", str(out)])
    assert result.exit_code == 1
    assert "REFUSED" in result.output
    assert calls == []  # no plugin was ever called
    assert not out.exists()
    assert not (tmp_path / "cache").exists()  # not even the cache was opened


def test_scan_missing_scope_file_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["scan", "example.com", "-s", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 2
    assert "scope.example.yaml" in result.output


def test_scan_default_output_is_named_after_the_domain(scope_file: Path, tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["scan", "example.com", "-s", str(scope_file)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "example.com-report.html").is_file()


def test_scan_reports_findings_from_the_risk_rules(
    scope_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Staging(FakePlugin):
        async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
            if getattr(entity, "fqdn", "") != "example.com":
                return []
            staging = Domain(fqdn="staging.example.com", in_scope=True)
            ip = IPAddress(address="192.0.2.1")
            provenance = Provenance(source="fake", retrieved_at=datetime.now(UTC), query="q")
            return [
                Observation(
                    entities=(staging, ip),
                    relations=(Relation.between(staging, RelationType.RESOLVES_TO, ip),),
                    provenance=provenance,
                )
            ]

    registry = PluginRegistry()
    registry.register(Staging())
    monkeypatch.setattr(cli, "default_registry", lambda: registry)
    out = tmp_path / "r.html"
    result = runner.invoke(cli.app, ["scan", "example.com", "-s", str(scope_file), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "Non-production name resolves publicly" in out.read_text(encoding="utf-8")


@pytest.mark.parametrize("bad", ["missing-dir/out.html", "."])
def test_scan_rejects_an_unwritable_output_before_collecting(
    scope_file: Path, tmp_path: Path, bad: str
) -> None:
    """A bad -o must fail fast: not after a full collection whose results would be lost."""
    result = runner.invoke(
        cli.app, ["scan", "example.com", "-s", str(scope_file), "-o", str(tmp_path / bad)]
    )
    assert result.exit_code == 2
    assert "output" in result.output.lower()
    assert calls == []  # no plugin ran
